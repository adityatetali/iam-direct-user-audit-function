"""
IAM Direct-User-Assignment Auditor
----------------------------------
Timer-triggered Azure Function that runs daily and checks Management Group,
Subscription, and Resource Group scopes for role assignments made directly
to a User principal (as opposed to a Group principal). Your org's policy is
group-based RBAC only, so any direct user assignment found (and not on the
exception list) is reported as a new finding.

State is kept in Azure Table Storage so that only *new* direct assignments
(ones not seen on a previous run) get reported each day, instead of re-alerting
on the same known assignment forever.

Required identity permissions (grant to the Function App's Managed Identity):
  - Reader                         at the Tenant Root Management Group
                                    (or every MG/subscription you want scanned)
  - Directory Readers (Microsoft Graph "Directory.Read.All", application)
                                    to resolve principal types/UPNs reliably

Environment variables (Function App > Configuration):
  AZURE_TENANT_ID            (optional if using system-assigned identity in Azure)
  MANAGEMENT_GROUP_ID        Root management group to start the scan from
                             (e.g. your tenant root MG id)
  TEAMS_WEBHOOK_URL          Optional. Incoming webhook URL for a Teams channel.
  AzureWebJobsStorage        Already required by Functions; reused for state table.
  EXCEPTIONS_PATH            Optional. Defaults to "exceptions.json" bundled with
                             the app. Points to the exception list file.
"""

import json
import logging
import os
from datetime import datetime, timezone

import azure.functions as func
import requests
from azure.core.exceptions import HttpResponseError
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient

app = func.FunctionApp()

STATE_TABLE_NAME = "iamAuditSeenAssignments"
EXCEPTIONS_PATH = os.environ.get(
    "EXCEPTIONS_PATH", os.path.join(os.path.dirname(__file__), "exceptions.json")
)
ROOT_MANAGEMENT_GROUP_ID = os.environ.get("MANAGEMENT_GROUP_ID")
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL")
STORAGE_CONNECTION = os.environ.get("AzureWebJobsStorage")

credential = DefaultAzureCredential()


# ---------------------------------------------------------------------------
# Exception list
# ---------------------------------------------------------------------------
def load_exceptions() -> list[dict]:
    """
    Exception list format (exceptions.json), one entry per allowed direct
    user assignment. All fields are optional except "principal"; omit a
    field to make it a wildcard for that field.

    [
      {
        "principal": "first.last@state.mo.us",   # UPN or object id
        "scope": "/subscriptions/xxxx",           # exact scope, prefix-matched
        "role": "Owner",                          # role definition name
        "reason": "Break-glass emergency access account",
        "expires": "2026-12-31"                   # optional ISO date; ignored if past
      }
    ]
    """
    try:
        with open(EXCEPTIONS_PATH, "r", encoding="utf-8") as f:
            exceptions = json.load(f)
    except FileNotFoundError:
        logging.warning("No exceptions.json found at %s; treating as empty.", EXCEPTIONS_PATH)
        return []

    today = datetime.now(timezone.utc).date()
    active = []
    for entry in exceptions:
        expires = entry.get("expires")
        if expires:
            try:
                if datetime.fromisoformat(expires).date() < today:
                    continue  # expired exception, no longer honored
            except ValueError:
                logging.warning("Bad 'expires' date in exception entry: %s", entry)
        active.append(entry)
    return active


def is_excepted(exceptions: list[dict], principal_upn: str, principal_id: str, scope: str, role_name: str) -> bool:
    for entry in exceptions:
        principal_match = entry.get("principal") in (principal_upn, principal_id)
        if not principal_match:
            continue
        scope_filter = entry.get("scope")
        if scope_filter and not scope.lower().startswith(scope_filter.lower()):
            continue
        role_filter = entry.get("role")
        if role_filter and role_filter.lower() != (role_name or "").lower():
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Scope enumeration: management groups -> subscriptions -> resource groups
# ---------------------------------------------------------------------------
def enumerate_scopes() -> list[str]:
    scopes: list[str] = []

    mg_client = ManagementGroupsAPI(credential)
    sub_client = SubscriptionClient(credential)

    if ROOT_MANAGEMENT_GROUP_ID:
        scopes.extend(_walk_management_groups(mg_client, ROOT_MANAGEMENT_GROUP_ID))
    else:
        logging.warning("MANAGEMENT_GROUP_ID not set; skipping management-group scopes.")

    subscription_ids = []
    for sub in sub_client.subscriptions.list():
        if sub.state != "Enabled":
            continue
        subscription_ids.append(sub.subscription_id)
        scopes.append(f"/subscriptions/{sub.subscription_id}")

    for sub_id in subscription_ids:
        rg_client = ResourceManagementClient(credential, sub_id)
        try:
            for rg in rg_client.resource_groups.list():
                scopes.append(
                    f"/subscriptions/{sub_id}/resourceGroups/{rg.name}"
                )
        except HttpResponseError as ex:
            logging.warning("Could not list resource groups for sub %s: %s", sub_id, ex)

    return scopes


def _walk_management_groups(mg_client: ManagementGroupsAPI, mg_id: str) -> list[str]:
    scopes = [f"/providers/Microsoft.Management/managementGroups/{mg_id}"]
    try:
        details = mg_client.management_groups.get(mg_id, expand="children", recurse=False)
    except HttpResponseError as ex:
        logging.warning("Could not expand management group %s: %s", mg_id, ex)
        return scopes

    for child in getattr(details, "children", None) or []:
        if child.type and child.type.lower().endswith("managementgroups"):
            scopes.extend(_walk_management_groups(mg_client, child.name))
    return scopes


# ---------------------------------------------------------------------------
# Role assignment collection
# ---------------------------------------------------------------------------
def get_direct_user_assignments(scope: str) -> list[dict]:
    """
    Returns role assignments whose principalType is 'User' and whose own
    scope exactly matches `scope` (so a Reader-at-MG assignment isn't
    re-reported at every subscription/RG beneath it -- it's only reported
    once, at the scope it was actually created on).
    """
    # subscription id is only needed for the client constructor's routing;
    # it does not restrict which scope's assignments we can query.
    auth_client = AuthorizationManagementClient(
        credential, subscription_id="00000000-0000-0000-0000-000000000000"
    )
    findings = []
    try:
        assignments = auth_client.role_assignments.list_for_scope(
            scope, filter="atScope()"
        )
        for a in assignments:
            if a.scope.lower() != scope.lower():
                continue  # inherited from a parent scope; that scope reports it
            if (a.principal_type or "").lower() != "user":
                continue
            findings.append(
                {
                    "assignment_id": a.id,
                    "scope": a.scope,
                    "principal_id": a.principal_id,
                    "role_definition_id": a.role_definition_id,
                    "created_on": str(getattr(a, "created_on", "")),
                }
            )
    except HttpResponseError as ex:
        logging.warning("Could not list role assignments for scope %s: %s", scope, ex)
    return findings


def resolve_role_name(auth_client: AuthorizationManagementClient, role_definition_id: str) -> str:
    try:
        role_def = auth_client.role_definitions.get_by_id(role_definition_id)
        return role_def.role_name
    except HttpResponseError:
        return role_definition_id.rsplit("/", 1)[-1]


def resolve_principal_upn(principal_id: str) -> str:
    """Best-effort UPN lookup via Microsoft Graph using the same credential."""
    try:
        token = credential.get_token("https://graph.microsoft.com/.default").token
        resp = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{principal_id}?$select=userPrincipalName",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("userPrincipalName", principal_id)
    except Exception as ex:  # noqa: BLE001 - best effort, never fail the run over this
        logging.warning("Graph lookup failed for %s: %s", principal_id, ex)
    return principal_id


# ---------------------------------------------------------------------------
# State tracking (only alert on NEW findings)
# ---------------------------------------------------------------------------
def get_state_table():
    table_service = TableServiceClient.from_connection_string(STORAGE_CONNECTION)
    table_service.create_table_if_not_exists(STATE_TABLE_NAME)
    return table_service.get_table_client(STATE_TABLE_NAME)


def filter_new_findings(table_client, findings: list[dict]) -> list[dict]:
    new_findings = []
    for f in findings:
        partition_key = "assignment"
        row_key = f["assignment_id"].replace("/", "_")
        try:
            table_client.get_entity(partition_key, row_key)
            continue  # already seen on a prior run
        except Exception:
            pass  # not found -> new finding
        table_client.upsert_entity(
            {
                "PartitionKey": partition_key,
                "RowKey": row_key,
                "scope": f["scope"],
                "principal_id": f["principal_id"],
                "firstSeen": datetime.now(timezone.utc).isoformat(),
            }
        )
        new_findings.append(f)
    return new_findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def send_teams_report(findings: list[dict]):
    if not TEAMS_WEBHOOK_URL:
        logging.info("TEAMS_WEBHOOK_URL not set; skipping Teams notification.")
        return
    if not findings:
        return

    lines = [
        f"- **{f['upn']}** was granted **{f['role_name']}** directly at `{f['scope']}`"
        for f in findings
    ]
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "New direct-user IAM assignment detected",
        "themeColor": "D9534F",
        "title": f"⚠️ {len(findings)} new direct-user role assignment(s) found",
        "text": "Group-based RBAC policy requires assigning roles to groups, not users directly.\n\n"
        + "\n".join(lines),
    }
    try:
        requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=10)
    except Exception as ex:  # noqa: BLE001
        logging.error("Failed to post Teams notification: %s", ex)


# ---------------------------------------------------------------------------
# Timer trigger entry point (runs daily at 06:00 UTC)
# ---------------------------------------------------------------------------
@app.function_name(name="IamDirectUserAudit")
@app.schedule(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False, use_monitor=True)
def iam_direct_user_audit(timer: func.TimerRequest) -> None:
    logging.info("IAM direct-user assignment audit started.")

    exceptions = load_exceptions()
    scopes = enumerate_scopes()
    logging.info("Scanning %d scopes.", len(scopes))

    auth_client = AuthorizationManagementClient(
        credential, subscription_id="00000000-0000-0000-0000-000000000000"
    )

    all_findings = []
    for scope in scopes:
        for raw in get_direct_user_assignments(scope):
            role_name = resolve_role_name(auth_client, raw["role_definition_id"])
            upn = resolve_principal_upn(raw["principal_id"])
            if is_excepted(exceptions, upn, raw["principal_id"], raw["scope"], role_name):
                continue
            all_findings.append({**raw, "role_name": role_name, "upn": upn})

    table_client = get_state_table()
    new_findings = filter_new_findings(table_client, all_findings)

    logging.info(
        "Audit complete: %d direct-user assignments found, %d are new.",
        len(all_findings),
        len(new_findings),
    )

    for f in new_findings:
        logging.warning(
            "NEW direct-user assignment: %s granted %s at %s",
            f["upn"],
            f["role_name"],
            f["scope"],
        )

    send_teams_report(new_findings)

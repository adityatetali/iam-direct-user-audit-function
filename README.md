# IAM Direct-User Assignment Auditor

Daily-scheduled Azure Function (Python v2 model, timer trigger) that enforces a
group-based RBAC policy: it scans Management Group, Subscription, and Resource
Group scopes for role assignments made directly to a **User** principal
(instead of a Group), and reports any **new** ones found each day. Anything on
the exception list is silently skipped.

## How it decides "new"

The function stores every direct-user assignment it has ever seen in an Azure
Table (`iamAuditSeenAssignments`, in the same storage account the Function App
already uses). On each run it only reports assignments not already in that
table, so you get one alert per offending assignment, not a repeat every day
until it's cleaned up. If you'd rather get a full daily report regardless of
"new," change `filter_new_findings` in `function_app.py` to just return
`findings` unchanged.

## Exception list

Edit `exceptions.json` (deployed alongside the function). Each entry can pin
down principal, scope, and/or role — omit a field to wildcard it:

```json
[
  {
    "principal": "break.glass@state.mo.us",
    "scope": "/providers/Microsoft.Management/managementGroups/ROOT_MG_ID",
    "role": "Owner",
    "reason": "Emergency break-glass account, direct assignment required by design",
    "expires": null
  }
]
```

`expires` (ISO date, optional) lets you grant a time-boxed exception that
automatically starts being enforced again once it passes.

## Required setup

1. **Enable a system-assigned managed identity** on the Function App.
2. **Grant IAM permissions to that identity:**
   - `Reader` at the Tenant Root Management Group (or each Management
     Group/subscription you want scanned, if you don't want tenant-wide reach)
   - Microsoft Graph **application** permission `User.Read.All` (admin-consented),
     used only to resolve a principal's UPN for readable alerts — remove
     `resolve_principal_upn` if you'd rather avoid the Graph dependency and
     just alert on the raw object id.
3. **Configure app settings** (Function App > Configuration):
   - `MANAGEMENT_GROUP_ID` — root Management Group id to start the scan from
   - `TEAMS_WEBHOOK_URL` — optional, an Incoming Webhook connector URL for a
     Teams channel to post findings to
   - `AzureWebJobsStorage` — already present by default; reused for the state table
4. **Deploy:**
   ```bash
   func azure functionapp publish <your-function-app-name>
   ```

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp local.settings.json.example local.settings.json  # fill in values
az login  # DefaultAzureCredential will use your az CLI login locally
func start
```

To force a run without waiting for the schedule, use the Functions Core Tools
"admin" trigger endpoint, or temporarily set `run_on_startup=True` in
`function_app.py`.

## Notes / things to double check for your environment

- The timer schedule `0 0 6 * * *` runs daily at 06:00 UTC — adjust for your
  timezone (Missouri is UTC-5/UTC-6).
- `list_for_scope(..., filter="atScope()")` returns assignments defined at the
  given scope **and every parent scope above it**; the code filters those back
  down to only assignments whose own `scope` equals the scope being scanned,
  so an assignment made at a Management Group is reported once (at that MG),
  not re-reported at every subscription and resource group beneath it.
- Deny assignments aren't included (Azure Blueprints/manual deny assignments
  are a separate, much rarer case) — only `role_assignments.list_for_scope`.
- If your subscriptions number in the hundreds, this will make a lot of ARM
  calls per run; consider Azure Resource Graph (`Microsoft.Authorization/roleAssignments`
  table) instead of the per-scope SDK calls if throttling becomes an issue.

# EndpointRead-MCP

Read-only Model Context Protocol (MCP) server for Microsoft Intune and Entra ID.

EndpointRead-MCP is a safe, non-destructive Graph MCP surface that supports
list/get/search/reporting operations only. It is designed for tenant visibility,
audits, troubleshooting, and health reporting without write actions.

## Key Features

- Read-only Intune and Entra operations.
- Write actions are blocked by allowlist guards.
- Built-in report export support for Intune reports.
- Authentication helper tools for app/delegated/hybrid flows.
- Metadata discovery tools for available operations.

## Security Model

EndpointRead-MCP enforces read-only behavior in tool action dispatch. Destructive
operations such as create/update/delete/assign/restart/wipe are not available.
If a blocked action is requested, the tool returns an error with allowed actions.

## Tool Catalog

### Connection and Auth

- `authenticate_mcp_session`
- `test_connection`
- `get_auth_status`
- `start_interactive_sign_in`
- `complete_interactive_sign_in`
- `complete_interactive_login`
- `connect_intune_mcp_server`
- `get_intune_overview`

### Intune and Entra Read Tools

- `manage_intune_devices`
- `manage_device_encryption`
- `manage_intune_apps`
- `manage_app_config_mam`
- `manage_compliance_policies`
- `manage_configuration_profiles`
- `manage_settings_catalog`
- `manage_admx_policies`
- `manage_endpoint_security`
- `manage_security_baselines`
- `manage_windows_update`
- `manage_intune_scripts`
- `manage_intune_enrollment`
- `manage_autopilot`
- `manage_filters_tags`
- `manage_intune_rbac`
- `manage_cloud_pc`
- `manage_entra_users`
- `manage_entra_groups`
- `manage_entra_devices`
- `manage_conditional_access`
- `manage_identity_protection`
- `manage_app_registrations`
- `manage_tenant_admin`

### Reporting Tool

- `manage_intune_reports`
	- `list_available_reports`
	- `export_report` (generic `reportName` support)
	- Summary and scoped report actions (compliance, app install, analytics,
		encryption, enrollment failures, and related export jobs)

### Catalog and Discovery

- `list_graph_catalog_operations`
- `describe_graph_catalog_operation`
- `discover_graph_operations`

## Permissions

Use least privilege and only grant the scopes your scenario needs. Typical read
permissions used by this server include:

- `Organization.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `AuditLog.Read.All`
- `Device.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementApps.Read.All`
- `DeviceManagementServiceConfig.Read.All`
- `DeviceManagementRBAC.Read.All`

For report exports and advanced analytics, additional Intune read scopes may be
required depending on endpoint/report type.

## Configuration

Create `.env` in repo root (never commit it):

```env
TENANT_ID=<your-tenant-id>
CLIENT_ID=<your-app-id>
CLIENT_SECRET=<your-client-secret>

AUTH_MODE=app
REQUIRE_USER_LOGIN=false
USER_AUTH_SCOPES=User.Read,DeviceManagementManagedDevices.Read.All
INTERACTIVE_LOGIN_MODE=browser
TOKEN_CACHE_PATH=.msal_token_cache.bin
```

## Installation

```powershell
cd E:\MCP\EndpointRead-MCP
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

## Run

```powershell
cd E:\MCP\EndpointRead-MCP
.venv\Scripts\python.exe -m intune_mcp_server.server
```

## VS Code MCP Config Example

```json
{
	"servers": {
		"EndpointRead-MCP": {
			"type": "stdio",
			"command": "E:\\MCP\\EndpointRead-MCP\\.venv\\Scripts\\python.exe",
			"args": ["-m", "intune_mcp_server.server"],
			"envFile": "E:\\MCP\\EndpointRead-MCP\\.env"
		}
	}
}
```

## Secret Hygiene

- `.env` is ignored by `.gitignore`.
- Do not commit tenant secrets, access tokens, or cache files.
- Rotate credentials if secrets are ever exposed.

## Project Base

- Derived from: IntuneRW-Core
- Adapted to enforce read-only action allowlists
- Includes one consolidated read reporting tool for Intune exports

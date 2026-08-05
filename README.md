# IntuneRW-Core

A full **read/write** [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for managing **Microsoft Intune** and **Entra ID (Azure AD)** through the Microsoft Graph API. It gives AI assistants (Claude Desktop, VS Code Copilot, Cursor, Copilot Studio, etc.) direct, structured access to device management, app management, compliance, security, identity, and reporting operations across your tenant.

The server exposes **34 MCP tools**, each accepting an `action` parameter so a single tool can drive dozens of related Graph operations without needing one MCP tool per endpoint. In total the tools cover **280+ underlying Microsoft Graph operations**.

> ⚠️ **This server can create, update, and delete real objects in your tenant** (devices, users, groups, policies, apps, etc.). Review the [Permissions](#required-graph-api-permissions) section and scope the app registration carefully before pointing it at a production tenant.

---

## Features

### Core / Connection
- Interactive and app-only (client credentials) authentication flows
- Session auth status, sign-in, and one-step connect helpers
- Graph connectivity test and tenant info
- Intune tenant overview (device counts, compliance, OS breakdown)
- `discover_graph_operations` — self-describing catalog of every action every tool supports

### Intune Device & App Management
- List, search, filter, and inspect managed devices
- Remote actions: sync, restart, lock, rename, locate, wipe, retire, reset passcode, lost mode, defender scan, log collection, diagnostics collection
- BitLocker / FileVault recovery key lookups and encryption reports
- Mobile app CRUD, assignments (required/available/uninstall), install status, discovered/detected apps
- App configuration (MAM) and app protection policies

### Compliance & Configuration
- Compliance policies (CRUD, assignment, deployment status)
- Device configuration profiles and Settings Catalog policies
- ADMX / administrative template policies
- Endpoint security policies and templates (AV, Firewall, EDR)
- Security baselines (templates + deployed profile status)
- Windows Update rings and feature/quality/driver update profiles

### Enrollment & Fleet Operations
- PowerShell scripts and proactive remediations (Windows + macOS shell scripts)
- Enrollment restrictions, Apple VPP/DEP tokens, Android Enterprise settings
- Windows Autopilot devices, deployment profiles, and enrollment status page (ESP) profiles
- Assignment filters and scope tags
- Intune RBAC role definitions and role assignments

### Windows 365 Cloud PC
- Cloud PC lifecycle (list, restart, reprovision, resize, restore, troubleshoot)
- Provisioning policies, gallery images, network connections, audit events

### Entra ID (Azure AD)
- Full user lifecycle: CRUD, onboarding/offboarding, licenses, manager assignment, password/session management, bulk operations
- Group management: security, Microsoft 365, and dynamic groups; members/owners
- Entra device inventory management (list/search/enable/disable/delete)
- Conditional Access policies and named locations
- Identity Protection: risky users, risk detections, sign-in/audit logs, MFA and authentication methods
- App registrations and enterprise app inspection/management

### Tenant Administration & Reporting
- Organization/domain info, service health, directory roles, subscriptions, security defaults
- Compliance, malware, encryption, endpoint analytics, app reliability, and license usage reports
- Async Graph report export jobs (`deviceManagement/reports/exportJobs`)

---

## Available Tools

| # | Tool | Area |
|---|------|------|
| 1 | `authenticate_mcp_session` | Auth |
| 2 | `test_connection` | Auth |
| 3 | `get_auth_status` | Auth |
| 4 | `start_interactive_sign_in` | Auth |
| 5 | `complete_interactive_sign_in` | Auth |
| 6 | `complete_interactive_login` | Auth |
| 7 | `connect_intune_mcp_server` | Auth |
| 8 | `get_intune_overview` | Core |
| 9 | `manage_intune_devices` | Intune Devices |
| 10 | `manage_device_encryption` | Encryption |
| 11 | `manage_intune_apps` | Apps |
| 12 | `manage_app_config_mam` | App Protection (MAM) |
| 13 | `manage_compliance_policies` | Compliance |
| 14 | `manage_configuration_profiles` | Config Profiles |
| 15 | `manage_settings_catalog` | Settings Catalog |
| 16 | `manage_admx_policies` | ADMX / GPO |
| 17 | `manage_endpoint_security` | Endpoint Security |
| 18 | `manage_security_baselines` | Security Baselines |
| 19 | `manage_windows_update` | Windows Update |
| 20 | `manage_intune_scripts` | Scripts & Remediations |
| 21 | `manage_intune_enrollment` | Enrollment |
| 22 | `manage_autopilot` | Autopilot |
| 23 | `manage_filters_tags` | Filters & Scope Tags |
| 24 | `manage_intune_rbac` | Intune RBAC |
| 25 | `manage_cloud_pc` | Windows 365 Cloud PC |
| 26 | `manage_entra_users` | Entra Users |
| 27 | `manage_entra_groups` | Entra Groups |
| 28 | `manage_entra_devices` | Entra Devices |
| 29 | `manage_conditional_access` | Conditional Access |
| 30 | `manage_identity_protection` | Identity Protection |
| 31 | `manage_app_registrations` | App Registrations |
| 32 | `manage_tenant_admin` | Tenant Administration |
| 33 | `manage_intune_reports` | Reports & Analytics |
| 34 | `discover_graph_operations` | Catalog / Discovery |

Each `manage_*` tool takes an `action` parameter (e.g. `manage_intune_devices(action="wipe", device_id="...", confirm=True)`). Call `discover_graph_operations` at any time to get the full, up-to-date list of actions per tool directly from the running server.

Destructive actions (wipe, delete, retire, etc.) require an explicit `confirm=True` argument — calling them without it returns a `confirmation_required` response instead of executing.

---

## Required Graph API Permissions

Grant these **Application** permissions to your Entra ID app registration (Azure Portal → App registrations → API permissions → Microsoft Graph → Application permissions), then click **Grant admin consent**.

### Intune
```
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
DeviceManagementRBAC.ReadWrite.All
DeviceManagementScripts.ReadWrite.All
DeviceManagementManagedDevices.PrivilegedOperations.All
```

### Entra ID
```
User.ReadWrite.All
Group.ReadWrite.All
Directory.ReadWrite.All
RoleManagement.ReadWrite.Directory
Policy.ReadWrite.ConditionalAccess
IdentityRiskyUser.ReadWrite.All
IdentityRiskEvent.Read.All
AuditLog.Read.All
UserAuthenticationMethod.ReadWrite.All
Application.Read.All
Organization.Read.All
```

### Tenant Administration & Reporting
```
ServiceHealth.Read.All
ServiceMessage.Read.All
Reports.Read.All
```

### Windows 365
```
CloudPC.ReadWrite.All
```

> Notes:
> - `DeviceManagementManagedDevices.PrivilegedOperations.All` is required for high-impact remote actions such as device log collection requests.
> - Some enrollment-restriction write actions additionally require the calling principal (or the app registration's effective context) to hold the **Global Administrator** or **Intune Service Administrator** directory role — this is a Graph service-side business rule, not just an application permission.
> - If you only need read-only/reporting access, use the `.Read.All` variants instead of `.ReadWrite.All` where available and drop any write-only scopes you don't need.

---

## Prerequisites

- Python 3.10+ (3.11 recommended)
- A Microsoft Entra ID tenant with Global Administrator (or delegated equivalent) access to create an app registration
- An Entra ID app registration configured for client credentials (app-only) auth, with the permissions above granted and admin-consented

## Installation

```powershell
git clone https://github.com/nelladath/IntuneRW-Core.git
cd IntuneRW-Core
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configure environment variables

Copy [`env.example`](env.example) to `.env` and fill in your app registration values:

```env
TENANT_ID=your-tenant-id
CLIENT_ID=your-app-client-id
CLIENT_SECRET=your-app-client-secret
AUTH_MODE=app
```

`AUTH_MODE` supports:
- `app` — app-only (client credentials) token, no user interaction (default, recommended for automation)
- `delegated` — signed-in user token only (device-code or browser flow)
- `hybrid` — app-only Graph calls gated behind an optional first-layer interactive user sign-in

See [`env.example`](env.example) for the full list of options (interactive login mode, token cache path, Graph endpoint overrides).

---

## VS Code Setup (MCP Client)

1. Install the [MCP extension support](https://code.visualstudio.com/docs/copilot/chat/mcp-servers) in VS Code (built into recent Copilot Chat versions) or your preferred MCP-compatible client.
2. Build the console entry point into your virtual environment (done automatically by `pip install -r requirements.txt` + the project's `pyproject.toml` script entry, or run directly via `python -m intune_mcp_server`).
3. Add a server entry to your workspace `.vscode/mcp.json` (a template is included in this repo):

```json
{
    "servers": {
        "intune-rw-core": {
            "type": "stdio",
            "command": "${workspaceFolder}/.venv/Scripts/intune-mcp-server.exe",
            "args": [],
            "env": {
                "TENANT_ID": "",
                "CLIENT_ID": "",
                "CLIENT_SECRET": ""
            }
        }
    }
}
```

- On macOS/Linux use `${workspaceFolder}/.venv/bin/intune-mcp-server` instead.
- You can leave `env` empty and rely on a `.env` file in the project root instead — the server loads it automatically via `python-dotenv`.
- Alternatively, run the server as a plain module without the console script: `"command": "python", "args": ["-m", "intune_mcp_server"]`.
4. Reload the VS Code window (or use the MCP: List Servers command) and the 34 tools listed above will become available to Copilot Chat.
5. Run `test_connection` (or `connect_intune_mcp_server`) first to verify authentication before using any other tool.

### Claude Desktop / other MCP clients

Add an equivalent entry to your client's MCP server configuration, pointing `command` at the same executable/module and passing the same environment variables.

---

## HTTP Transport (optional)

In addition to stdio (the default, used by most desktop MCP clients), the server can run over Streamable HTTP for hosted scenarios (e.g. Copilot Studio custom connectors):

```powershell
uvicorn intune_mcp_server.mcp_app:app --host 0.0.0.0 --port 8000
```

A minimal REST bridge exposing a handful of tools as plain HTTP endpoints is also available in [`bridge.py`](bridge.py) (FastAPI) for scenarios that need simple REST calls instead of the native MCP protocol.

---

## Security Notes

- Never commit `.env` or the MSAL token cache (`.msal_token_cache.bin`) — both are already excluded via [`.gitignore`](.gitignore).
- Prefer `AUTH_MODE=app` with a tightly-scoped app registration for automation; reserve `delegated`/`hybrid` modes for interactive, human-supervised sessions.
- Destructive actions (wipe, retire, delete) require `confirm=True` — treat any AI client wired to this server with the same caution as a human holding Global Administrator credentials.
- Grant only the permissions your use case needs; the lists above are the maximum superset for full read/write coverage, not a minimum requirement.

## License

[MIT](LICENSE) © Sujin Nelladath

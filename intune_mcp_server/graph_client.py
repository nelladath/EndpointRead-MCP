"""Microsoft Graph API Client with authentication."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any
from pathlib import Path

import httpx
from msal import ConfidentialClientApplication, PublicClientApplication, SerializableTokenCache

from .config import get_config, GraphConfig

_msal_executor = ThreadPoolExecutor(max_workers=2)


class AuthRequiredError(Exception):
    """Raised when interactive user sign-in is required before continuing."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}


class GraphClient:
    """Async Microsoft Graph API client with automatic token management."""
    
    def __init__(self, config: GraphConfig | None = None):
        """Initialize the Graph client."""
        self.config = config or get_config()
        self._token: str | None = None
        self._token_expires: datetime | None = None
        self._msal_app: ConfidentialClientApplication | None = None
        self._public_app: PublicClientApplication | None = None
        self._token_cache: SerializableTokenCache | None = None
        self._pending_device_flow: dict[str, Any] | None = None
        self._http_client: httpx.AsyncClient | None = None

    @property
    def token_cache(self) -> SerializableTokenCache:
        """Load and return the persistent token cache used for delegated auth."""
        if self._token_cache is None:
            self._token_cache = SerializableTokenCache()
            cache_path = Path(self.config.token_cache_path)
            if cache_path.exists():
                try:
                    self._token_cache.deserialize(cache_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
        return self._token_cache

    def _save_token_cache(self) -> None:
        if self._token_cache and self._token_cache.has_state_changed:
            cache_path = Path(self.config.token_cache_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(self._token_cache.serialize(), encoding="utf-8")
    
    @property
    def msal_app(self) -> ConfidentialClientApplication:
        """Get or create the MSAL application."""
        if self._msal_app is None:
            self._msal_app = ConfidentialClientApplication(
                client_id=self.config.client_id,
                client_credential=self.config.client_secret,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}",
            )
        return self._msal_app

    @property
    def public_app(self) -> PublicClientApplication:
        """Get or create the delegated-user MSAL public client app."""
        if self._public_app is None:
            self._public_app = PublicClientApplication(
                client_id=self.config.client_id,
                authority=f"https://login.microsoftonline.com/{self.config.tenant_id}",
                token_cache=self.token_cache,
            )
        return self._public_app

    async def _acquire_app_token(self) -> str:
        """Acquire app-only token using client credentials."""
        scopes = ["https://graph.microsoft.com/.default"]
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _msal_executor,
            lambda: self.msal_app.acquire_token_for_client(scopes=scopes)
        )
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise Exception(f"Failed to acquire app token: {error}")

        self._token = result["access_token"]
        expires_in = result.get("expires_in", 3600)
        self._token_expires = datetime.now() + timedelta(seconds=expires_in - 300)
        return self._token

    async def _acquire_delegated_token_silent(self) -> str | None:
        """Try to get delegated token from cache without prompting user."""
        scopes = self.config.user_auth_scopes or ["User.Read"]
        loop = asyncio.get_event_loop()
        accounts = await loop.run_in_executor(_msal_executor, lambda: self.public_app.get_accounts())
        if not accounts:
            return None

        result = await loop.run_in_executor(
            _msal_executor,
            lambda: self.public_app.acquire_token_silent(scopes=scopes, account=accounts[0])
        )
        if not result or "access_token" not in result:
            return None

        self._save_token_cache()
        return result["access_token"]

    async def start_interactive_sign_in(self) -> dict[str, Any]:
        """Start interactive sign-in according to configured mode."""
        if self.config.interactive_login_mode == "browser":
            return await self._start_browser_sign_in()

        return await self._start_device_code_sign_in()

    async def _start_device_code_sign_in(self) -> dict[str, Any]:
        """Start device-code flow and return instructions for user sign-in."""
        scopes = self.config.user_auth_scopes or ["User.Read"]
        loop = asyncio.get_event_loop()
        flow = await loop.run_in_executor(
            _msal_executor,
            lambda: self.public_app.initiate_device_flow(scopes=scopes)
        )
        if not flow or "user_code" not in flow:
            raise Exception(f"Failed to start device-code flow: {flow}")

        self._pending_device_flow = flow
        return {
            "status": "auth_required",
            "message": flow.get("message", "Complete sign-in with the provided code."),
            "verification_uri": flow.get("verification_uri") or flow.get("verification_uri_complete"),
            "user_code": flow.get("user_code"),
            "expires_in": flow.get("expires_in"),
            "interval": flow.get("interval"),
            "scopes": scopes,
        }

    async def _start_browser_sign_in(self) -> dict[str, Any]:
        """Start browser-based interactive sign-in and wait for completion."""
        scopes = self.config.user_auth_scopes or ["User.Read"]
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _msal_executor,
            lambda: self.public_app.acquire_token_interactive(
                scopes=scopes,
                prompt="select_account",
            ),
        )

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise Exception(f"Interactive browser sign-in failed: {error}")

        self._save_token_cache()
        return {
            "status": "signed_in",
            "message": "Browser sign-in completed successfully.",
            "account": result.get("id_token_claims", {}).get("preferred_username", "unknown"),
            "expires_in": result.get("expires_in", 0),
            "scopes": scopes,
        }

    async def complete_interactive_sign_in(self) -> dict[str, Any]:
        """Complete device-code flow after user signs in and persist token cache."""
        # Browser mode is a single-step flow: completion should trigger the browser prompt.
        if self.config.interactive_login_mode == "browser":
            return await self._start_browser_sign_in()

        if not self._pending_device_flow:
            # Return a fresh device-code prompt instead of failing hard.
            return await self._start_device_code_sign_in()

        flow = self._pending_device_flow
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _msal_executor,
            lambda: self.public_app.acquire_token_by_device_flow(flow)
        )

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise Exception(f"Interactive sign-in failed: {error}")

        self._save_token_cache()
        self._pending_device_flow = None
        return {
            "status": "signed_in",
            "account": result.get("id_token_claims", {}).get("preferred_username", "unknown"),
            "expires_in": result.get("expires_in", 0),
        }

    async def ensure_authenticated(self) -> dict[str, Any]:
        """Ensure the configured auth mode is authenticated and return a status payload."""
        if self.config.auth_mode == "app":
            await self._acquire_app_token()
            return {
                "status": "authenticated",
                "auth_mode": "app",
                "source": "client_credentials",
            }

        if self.config.auth_mode == "delegated":
            token = await self._acquire_delegated_token_silent()
            if token:
                self._token = token
                self._token_expires = datetime.now() + timedelta(minutes=30)
                return {
                    "status": "authenticated",
                    "auth_mode": "delegated",
                    "source": "cache",
                }

            details = await self.start_interactive_sign_in()
            if details.get("status") == "signed_in":
                token = await self._acquire_delegated_token_silent()
                if token:
                    self._token = token
                    self._token_expires = datetime.now() + timedelta(minutes=30)
                    return {
                        "status": "authenticated",
                        "auth_mode": "delegated",
                        "source": "interactive",
                        "details": details,
                    }

            raise AuthRequiredError(
                "Delegated token not available. Complete interactive sign-in.",
                details=details,
            )

        if self.config.auth_mode == "hybrid":
            if self.config.require_user_login:
                token = await self._acquire_delegated_token_silent()
                if token:
                    self._token = token
                    self._token_expires = datetime.now() + timedelta(minutes=30)
                    return {
                        "status": "authenticated",
                        "auth_mode": "hybrid",
                        "source": "cache",
                    }

                details = await self.start_interactive_sign_in()
                if details.get("status") == "signed_in":
                    token = await self._acquire_delegated_token_silent()
                    if token:
                        self._token = token
                        self._token_expires = datetime.now() + timedelta(minutes=30)
                        return {
                            "status": "authenticated",
                            "auth_mode": "hybrid",
                            "source": "interactive",
                            "details": details,
                        }

                raise AuthRequiredError(
                    "User sign-in required before app authentication. Complete the sign-in flow.",
                    details=details,
                )

            await self._acquire_app_token()
            return {
                "status": "authenticated",
                "auth_mode": "hybrid",
                "source": "app_credentials",
            }

        raise ValueError(f"Unsupported auth mode: {self.config.auth_mode}")

    async def get_token(self) -> str:
        """Get a valid access token, refreshing if necessary."""
        if self._token and self._token_expires and datetime.now() < self._token_expires:
            return self._token

        await self.ensure_authenticated()

        if self._token and self._token_expires and datetime.now() < self._token_expires:
            return self._token

        return await self._acquire_app_token()

    async def get_auth_status(self) -> dict[str, Any]:
        """Return current auth mode and cached interactive sign-in status."""
        accounts = []
        if self.config.auth_mode in {"delegated", "hybrid"}:
            loop = asyncio.get_event_loop()
            accounts = await loop.run_in_executor(_msal_executor, lambda: self.public_app.get_accounts())

        return {
            "auth_mode": self.config.auth_mode,
            "require_user_login": self.config.require_user_login,
            "has_app_credentials": bool(self.config.tenant_id and self.config.client_id and self.config.client_secret),
            "has_cached_user_login": len(accounts) > 0,
            "cached_accounts": [a.get("username", "unknown") for a in accounts],
            "pending_interactive_login": self._pending_device_flow is not None,
            "interactive_login_mode": self.config.interactive_login_mode,
            "user_auth_scopes": self.config.user_auth_scopes or ["User.Read"],
        }
    
    async def get_http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        use_beta: bool = False,
        _max_retries: int = 3,
        **kwargs
    ) -> dict[str, Any]:
        """Make an authenticated request to Microsoft Graph with retry for transient failures."""
        base_url = self.config.beta_endpoint if use_beta else self.config.graph_endpoint
        url = f"{base_url}{endpoint}" if endpoint.startswith("/") else f"{base_url}/{endpoint}"
        extra_headers = kwargs.pop("headers", {})
        
        for attempt in range(_max_retries + 1):
            token = await self.get_token()
            client = await self.get_http_client()
            
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                **extra_headers,
            }
            
            response = await client.request(method, url, headers=headers, **kwargs)
            
            if response.status_code in (429, 503) and attempt < _max_retries:
                retry_after = int(response.headers.get("Retry-After", min(2 ** attempt, 16)))
                await asyncio.sleep(retry_after)
                continue
            
            break
        
        if response.status_code == 204:
            return {"status": "success", "message": "Operation completed successfully"}
        
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_message = error_data.get("error", {}).get("message", response.text)
            except Exception:
                error_message = response.text
            raise Exception(f"Graph API error ({response.status_code}): {error_message}")
        
        if not response.text or response.text.strip() == "":
            return {"status": "success", "message": "Operation completed successfully"}
        
        try:
            return response.json()
        except Exception:
            if 200 <= response.status_code < 300:
                return {"status": "success", "message": "Operation completed successfully", "raw_response": response.text}
            raise
    
    async def get(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a GET request."""
        return await self._request("GET", endpoint, use_beta=use_beta, **kwargs)
    
    async def post(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a POST request."""
        return await self._request("POST", endpoint, use_beta=use_beta, **kwargs)
    
    async def patch(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a PATCH request."""
        return await self._request("PATCH", endpoint, use_beta=use_beta, **kwargs)

    async def put(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a PUT request."""
        return await self._request("PUT", endpoint, use_beta=use_beta, **kwargs)
    
    async def delete(self, endpoint: str, use_beta: bool = False, **kwargs) -> dict[str, Any]:
        """Make a DELETE request."""
        return await self._request("DELETE", endpoint, use_beta=use_beta, **kwargs)
    
    async def get_all_pages(
        self,
        endpoint: str,
        use_beta: bool = False,
        max_pages: int = 100
    ) -> list[dict[str, Any]]:
        """Get all pages of a paginated response."""
        all_items = []
        current_endpoint = endpoint
        page_count = 0
        
        while current_endpoint and page_count < max_pages:
            if page_count > 0:
                token = await self.get_token()
                client = await self.get_http_client()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.get(current_endpoint, headers=headers)
                response = resp.json()
            else:
                response = await self.get(current_endpoint, use_beta=use_beta)
            
            items = response.get("value", [])
            all_items.extend(items)
            
            # Check for next page
            current_endpoint = response.get("@odata.nextLink")
            page_count += 1
        
        return all_items
    
    async def close(self):
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# Global client instance (lazy loaded)
_client: GraphClient | None = None


def get_graph_client() -> GraphClient:
    """Get the global Graph client instance."""
    global _client
    if _client is None:
        _client = GraphClient()
    return _client


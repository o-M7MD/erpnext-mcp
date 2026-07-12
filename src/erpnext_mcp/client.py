import os
import httpx
import json
import re
from typing import Optional, Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

def sanitize_path_component(value: str, label: str) -> str:
    # Use a strict regex allowlist to prevent injection, path traversal, null bytes, etc.
    # Allowed: alphanumeric, space, underscore, dot, hyphen
    if not value or not re.match(r'^[a-zA-Z0-9 _.\-]+$', str(value)):
        raise ValueError(f"Invalid {label}: contains forbidden characters.")
    if ".." in str(value):
        raise ValueError(f"Invalid {label}: contains forbidden characters.")
    return str(value)

class ERPNextClient:
    def __init__(self, url: str = None, api_key: str = None, api_secret: str = None):
        self.url = url or os.environ.get("ERPNEXT_URL")
        self.api_key = api_key or os.environ.get("ERPNEXT_API_KEY")
        self.api_secret = api_secret or os.environ.get("ERPNEXT_API_SECRET")
        
        if not self.url or not self.api_key or not self.api_secret:
            raise ValueError("Missing ERPNext connection credentials (URL, API_KEY, API_SECRET)")
            
        self.url = self.url.rstrip("/")
        
        self.headers = {
            "Authorization": f"token {self.api_key}:{self.api_secret}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Connection pooling and strict timeouts
        self.client = httpx.AsyncClient(
            headers=self.headers, 
            base_url=f"{self.url}/api/",
            timeout=httpx.Timeout(30.0, connect=10.0)
        )

    async def close(self):
        await self.client.aclose()
        
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException, httpx.ReadError, httpx.WriteError))
    )
    async def _request(self, method: str, endpoint: str, params: dict = None, data: dict = None) -> Any:
        kwargs = {}
        if params:
            for k, v in params.items():
                if isinstance(v, (list, dict)):
                    params[k] = json.dumps(v)
            kwargs["params"] = params
        if data:
            kwargs["json"] = data
            
        response = await self.client.request(method, endpoint, **kwargs)
        
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            # Mask internal details from the error response to prevent leaking stack traces
            error_msg = "Unknown error"
            try:
                error_json = response.json()
                if "_server_messages" in error_json:
                    msgs = json.loads(error_json["_server_messages"])
                    parsed_msgs = [json.loads(m).get("message", m) for m in msgs]
                    error_msg = " | ".join(parsed_msgs)
            except Exception:
                # Fallback to generic status message without exposing traceback HTML or SQL queries
                error_msg = f"The backend returned a {response.status_code} status code."
            raise Exception(f"ERPNext API Error ({response.status_code}): {error_msg}") from None
            
        json_response = response.json()
        if "data" in json_response:
            return json_response["data"]
        elif "message" in json_response:
            return json_response["message"]
        return json_response

    async def get_list(self, doctype: str, filters: list = None, fields: list = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Fetch a list of documents."""
        # Hard cap the limit to prevent massive payload memory spikes or bypasses
        limit = max(1, min(limit, 1000))
        
        params = {
            "limit_page_length": limit
        }
        if filters:
            params["filters"] = filters
        if fields:
            params["fields"] = fields
        
        doctype = sanitize_path_component(doctype, "doctype")
        return await self._request("GET", f"resource/{doctype}", params=params)

    async def get_doc(self, doctype: str, name: str) -> Dict[str, Any]:
        """Fetch a single document."""
        doctype = sanitize_path_component(doctype, "doctype")
        name = sanitize_path_component(name, "name")
        return await self._request("GET", f"resource/{doctype}/{name}")

    async def create_doc(self, doctype: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new document."""
        payload = data.copy()
        payload["doctype"] = doctype
        doctype = sanitize_path_component(doctype, "doctype")
        return await self._request("POST", f"resource/{doctype}", data=payload)

    async def update_doc(self, doctype: str, name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing document."""
        doctype = sanitize_path_component(doctype, "doctype")
        name = sanitize_path_component(name, "name")
        return await self._request("PUT", f"resource/{doctype}/{name}", data=data)

    async def delete_doc(self, doctype: str, name: str) -> str:
        """Delete a document."""
        doctype = sanitize_path_component(doctype, "doctype")
        name = sanitize_path_component(name, "name")
        await self._request("DELETE", f"resource/{doctype}/{name}")
        return "Deleted successfully"

    async def execute_method(self, method: str, kwargs: dict = None) -> Any:
        """Execute a whitelisted python method."""
        method = sanitize_path_component(method, "method")
        return await self._request("POST", f"method/{method}", data=kwargs or {})

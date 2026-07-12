import os
import httpx
import json
import re
from typing import Optional, Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

def sanitize_path_component(value: str, label: str) -> str:
    # Allowed: alphanumeric, space, underscore, dot, hyphen
    if not value or not re.match(r'^[a-zA-Z0-9 _.\-]+$', str(value)):
        raise ValueError(f"Invalid {label}: contains forbidden characters.")
    if ".." in str(value):
        raise ValueError(f"Invalid {label}: contains forbidden characters.")
    return str(value)

def validate_method_path(value: str) -> str:
    # H5: Specific sanitizer for dotted method paths
    if not value or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*$', str(value)):
        raise ValueError("Invalid method path: contains forbidden characters.")
    return str(value)

from urllib.parse import urlparse

class ERPNextClient:
    def __init__(self, url: str = None, api_key: str = None, api_secret: str = None):
        self.url = url or os.environ.get("ERPNEXT_URL")
        self.api_key = api_key or os.environ.get("ERPNEXT_API_KEY")
        self.api_secret = api_secret or os.environ.get("ERPNEXT_API_SECRET")
        
        if not self.url or not self.api_key or not self.api_secret:
            raise ValueError("Missing ERPNext connection credentials (URL, API_KEY, API_SECRET)")
            
        # C8: Strict SSRF protection
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("ERPNEXT_URL must use http or https")
        if parsed.hostname in ("169.254.169.254", "metadata.google.internal"):
            raise ValueError("ERPNEXT_URL points to a cloud metadata endpoint — blocked")
            
        self.url = self.url.rstrip("/")
        
        self.headers = {
            "Authorization": f"token {self.api_key}:{self.api_secret}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        self.client = httpx.AsyncClient(
            headers=self.headers, 
            base_url=f"{self.url}/api/",
            timeout=httpx.Timeout(10.0, connect=5.0),
            verify=True
        )

    async def close(self):
        await self.client.aclose()
        
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=5),
        # H2: Handle stale keep-alive connections
        retry=retry_if_exception_type((
            httpx.ConnectError, httpx.TimeoutException, 
            httpx.ReadError, httpx.WriteError,
            httpx.RemoteProtocolError, httpx.PoolTimeout
        ))
    )
    async def _request(self, method: str, endpoint: str, params: dict = None, data: dict = None) -> Any:
        kwargs = {}
        if params:
            for k, v in params.items():
                if isinstance(v, (list, dict)):
                    params[k] = json.dumps(v, default=str)
            kwargs["params"] = params
        if data:
            kwargs["json"] = data
            
        # H3: Use stream to check Content-Length before downloading full response
        async with self.client.stream(method, endpoint, **kwargs) as response:
            try:
                response.raise_for_status()
                
                content_length = int(response.headers.get("Content-Length", 0))
                if content_length > 5_000_000:
                    raise ValueError(f"Response size ({content_length} bytes) exceeds 5MB limit.")
                    
                body = await response.aread()
                
            except httpx.HTTPStatusError as e:
                # Mask internal details from the error response
                await response.aread()
                error_msg = "Unknown error"
                try:
                    error_json = response.json()
                    # M9: Hard-cap server messages length
                    raw_msgs = error_json.get("_server_messages", "")
                    if len(raw_msgs) > 10000:
                        error_msg = "Error response too large to parse."
                    elif raw_msgs:
                        msgs = json.loads(raw_msgs)
                        parsed_msgs = [json.loads(m).get("message", m) for m in msgs]
                        error_msg = " | ".join(parsed_msgs)
                except Exception:
                    error_msg = f"The backend returned a {response.status_code} status code."
                raise Exception(f"ERPNext API Error ({response.status_code}): {error_msg}") from None
            
        json_response = json.loads(body)
        if "data" in json_response:
            return json_response["data"]
        elif "message" in json_response:
            return json_response["message"]
        return json_response

    async def get_list(self, doctype: str, filters: list = None, fields: list = None, limit: int = 1000) -> List[Dict[str, Any]]:
        limit = max(1, min(limit, 1000))
        params = {"limit_page_length": limit}
        if filters: params["filters"] = filters
        if fields: params["fields"] = fields
        
        doctype = sanitize_path_component(doctype, "doctype")
        return await self._request("GET", f"resource/{doctype}", params=params)

    async def get_doc(self, doctype: str, name: str) -> Dict[str, Any]:
        doctype = sanitize_path_component(doctype, "doctype")
        name = sanitize_path_component(name, "name")
        return await self._request("GET", f"resource/{doctype}/{name}")

    async def create_doc(self, doctype: str, data: Dict[str, Any]) -> Dict[str, Any]:
        payload = data.copy()
        payload["doctype"] = doctype
        doctype = sanitize_path_component(doctype, "doctype")
        return await self._request("POST", f"resource/{doctype}", data=payload)

    async def update_doc(self, doctype: str, name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        doctype = sanitize_path_component(doctype, "doctype")
        name = sanitize_path_component(name, "name")
        return await self._request("PUT", f"resource/{doctype}/{name}", data=data)

    async def delete_doc(self, doctype: str, name: str) -> str:
        doctype = sanitize_path_component(doctype, "doctype")
        name = sanitize_path_component(name, "name")
        await self._request("DELETE", f"resource/{doctype}/{name}")
        return "Deleted successfully"

    async def execute_method(self, method: str, kwargs: dict = None) -> Any:
        # H5: Strict regex for methods
        method = validate_method_path(method)
        return await self._request("POST", f"method/{method}", data=kwargs or {})

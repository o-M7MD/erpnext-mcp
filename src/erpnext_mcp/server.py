import os
import json
import asyncio
import logging
import time
from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP
from .client import ERPNextClient

# Set up structured logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("erpnext_mcp")

# Load Configuration
CONFIG_PATH = os.environ.get("ERPNEXT_MCP_CONFIG", "config.json")
if not os.path.exists(CONFIG_PATH):
    raise RuntimeError(f"CRITICAL ERROR: Configuration file not found at {CONFIG_PATH}. Cannot start securely.")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

# C2: Backward compatibility for legacy "allowed_doctypes"
if "allowed_doctypes" in config and not config.get("readable_doctypes"):
    legacy_docs = config.get("allowed_doctypes", [])
    logger.warning("Legacy 'allowed_doctypes' found in config. Mapping to read/write/delete permissions. Please update your config schema.")
    config["readable_doctypes"] = legacy_docs
    config["writable_doctypes"] = legacy_docs
    config["deletable_doctypes"] = legacy_docs

READABLE_DOCTYPES = set(config.get("readable_doctypes", []))
WRITABLE_DOCTYPES = set(config.get("writable_doctypes", []))
DELETABLE_DOCTYPES = set(config.get("deletable_doctypes", []))
ALLOWED_METHODS = set(config.get("allowed_methods", []))
MCP_TOKENS = set(config.get("mcp_tokens", []))

# NEW-5: Schema Validation at startup
if not READABLE_DOCTYPES and not WRITABLE_DOCTYPES:
    logger.warning("WARNING: No doctypes are configured for read or write. All requests will be denied.")

unknown_keys = set(config.keys()) - {"readable_doctypes", "writable_doctypes", "deletable_doctypes", "allowed_methods", "mcp_tokens", "allowed_doctypes"}
if unknown_keys:
    logger.warning(f"Unknown config keys detected (possible typo): {unknown_keys}")

# Initialize FastMCP Server
mcp = FastMCP("ERPNext")

# Global client for connection pooling with Lock for thread-safety
_client = None
_client_lock = asyncio.Lock()

async def get_client():
    global _client
    async with _client_lock:
        if _client is None:
            _client = ERPNextClient()
    return _client

def check_doctype_access(doctype: str, action: str):
    if action == "READ" and doctype not in READABLE_DOCTYPES:
        logger.warning(f"Rejected READ access to DocType: {doctype}")
        raise ValueError(f"Read access to DocType '{doctype}' is denied.")
    elif action == "WRITE" and doctype not in WRITABLE_DOCTYPES:
        logger.warning(f"Rejected WRITE access to DocType: {doctype}")
        raise ValueError(f"Write access to DocType '{doctype}' is denied.")
    elif action == "DELETE" and doctype not in DELETABLE_DOCTYPES:
        logger.warning(f"Rejected DELETE access to DocType: {doctype}")
        raise ValueError(f"Delete access to DocType '{doctype}' is denied.")

def validate_input_fields(fields: list = None, filters: list = None):
    # M4: Input validation to block sensitive data extraction
    sensitive_keywords = {"password", "api_key", "api_secret", "session", "token", "hash"}
    
    if fields:
        if not isinstance(fields, list):
            raise ValueError("Fields must be a list of strings.")
        for field in fields:
            if not isinstance(field, str):
                raise ValueError("Fields must be a list of strings.")
            if any(sensitive in field.lower() for sensitive in sensitive_keywords):
                raise ValueError(f"Access to sensitive field '{field}' is blocked by security policy.")
                
    if filters:
        if not isinstance(filters, list):
            raise ValueError("Filters must be a list.")
        for f in filters:
            if isinstance(f, list) and len(f) >= 2:
                field_name = str(f[1]).lower()
                if any(sensitive in field_name for sensitive in sensitive_keywords):
                    raise ValueError(f"Filtering on sensitive field '{field_name}' is blocked by security policy.")

@mcp.tool()
async def erpnext_get_list(doctype: str, filters: list = None, fields: list = None, limit: int = 1000) -> str:
    """
    Fetch a list of records from ERPNext.
    
    Args:
        doctype: The DocType to fetch (e.g., 'Customer', 'Sales Invoice')
        filters: Optional list of filters, e.g. [["Customer", "customer_group", "=", "Commercial"]]
        fields: Optional list of fields to return, e.g. ["name", "customer_name"]
        limit: Max number of records to return (capped at 1000)
    """
    try:
        logger.info(f"Tool call: get_list | doctype={doctype} limit={limit}")
        check_doctype_access(doctype, "READ")
        validate_input_fields(fields=fields, filters=filters)
        
        client = await get_client()
        data = await client.get_list(doctype, filters=filters, fields=fields, limit=limit)
        return json.dumps(data, separators=(',', ':'))
    except Exception as e:
        logger.error(f"Error in get_list: {e}")
        return f"Error: {str(e)}"

@mcp.tool()
async def erpnext_get_doc(doctype: str, name: str) -> str:
    """
    Fetch a specific document from ERPNext by name.
    
    Args:
        doctype: The DocType (e.g., 'Customer')
        name: The primary key / name of the document
    """
    try:
        logger.info(f"Tool call: get_doc | doctype={doctype} name={name}")
        check_doctype_access(doctype, "READ")
        client = await get_client()
        data = await client.get_doc(doctype, name)
        # H3: Cap response sizes
        json_resp = json.dumps(data, separators=(',', ':'))
        if len(json_resp) > 5_000_000:
            raise ValueError("Document payload exceeds 5MB limit.")
        return json_resp
    except Exception as e:
        logger.error(f"Error in get_doc: {e}")
        return f"Error: {str(e)}"

@mcp.tool()
async def erpnext_create_doc(doctype: str, doc_data: str) -> str:
    """
    Create a new document in ERPNext.
    
    Args:
        doctype: The DocType to create
        doc_data: JSON string containing the document fields and values
    """
    try:
        logger.info(f"Tool call: create_doc | doctype={doctype}")
        check_doctype_access(doctype, "WRITE")
        client = await get_client()
        parsed_data = json.loads(doc_data)
        data = await client.create_doc(doctype, parsed_data)
        return f"Created successfully:\n{json.dumps(data, separators=(',', ':'))}"
    except json.JSONDecodeError:
        return "Error: doc_data must be a valid JSON string."
    except Exception as e:
        logger.error(f"Error in create_doc: {e}")
        return f"Error: {str(e)}"

@mcp.tool()
async def erpnext_update_doc(doctype: str, name: str, doc_data: str) -> str:
    """
    Update an existing document in ERPNext.
    
    Args:
        doctype: The DocType
        name: The name of the document to update
        doc_data: JSON string containing the fields to update
    """
    try:
        logger.info(f"Tool call: update_doc | doctype={doctype} name={name}")
        check_doctype_access(doctype, "WRITE")
        client = await get_client()
        parsed_data = json.loads(doc_data)
        data = await client.update_doc(doctype, name, parsed_data)
        return f"Updated successfully:\n{json.dumps(data, separators=(',', ':'))}"
    except json.JSONDecodeError:
        return "Error: doc_data must be a valid JSON string."
    except Exception as e:
        logger.error(f"Error in update_doc: {e}")
        return f"Error: {str(e)}"

@mcp.tool()
async def erpnext_delete_doc(doctype: str, name: str) -> str:
    """
    Delete a document in ERPNext.
    
    Args:
        doctype: The DocType
        name: The name of the document to delete
    """
    try:
        logger.warning(f"Tool call: delete_doc | doctype={doctype} name={name}")
        check_doctype_access(doctype, "DELETE")
        client = await get_client()
        result = await client.delete_doc(doctype, name)
        return result
    except Exception as e:
        logger.error(f"Error in delete_doc: {e}")
        return f"Error: {str(e)}"

@mcp.tool()
async def erpnext_call_method(method: str, kwargs_json: str = None) -> str:
    """
    Call a whitelisted Frappe/ERPNext python method.
    
    Args:
        method: The dotted path to the method (e.g., 'erpnext.accounts.doctype.sales_invoice.sales_invoice.make_delivery_note')
        kwargs_json: Optional JSON string of arguments to pass to the method
    """
    try:
        logger.info(f"Tool call: call_method | method={method}")
        if method not in ALLOWED_METHODS:
            logger.warning(f"Rejected access to method: {method}")
            raise ValueError(f"Access to method '{method}' is denied by the MCP configuration.")
        
        client = await get_client()
        kwargs = {}
        if kwargs_json:
            kwargs = json.loads(kwargs_json)
        data = await client.execute_method(method, kwargs)
        return json.dumps(data, separators=(',', ':'))
    except json.JSONDecodeError:
        return "Error: kwargs_json must be a valid JSON string."
    except Exception as e:
        logger.error(f"Error in call_method: {e}")
        return f"Error: {str(e)}"

def main():
    if not all([os.environ.get("ERPNEXT_URL"), os.environ.get("ERPNEXT_API_KEY"), os.environ.get("ERPNEXT_API_SECRET")]):
        logger.warning("ERPNEXT_URL, ERPNEXT_API_KEY, and ERPNEXT_API_SECRET environment variables are not all set.")
    
    port = os.environ.get("PORT")
    if port:
        logger.info(f"Starting MCP Server in SSE mode on port {port}")
        
        try:
            import uvicorn
            from starlette.applications import Starlette
            from starlette.responses import JSONResponse
            from starlette.middleware.base import BaseHTTPMiddleware
            from starlette.middleware.cors import CORSMiddleware
            from contextlib import asynccontextmanager
            
            app = getattr(mcp, "_app", None)
            if not app:
                logger.warning("FastMCP internal ASGI app not found. Running native unauthenticated SSE.")
                mcp.run(transport='sse', port=int(port))
                return
                
            # H1 / NEW-3: In-memory Rate Limiting (Bounded)
            RATE_LIMIT_DICT = {}
            
            class TokenAuthAndRateLimitMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request, call_next):
                    if request.url.path == "/health":
                        return await call_next(request)
                    
                    # NEW-3: Use X-Forwarded-For if available
                    forwarded = request.headers.get("X-Forwarded-For")
                    if forwarded:
                        ip = forwarded.split(",")[0].strip()
                    else:
                        ip = request.client.host if request.client else "127.0.0.1"
                        
                    now = time.time()
                    
                    # Prevent unbounded memory growth
                    if len(RATE_LIMIT_DICT) > 10000 and ip not in RATE_LIMIT_DICT:
                        # Clear old entries to free memory
                        stale_keys = [k for k, v in RATE_LIMIT_DICT.items() if not v or (now - v[-1]) > 60]
                        for k in stale_keys:
                            RATE_LIMIT_DICT.pop(k, None)
                        # If still too large, reject new IPs
                        if len(RATE_LIMIT_DICT) > 10000:
                            return JSONResponse({"detail": "Server under heavy load"}, status_code=503)
                            
                    # Get or init list for IP
                    timestamps = RATE_LIMIT_DICT.get(ip, [])
                    timestamps = [t for t in timestamps if now - t < 60]
                    
                    if len(timestamps) >= 120:
                        logger.warning(f"Rate limit exceeded for IP {ip}")
                        RATE_LIMIT_DICT[ip] = timestamps
                        return JSONResponse({"detail": "Rate limit exceeded (120 req/min)"}, status_code=429)
                        
                    timestamps.append(now)
                    RATE_LIMIT_DICT[ip] = timestamps
                    
                    # C1 / NEW-1: Auth Fail-Closed. STRICT REQUIREMENT
                    if not MCP_TOKENS:
                        logger.error("CRITICAL: Auth is enabled but MCP_TOKENS is empty. Failing closed.")
                        return JSONResponse({"detail": "Server configuration error: No valid tokens defined."}, status_code=500)
                    
                    auth_header = request.headers.get("Authorization", "")
                    if not auth_header.startswith("Bearer "):
                        return JSONResponse({"detail": "Unauthorized. Missing or invalid Bearer token prefix."}, status_code=401)
                    
                    token = auth_header[7:].strip()
                    if token not in MCP_TOKENS:
                        logger.warning(f"Unauthorized access attempt to {request.url.path} from {ip}")
                        return JSONResponse({"detail": "Unauthorized. Invalid Bearer token."}, status_code=401)
                    
                    return await call_next(request)
            
            # NEW-6: Use Lifespan context manager instead of on_event("shutdown")
            @asynccontextmanager
            async def lifespan(app):
                # Startup
                yield
                # Shutdown
                global _client
                if _client:
                    logger.info("Closing ERPNext API client gracefully...")
                    await _client.close()

            wrapper = Starlette(lifespan=lifespan)
            
            # Middlewares are executed in reverse order of addition.
            # We want TokenAuth to run INNERMOST so CORS preflight OPTIONS bypasses Auth.
            # So TokenAuth is added FIRST.
            wrapper.add_middleware(TokenAuthAndRateLimitMiddleware)
            
            # NEW-4 / NEW-9: CORS runs OUTERMOST.
            wrapper.add_middleware(
                CORSMiddleware,
                allow_origins=["*"], 
                allow_credentials=False, # Must be false when origin is *
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
            @wrapper.route("/health")
            async def health(request):
                return JSONResponse({"status": "ok"})
                
            wrapper.mount("/", app)
            
            logger.info("ASGI Token Auth Middleware, CORS, and Rate Limiter successfully injected.")
            uvicorn.run(wrapper, host="0.0.0.0", port=int(port))
            
        except ImportError:
            logger.warning("uvicorn/starlette not found. Running native FastMCP SSE.")
            mcp.run(transport='sse', port=int(port))
    else:
        logger.info("Starting MCP Server in stdio mode")
        mcp.run()

if __name__ == "__main__":
    main()

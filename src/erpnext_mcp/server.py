import os
import sys
import json
import asyncio
import logging
import time
import hmac
from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP
from .client import ERPNextClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("erpnext_mcp")

# M11 & L11: Fail fast if credentials missing
if not all([os.environ.get("ERPNEXT_URL"), os.environ.get("ERPNEXT_API_KEY"), os.environ.get("ERPNEXT_API_SECRET")]):
    logger.critical("FATAL: ERPNEXT_URL, ERPNEXT_API_KEY, and ERPNEXT_API_SECRET must be set. Refusing to start.")
    sys.exit(1)

CONFIG_PATH = os.environ.get("ERPNEXT_MCP_CONFIG", "config.json")
if not os.path.exists(CONFIG_PATH):
    logger.critical(f"FATAL: Configuration file not found at {CONFIG_PATH}. Refusing to start.")
    sys.exit(1)

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

# H10: Legacy mode is read-only by default
if "allowed_doctypes" in config and not config.get("readable_doctypes"):
    legacy_docs = config.get("allowed_doctypes", [])
    logger.warning("Legacy 'allowed_doctypes' found in config. Mapping to READ-ONLY permissions for safety. Please update your config schema.")
    config["readable_doctypes"] = legacy_docs
    config["writable_doctypes"] = []
    config["deletable_doctypes"] = []

# C6: Lowercase for case-insensitive validation
READABLE_DOCTYPES = {d.lower() for d in config.get("readable_doctypes", [])}
WRITABLE_DOCTYPES = {d.lower() for d in config.get("writable_doctypes", [])}
DELETABLE_DOCTYPES = {d.lower() for d in config.get("deletable_doctypes", [])}
ALLOWED_METHODS = set(config.get("allowed_methods", []))
MCP_TOKENS = set(config.get("mcp_tokens", []))

if not READABLE_DOCTYPES and not WRITABLE_DOCTYPES:
    logger.warning("WARNING: No doctypes are configured for read or write. All requests will be denied.")

unknown_keys = set(config.keys()) - {"readable_doctypes", "writable_doctypes", "deletable_doctypes", "allowed_methods", "mcp_tokens", "allowed_doctypes"}
if unknown_keys:
    logger.warning(f"Unknown config keys detected (possible typo): {unknown_keys}")

mcp = FastMCP("ERPNext")
_client = None
_client_lock = asyncio.Lock()

async def get_client():
    global _client
    async with _client_lock:
        if _client is None:
            _client = ERPNextClient()
    return _client

def check_doctype_access(doctype: str, action: str):
    normalized = doctype.strip().lower()
    if action == "READ" and normalized not in READABLE_DOCTYPES:
        raise ValueError(f"Read access to DocType '{doctype}' is denied.")
    elif action == "WRITE" and normalized not in WRITABLE_DOCTYPES:
        raise ValueError(f"Write access to DocType '{doctype}' is denied.")
    elif action == "DELETE" and normalized not in DELETABLE_DOCTYPES:
        raise ValueError(f"Delete access to DocType '{doctype}' is denied.")

SENSITIVE_KEYWORDS = {"password", "api_key", "api_secret", "session", "token", "hash", "secret", "owner", "_user_tags", "_comments", "_assign"}

ALLOWED_FILTER_OPERATORS = {"=", "!=", ">", "<", ">=", "<=", "like", "not like", "in", "not in", "is", "between"}

def validate_input_fields(doctype: str, fields: list = None, filters: list = None):
    if fields:
        if not isinstance(fields, list):
            raise ValueError("Fields must be a list of strings.")
        for field in fields:
            if not isinstance(field, str):
                raise ValueError("Fields must be a list of strings.")
            if any(sensitive in field.lower() for sensitive in SENSITIVE_KEYWORDS):
                raise ValueError(f"Access to sensitive field '{field}' is blocked by security policy.")
                
    if filters:
        if not isinstance(filters, list):
            raise ValueError("Filters must be a list.")
        for f in filters:
            # Frappe array filters: [doctype, fieldname, operator, value]
            if isinstance(f, list) and len(f) >= 3:
                # H6: Cross-doctype filter injection check
                filter_doctype = str(f[0])
                if filter_doctype.lower() != doctype.lower():
                    raise ValueError(f"Cross-doctype filter on '{filter_doctype}' is not allowed.")
                
                # Operator validation
                operator = str(f[2]).lower()
                if operator not in ALLOWED_FILTER_OPERATORS:
                    raise ValueError(f"Filter operator '{operator}' is not allowed.")
                
                field_name = str(f[1]).lower()
                if any(sensitive in field_name for sensitive in SENSITIVE_KEYWORDS):
                    raise ValueError(f"Filtering on sensitive field '{field_name}' is blocked by security policy.")

# C7 & H9: Write-side field validation to prevent overriding system fields
FORBIDDEN_WRITE_FIELDS = {"doctype", "owner", "modified_by", "creation", "modified", "docstatus", "idx", "name", "parent", "parenttype", "parentfield"}

def validate_write_data(data: dict):
    for key in FORBIDDEN_WRITE_FIELDS:
        data.pop(key, None)
    for key in list(data.keys()):
        if any(sensitive in str(key).lower() for sensitive in SENSITIVE_KEYWORDS):
            raise ValueError(f"Writing to sensitive field '{key}' is blocked.")

def sanitize_response_dict(data: Any) -> Any:
    # C4: Strip PII and internal metadata from responses
    if isinstance(data, dict):
        return {k: sanitize_response_dict(v) for k, v in data.items() 
                if not any(sensitive in str(k).lower() for sensitive in SENSITIVE_KEYWORDS)}
    elif isinstance(data, list):
        return [sanitize_response_dict(i) for i in data]
    return data

def format_error(e: Exception) -> str:
    # M1: Mask uncaught exceptions
    if isinstance(e, (ValueError, json.JSONDecodeError)):
        return f"Error: {str(e)}"
    return "Error: An internal server error occurred. Check server logs."

@mcp.tool()
async def erpnext_get_list(doctype: str, filters: list = None, fields: list = None, limit: int = 1000) -> str:
    try:
        logger.info(f"Tool call: get_list | doctype={doctype} limit={limit}")
        check_doctype_access(doctype, "READ")
        validate_input_fields(doctype, fields=fields, filters=filters)
        
        client = await get_client()
        data = await client.get_list(doctype, filters=filters, fields=fields, limit=limit)
        clean_data = sanitize_response_dict(data)
        return json.dumps(clean_data, separators=(',', ':'), default=str)
    except Exception as e:
        logger.error(f"Error in get_list: {e}", exc_info=True)
        return format_error(e)

@mcp.tool()
async def erpnext_get_doc(doctype: str, name: str) -> str:
    try:
        logger.info(f"Tool call: get_doc | doctype={doctype} name={name}")
        check_doctype_access(doctype, "READ")
        client = await get_client()
        data = await client.get_doc(doctype, name)
        
        clean_data = sanitize_response_dict(data)
        json_resp = json.dumps(clean_data, separators=(',', ':'), default=str)
        
        if len(json_resp) > 5_000_000:
            raise ValueError("Document payload exceeds 5MB limit.")
        return json_resp
    except Exception as e:
        logger.error(f"Error in get_doc: {e}", exc_info=True)
        return format_error(e)

@mcp.tool()
async def erpnext_create_doc(doctype: str, doc_data: str) -> str:
    try:
        logger.info(f"Tool call: create_doc | doctype={doctype}")
        check_doctype_access(doctype, "WRITE")
        
        parsed_data = json.loads(doc_data)
        validate_write_data(parsed_data)
        
        client = await get_client()
        data = await client.create_doc(doctype, parsed_data)
        
        # M10: Audit logging
        logger.warning(f"[AUDIT: WRITE] create_doc | doctype={doctype} | result_name={data.get('name')}")
        return f"Created successfully:\n{json.dumps(sanitize_response_dict(data), separators=(',', ':'), default=str)}"
    except Exception as e:
        logger.error(f"Error in create_doc: {e}", exc_info=True)
        return format_error(e)

@mcp.tool()
async def erpnext_update_doc(doctype: str, name: str, doc_data: str) -> str:
    try:
        logger.info(f"Tool call: update_doc | doctype={doctype} name={name}")
        check_doctype_access(doctype, "WRITE")
        
        parsed_data = json.loads(doc_data)
        validate_write_data(parsed_data)
        
        client = await get_client()
        data = await client.update_doc(doctype, name, parsed_data)
        
        # M10: Audit logging
        logger.warning(f"[AUDIT: WRITE] update_doc | doctype={doctype} | name={name}")
        return f"Updated successfully:\n{json.dumps(sanitize_response_dict(data), separators=(',', ':'), default=str)}"
    except Exception as e:
        logger.error(f"Error in update_doc: {e}", exc_info=True)
        return format_error(e)

@mcp.tool()
async def erpnext_delete_doc(doctype: str, name: str) -> str:
    try:
        logger.warning(f"Tool call: delete_doc | doctype={doctype} name={name}")
        check_doctype_access(doctype, "DELETE")
        client = await get_client()
        result = await client.delete_doc(doctype, name)
        
        # M10: Audit logging
        logger.warning(f"[AUDIT: WRITE] delete_doc | doctype={doctype} | name={name}")
        return result
    except Exception as e:
        logger.error(f"Error in delete_doc: {e}", exc_info=True)
        return format_error(e)

@mcp.tool()
async def erpnext_call_method(method: str, kwargs_json: str = None) -> str:
    try:
        logger.info(f"Tool call: call_method | method={method}")
        if method not in ALLOWED_METHODS:
            raise ValueError(f"Access to method '{method}' is denied by the MCP configuration.")
        
        kwargs = {}
        if kwargs_json:
            kwargs = json.loads(kwargs_json)
        
        client = await get_client()
        data = await client.execute_method(method, kwargs)
        return json.dumps(sanitize_response_dict(data), separators=(',', ':'), default=str)
    except Exception as e:
        logger.error(f"Error in call_method: {e}", exc_info=True)
        return format_error(e)

def main():
    raw_port = os.environ.get("PORT", "").strip()
    if raw_port:
        try:
            port = int(raw_port)
            if not (1024 <= port <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            logger.critical(f"FATAL: Invalid PORT '{raw_port}'. Must be 1024-65535. Refusing to start.")
            sys.exit(1)
            
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
                # C5: Fail fast if FastMCP ASGI app is missing
                logger.critical("FATAL: Cannot inject auth middleware — FastMCP internal ASGI app not found. REFUSING TO START.")
                sys.exit(1)
                
            RATE_LIMIT_DICT = {}
            
            class SecurityMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request, call_next):
                    if request.url.path == "/health":
                        return await call_next(request)
                        
                    cl = request.headers.get("Content-Length")
                    if cl and int(cl) > 1_000_000:
                        return JSONResponse({"detail": "Payload Too Large. Max 1MB allowed."}, status_code=413)
                    
                    client_host = request.client.host if request.client else "127.0.0.1"
                    is_private_ip = client_host.startswith(("127.", "10.", "172.", "192.168."))
                    
                    forwarded = request.headers.get("X-Forwarded-For")
                    if forwarded and is_private_ip:
                        ip = forwarded.split(",")[0].strip()
                    else:
                        ip = client_host
                        
                    now = time.time()
                    
                    if len(RATE_LIMIT_DICT) > 10000 and ip not in RATE_LIMIT_DICT:
                        stale_keys = [k for k, v in RATE_LIMIT_DICT.items() if not v or (now - v[-1]) > 60]
                        for k in stale_keys:
                            RATE_LIMIT_DICT.pop(k, None)
                        if len(RATE_LIMIT_DICT) > 10000:
                            return JSONResponse({"detail": "Server under heavy load"}, status_code=503)
                            
                    timestamps = RATE_LIMIT_DICT.get(ip, [])
                    timestamps = [t for t in timestamps if now - t < 60]
                    
                    if len(timestamps) >= 120:
                        logger.warning(f"Rate limit exceeded for IP {ip}")
                        RATE_LIMIT_DICT[ip] = timestamps
                        return JSONResponse({"detail": "Rate limit exceeded (120 req/min)"}, status_code=429)
                        
                    timestamps.append(now)
                    RATE_LIMIT_DICT[ip] = timestamps
                    
                    if not MCP_TOKENS:
                        logger.error("CRITICAL: Auth is enabled but MCP_TOKENS is empty. Failing closed.")
                        return JSONResponse({"detail": "Server configuration error: No valid tokens defined."}, status_code=500)
                    
                    auth_header = request.headers.get("Authorization", "")
                    if not auth_header.startswith("Bearer "):
                        return JSONResponse({"detail": "Unauthorized. Missing or invalid Bearer token prefix."}, status_code=401)
                    
                    token = auth_header[7:].strip().encode('utf-8')
                    is_valid = False
                    for valid_token in MCP_TOKENS:
                        if hmac.compare_digest(token, valid_token.encode('utf-8')):
                            is_valid = True
                            break
                            
                    if not is_valid:
                        logger.warning(f"Unauthorized access attempt to {request.url.path} from {ip}")
                        return JSONResponse({"detail": "Unauthorized. Invalid Bearer token."}, status_code=401)
                    
                    response = await call_next(request)
                    # L8: Security headers
                    response.headers["X-Content-Type-Options"] = "nosniff"
                    return response
            
            @asynccontextmanager
            async def lifespan(app):
                yield
                global _client
                if _client:
                    # M8: Prevent race condition on shutdown
                    client_ref = _client
                    _client = None
                    await client_ref.close()

            wrapper = Starlette(lifespan=lifespan)
            wrapper.add_middleware(SecurityMiddleware)
            
            wrapper.add_middleware(
                CORSMiddleware,
                allow_origins=["*"], 
                allow_credentials=False,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            
            @wrapper.route("/health")
            async def health(request):
                return JSONResponse({"status": "ok"})
                
            wrapper.mount("/", app)
            
            host = os.environ.get("HOST", "127.0.0.1")
            # M13 & H8: Add concurrency limits and configurable host
            uvicorn.run(wrapper, host=host, port=port, limit_concurrency=100)
            
        except ImportError:
            logger.critical("FATAL: uvicorn/starlette not found. Cannot run securely in SSE mode.")
            sys.exit(1)
    else:
        logger.info("Starting MCP Server in stdio mode")
        mcp.run()

if __name__ == "__main__":
    main()

import asyncio
import json
import sys

# Ensure src is in the python path
sys.path.insert(0, ".")

from src.erpnext_mcp.server import (
    erpnext_get_list, erpnext_get_doc, erpnext_create_doc, 
    erpnext_update_doc, erpnext_delete_doc, erpnext_call_method,
    READABLE_DOCTYPES, ALLOWED_METHODS
)

async def test_fuzz():
    results = []
    
    # Ensure config has at least one allowed doctype for the next tests
    allowed_doc = list(ALLOWED_DOCTYPES)[0] if ALLOWED_DOCTYPES else "Customer"
    
    print(f"Starting dynamic fuzz tests on MCP Server tools...")
    print("-" * 50)

    # 1. Test massive doctype string (10MB) to check for buffer overflows or unhandled OOM logic
    print("Test 1: Massive string payload (10MB)...")
    massive_str = "A" * 10_000_000
    try:
        res = await erpnext_get_doc(massive_str, "Test")
        # Should cleanly return an access denied error without crashing
        passed = "Access to DocType" in res
        results.append(("Massive DocType String rejection", passed))
    except Exception as e:
        results.append(("Massive DocType String rejection", False))

    # 2. Test malformed JSON for create_doc
    print("Test 2: Malformed JSON parsing...")
    try:
        res = await erpnext_create_doc(allowed_doc, "{this is definitely not json: 'test', }")
        passed = "Error: doc_data must be a valid JSON string" in res
        results.append(("Malformed JSON payload handled", passed))
    except Exception as e:
        results.append(("Malformed JSON payload handled", False))
        
    # 3. Test wrong data types for filters (Passing int instead of list)
    print("Test 3: Unexpected data types for filters...")
    try:
        # Pydantic usually handles this at the FastMCP layer, but we are calling the python function directly.
        # If it hits the client, it will stringify or crash the json.dumps. 
        # But we don't have credentials set, so it should hit the Missing Credentials error cleanly.
        res = await erpnext_get_list(allowed_doc, filters=12345)
        passed = res.startswith("Error:") # Any controlled string error is a pass
        results.append(("Invalid Data Types (int instead of list)", passed))
    except Exception as e:
        results.append(("Invalid Data Types (int instead of list)", False))

    # 4. Test method spoofing
    print("Test 4: Method spoofing (calling disallowed internal Frappe method)...")
    try:
        res = await erpnext_call_method("frappe.auth.get_logged_user")
        passed = "Access to method" in res and "denied" in res
        results.append(("Method Spoofing rejection", passed))
    except Exception as e:
        results.append(("Method Spoofing rejection", False))

    print("-" * 50)
    print("RESULTS:")
    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} | {name}")

if __name__ == "__main__":
    asyncio.run(test_fuzz())

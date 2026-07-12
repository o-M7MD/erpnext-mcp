import asyncio
import os
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

async def test_remote_mcp():
    url = "https://mcp.extrotechs.com/sse"
    token = "EXTROTECHS_MCP_SECRET_TOKEN_2026_x"
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"Connecting to {url}...")
    
    try:
        async with sse_client(url, headers=headers) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                print("\n✅ Successfully connected to remote MCP Server!")
                
                tools = await session.list_tools()
                print(f"\nAvailable Tools ({len(tools.tools)}):")
                for tool in tools.tools:
                    print(f" - {tool.name}: {tool.description}")
                    
                print("\nTesting frappe.ping...")
                result = await session.call_tool("call_method", arguments={"method": "frappe.ping"})
                print(f"Result: {result.content}")
                
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_remote_mcp())

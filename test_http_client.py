import asyncio
import aiohttp
import json
from typing import Dict, Any

class MCPHTTPClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send a message via streamable HTTP"""
        async with self.session.post(
            f"{self.base_url}/mcp/stream",
            json=message,
            headers={"Content-Type": "application/json"}
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"HTTP {response.status}: {await response.text()}")
    
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities"""
        async with self.session.get(f"{self.base_url}/mcp/capabilities") as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"HTTP {response.status}: {await response.text()}")

async def test_http_client():
    """Test the HTTP MCP client"""
    print("🚀 Testing MCP Streamable HTTP Client")
    print("=" * 50)
    
    async with MCPHTTPClient() as client:
        try:
            # Test 0: Get capabilities
            print("\n0. Testing capabilities...")
            capabilities = await client.get_capabilities()
            print(f"Capabilities: {json.dumps(capabilities, indent=2)}")
            
            # Test 1: Initialize
            print("\n1. Testing initialize...")
            init_message = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "Test HTTP Client",
                        "version": "1.0.0"
                    }
                }
            }
            
            response = await client.send_message(init_message)
            print(f"Response: {json.dumps(response, indent=2)}")
            
            # Test 2: List tools
            print("\n2. Testing tools/list...")
            tools_message = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }
            
            response = await client.send_message(tools_message)
            print(f"Response: {json.dumps(response, indent=2)}")
              # Test 3: Call get_alerts tool
            print("\n3. Testing get_alerts tool...")
            alerts_message = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "get_alerts",
                    "arguments": {
                        "state": "CA"
                    }
                }
            }
            
            response = await client.send_message(alerts_message)
            print(f"Response: {json.dumps(response, indent=2)}")
            
            # Test 4: Get forecast for San Francisco
            print("\n4. Testing get_forecast tool...")
            forecast_message = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "get_forecast",
                    "arguments": {
                        "latitude": 37.7749,
                        "longitude": -122.4194
                    }
                }
            }
            
            response = await client.send_message(forecast_message)
            print(f"Response: {json.dumps(response, indent=2)}")
            
            # Test 5: List resources
            print("\n5. Testing resources/list...")
            resources_message = {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "resources/list"
            }
            
            response = await client.send_message(resources_message)
            print(f"Response: {json.dumps(response, indent=2)}")
            
            # Test 6: Read resource
            print("\n6. Testing resources/read...")
            read_message = {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "resources/read",
                "params": {
                    "uri": "mcp://server/sample"
                }
            }
            
            response = await client.send_message(read_message)
            print(f"Response: {json.dumps(response, indent=2)}")
            
            print("\n✅ All HTTP tests completed!")
            
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_http_client())

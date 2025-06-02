from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Any, Dict, Optional
import logging
import asyncio
from contextlib import asynccontextmanager
import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Weather API Constants
NWS_API_BASE = "https://api.weather.gov"
USER_AGENT = "weather-app/1.0"

# Pydantic Models
class Tool(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any]

class Resource(BaseModel):
    uri: str
    name: str
    description: Optional[str] = None
    mimeType: Optional[str] = None

# Weather API Helper Functions
async def make_nws_request(url: str) -> Optional[Dict[str, Any]]:
    """Make a request to the NWS API with proper error handling."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/geo+json"
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"NWS API request failed: {e}")
            return None

def format_alert(feature: Dict[str, Any]) -> str:
    """Format an alert feature into a readable string."""
    props = feature["properties"]
    return f"""
Event: {props.get('event', 'Unknown')}
Area: {props.get('areaDesc', 'Unknown')}
Severity: {props.get('severity', 'Unknown')}
Description: {props.get('description', 'No description available')}
Instructions: {props.get('instruction', 'No specific instructions provided')}
"""

# MCP Server Class
class MCPServer:
    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self.resources: Dict[str, Resource] = {}
        self.initialize_tools()
        self.initialize_resources()
    
    def initialize_tools(self):
        """Initialize available tools"""
        # Weather alerts tool
        alerts_tool = Tool(
            name="get_alerts",
            description="Get weather alerts for a US state",
            inputSchema={
                "type": "object",
                "properties": {
                    "state": {
                        "type": "string",
                        "description": "Two-letter US state code (e.g. CA, NY)"
                    }
                },
                "required": ["state"]
            }
        )
        self.tools["get_alerts"] = alerts_tool
        
        # Weather forecast tool
        forecast_tool = Tool(
            name="get_forecast",
            description="Get weather forecast for a location",
            inputSchema={
                "type": "object",
                "properties": {
                    "latitude": {
                        "type": "number",
                        "description": "Latitude of the location"
                    },
                    "longitude": {
                        "type": "number",
                        "description": "Longitude of the location"
                    }
                },
                "required": ["latitude", "longitude"]
            }
        )
        self.tools["get_forecast"] = forecast_tool
    
    def initialize_resources(self):
        """Initialize available resources"""
        # Example resource
        sample_resource = Resource(
            uri="mcp://server/sample",
            name="Sample Resource",
            description="A sample resource for demonstration",
            mimeType="text/plain"
        )
        self.resources["sample"] = sample_resource
    
    async def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialize request"""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {
                    "listChanged": True
                },
                "resources": {
                    "subscribe": True,
                    "listChanged": True
                }
            },
            "serverInfo": {
                "name": "FastAPI MCP Server",
                "version": "1.0.0"
            }
        }
    
    async def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/list request"""
        tools_list = [tool.dict() for tool in self.tools.values()]
        return {"tools": tools_list}
    
    async def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if tool_name not in self.tools:
            raise HTTPException(status_code=400, detail=f"Tool '{tool_name}' not found")
        
        if tool_name == "get_alerts":
            state = arguments.get("state", "")
            if not state:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "Error: State code is required"
                        }
                    ]
                }
            
            url = f"{NWS_API_BASE}/alerts/active/area/{state.upper()}"
            data = await make_nws_request(url)
            
            if not data or "features" not in data:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "Unable to fetch alerts or no alerts found."
                        }
                    ]
                }
            
            if not data["features"]:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "No active alerts for this state."
                        }
                    ]
                }
            
            alerts = [format_alert(feature) for feature in data["features"]]
            result_text = "\n---\n".join(alerts)
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": result_text
                    }
                ]
            }
            
        elif tool_name == "get_forecast":
            latitude = arguments.get("latitude")
            longitude = arguments.get("longitude")
            
            if latitude is None or longitude is None:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "Error: Both latitude and longitude are required"
                        }
                    ]
                }
            
            # First get the forecast grid endpoint
            points_url = f"{NWS_API_BASE}/points/{latitude},{longitude}"
            points_data = await make_nws_request(points_url)
            
            if not points_data:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "Unable to fetch forecast data for this location."
                        }
                    ]
                }
            
            # Get the forecast URL from the points response
            try:
                forecast_url = points_data["properties"]["forecast"]
                forecast_data = await make_nws_request(forecast_url)
                
                if not forecast_data:
                    return {
                        "content": [
                            {
                                "type": "text",
                                "text": "Unable to fetch detailed forecast."
                            }
                        ]
                    }
                
                # Format the periods into a readable forecast
                periods = forecast_data["properties"]["periods"]
                forecasts = []
                for period in periods[:5]:  # Only show next 5 periods
                    forecast = f"""
{period['name']}:
Temperature: {period['temperature']}°{period['temperatureUnit']}
Wind: {period['windSpeed']} {period['windDirection']}
Forecast: {period['detailedForecast']}
"""
                    forecasts.append(forecast)
                
                result_text = "\n---\n".join(forecasts)
                
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text
                        }
                    ]
                }
                
            except KeyError as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error parsing forecast data: {str(e)}"
                        }
                    ]
                }
        
        return {"content": [{"type": "text", "text": "Tool executed successfully"}]}
    
    async def handle_resources_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resources/list request"""
        resources_list = [resource.dict() for resource in self.resources.values()]
        return {"resources": resources_list}
    
    async def handle_resources_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resources/read request"""
        uri = params.get("uri")
        
        if uri == "mcp://server/sample":
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": "This is a sample resource content."
                    }
                ]
            }
        
        raise HTTPException(status_code=404, detail=f"Resource '{uri}' not found")

# Initialize MCP server
mcp_server = MCPServer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting MCP FastAPI Server")
    yield
    logger.info("Shutting down MCP FastAPI Server")

# Create FastAPI app
app = FastAPI(
    title="MCP FastAPI Server",
    description="Model Context Protocol server implementation using FastAPI with weather tools",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "MCP FastAPI Server is running", "status": "healthy"}

@app.get("/tools")
async def list_tools():
    """REST endpoint to list available tools"""
    return {"tools": [tool.dict() for tool in mcp_server.tools.values()]}

@app.get("/resources")
async def list_resources():
    """REST endpoint to list available resources"""
    return {"resources": [resource.dict() for resource in mcp_server.resources.values()]}

@app.get("/test")
async def serve_test_page():
    """Serve the HTTP test page"""
    return FileResponse("test_http_web.html")

# MCP Streamable HTTP Endpoints
@app.get("/mcp/stream")
async def mcp_stream_info():
    """Information about the MCP stream endpoint"""
    return {
        "info": "MCP Streamable HTTP Transport Endpoint",
        "description": "This endpoint accepts POST requests with JSON-RPC 2.0 messages for MCP communication",
        "usage": "Use MCP Inspector or send POST requests with proper JSON-RPC payloads",
        "methods": ["POST"],
        "example_request": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
    }

@app.post("/mcp/stream")
async def mcp_stream_endpoint(request: Request):
    """Main MCP endpoint with streamable HTTP support"""
    try:
        message = await request.json()
        logger.info(f"Received MCP message: {message}")
        
        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        if method == "initialize":
            result = await mcp_server.handle_initialize(params)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result
            }
        elif method == "tools/list":
            result = await mcp_server.handle_tools_list(params)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result
            }
        elif method == "tools/call":
            result = await mcp_server.handle_tools_call(params)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result
            }
        elif method == "resources/list":
            result = await mcp_server.handle_resources_list(params)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result
            }
        elif method == "resources/read":
            result = await mcp_server.handle_resources_read(params)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found"
                }
            }
        
    except Exception as e:
        logger.error(f"MCP stream error: {e}")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id") if 'message' in locals() else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        }

@app.get("/mcp/capabilities")
async def mcp_capabilities():
    """Return MCP server capabilities"""
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True}
        },
        "serverInfo": {
            "name": "FastAPI MCP Server",
            "version": "1.0.0"
        }
    }

@app.options("/mcp/stream")
async def mcp_stream_options():
    """Handle CORS preflight for MCP stream endpoint"""
    return {
        "status": "ok",
        "methods": ["POST", "OPTIONS"],
        "headers": ["Content-Type", "Accept"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import Any, Dict, Optional
import logging
import asyncio
from contextlib import asynccontextmanager
import httpx
import os
from dotenv import load_dotenv
from auth import AuthService, get_current_user, optional_auth

# Load environment variables
load_dotenv()

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
    """Health check endpoint with authentication info"""
    return {
        "message": "MCP FastAPI Server with Azure OAuth is running",
        "status": "healthy",
        "authentication": {
            "type": "Azure OAuth 2.0",
            "login_endpoint": "/auth/login",
            "test_page": "/test-auth",
            "required_for": ["/mcp/stream", "/tools", "/resources"]
        },
        "endpoints": {
            "login": "/auth/login",
            "callback": "/auth/callback", 
            "me": "/auth/me",
            "test": "/test-auth",
            "mcp": "/mcp/stream",
            "docs": "/docs"
        }
    }

# Authentication routes
@app.get("/auth/login")
async def login():
    """Initiate Azure OAuth login"""
    auth_url = AuthService.get_authorization_url()
    return RedirectResponse(url=auth_url, status_code=302)

@app.get("/auth/url")
async def get_auth_url():
    """Get the OAuth authorization URL as JSON"""
    auth_url = AuthService.get_authorization_url()
    return {"auth_url": auth_url}

@app.get("/auth/callback")
async def auth_callback(code: str = None, error: str = None, state: str = None):
    """Handle OAuth callback from Azure"""
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth error: {error}"
        )
    
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code not provided"
        )
    
    try:
        # Exchange code for token
        token_data = await AuthService.exchange_code_for_token(code)
        access_token = token_data.get("access_token")
        
        # Get user info
        user_info = await AuthService.get_user_info(access_token)
        
        # Create JWT token
        jwt_token = AuthService.create_jwt_token(user_info)
        
        # Return success page with token
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Successful</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
                .success {{ color: green; }}
                .token {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; word-break: break-all; }}
                .user-info {{ background: #e8f4fd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1 class="success">✅ Authentication Successful!</h1>
            <div class="user-info">
                <h3>Welcome, {user_info.get('displayName', 'User')}!</h3>
                <p><strong>Email:</strong> {user_info.get('mail') or user_info.get('userPrincipalName', 'N/A')}</p>
                <p><strong>ID:</strong> {user_info.get('id', 'N/A')}</p>
            </div>
            <h3>Your JWT Token:</h3>
            <div class="token">{jwt_token}</div>
            <p><strong>Instructions:</strong></p>
            <ol>
                <li>Copy the token above</li>
                <li>Use it in the Authorization header as: <code>Bearer &lt;token&gt;</code></li>
                <li>The token expires in {os.getenv('JWT_EXPIRATION_HOURS', '24')} hours</li>
            </ol>
            <p><a href="/test-auth">Test your authentication</a> | <a href="/docs">API Documentation</a></p>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {str(e)}"
        )

@app.get("/auth/me")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {"user": current_user}

@app.get("/test-auth")
async def test_auth_page():
    """Serve a page to test authentication"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Authentication</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .container { margin: 20px 0; }
            input, button { padding: 10px; margin: 5px; }
            input[type="text"] { width: 300px; }
            .response { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; min-height: 100px; }
            .error { color: red; }
            .success { color: green; }
        </style>
    </head>
    <body>
        <h1>MCP Server Authentication Test</h1>
        
        <div class="container">
            <h3>1. Login to get token:</h3>
            <button onclick="login()">Start Azure OAuth Login</button>
        </div>
        
        <div class="container">
            <h3>2. Test authenticated endpoint:</h3>
            <input type="text" id="token" placeholder="Paste your JWT token here" />
            <button onclick="testAuth()">Test /auth/me</button>
        </div>
        
        <div class="container">
            <h3>3. Test MCP endpoint with auth:</h3>
            <button onclick="testMCPAuth()">Test MCP Tools (requires token above)</button>
        </div>
        
        <div class="container">
            <h3>Response:</h3>
            <div id="response" class="response">Click a button to test...</div>
        </div>
          <script>
            function login() {
                fetch('/auth/url')
                    .then(response => response.json())
                    .then(data => {
                        if (data.auth_url) {
                            window.open(data.auth_url, '_blank');
                            document.getElementById('response').innerHTML = '<span class="success">✅ Login window opened. Complete the login and copy your token.</span>';
                        }
                    })
                    .catch(error => {
                        document.getElementById('response').innerHTML = '<span class="error">❌ Error: ' + error + '</span>';
                    });
            }
            
            function testAuth() {
                const token = document.getElementById('token').value;
                if (!token) {
                    document.getElementById('response').innerHTML = '<span class="error">❌ Please enter a token first</span>';
                    return;
                }
                
                fetch('/auth/me', {
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('response').innerHTML = '<span class="success">✅ Success!</span><br><pre>' + JSON.stringify(data, null, 2) + '</pre>';
                })
                .catch(error => {
                    document.getElementById('response').innerHTML = '<span class="error">❌ Error: ' + error + '</span>';
                });
            }
            
            function testMCPAuth() {
                const token = document.getElementById('token').value;
                if (!token) {
                    document.getElementById('response').innerHTML = '<span class="error">❌ Please enter a token first</span>';
                    return;
                }
                
                fetch('/mcp/stream', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {}
                    })
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('response').innerHTML = '<span class="success">✅ MCP Tools List Success!</span><br><pre>' + JSON.stringify(data, null, 2) + '</pre>';
                })
                .catch(error => {
                    document.getElementById('response').innerHTML = '<span class="error">❌ Error: ' + error + '</span>';
                });
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# Update existing endpoints to require authentication
@app.get("/tools")
async def list_tools(current_user: Dict[str, Any] = Depends(get_current_user)):
    """REST endpoint to list available tools (requires authentication)"""
    logger.info(f"User {current_user.get('email')} requested tools list")
    return {"tools": [tool.dict() for tool in mcp_server.tools.values()]}

@app.get("/resources")
async def list_resources(current_user: Dict[str, Any] = Depends(get_current_user)):
    """REST endpoint to list available resources (requires authentication)"""
    logger.info(f"User {current_user.get('email')} requested resources list")
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
async def mcp_stream_endpoint(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Main MCP endpoint with streamable HTTP support (requires authentication)"""
    try:
        message = await request.json()
        logger.info(f"User {current_user.get('email')} sent MCP message: {message}")
        
        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        if method == "initialize":
            result = await mcp_server.handle_initialize(params)
            # Add user info to initialization response
            result["userInfo"] = {
                "email": current_user.get("email"),
                "name": current_user.get("name"),
                "authenticated": True
            }
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

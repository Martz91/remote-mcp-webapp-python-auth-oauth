from fastapi import FastAPI, HTTPException, Request, Depends, status, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import Any, Dict, Optional
import logging
import asyncio
from contextlib import asynccontextmanager
import httpx
import os
from urllib.parse import parse_qs
from dotenv import load_dotenv
from mcp_auth import (
    MCPAuthService, 
    AuthorizationServerMetadata,
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    TokenRequest,
    TokenResponse,
    MCP_PROTOCOL_VERSION,
    get_current_user,
    optional_auth
)
from graph_client import GraphClient

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

# Weather Tool Implementation Functions
async def get_forecast(latitude: float, longitude: float) -> str:
    """Get weather forecast for given coordinates using NWS API."""
    try:
        # Get grid point
        points_url = f"https://api.weather.gov/points/{latitude},{longitude}"
        points_data = await make_nws_request(points_url)
        
        if not points_data:
            return "Unable to get grid point data from NWS"
        
        # Get forecast URL
        forecast_url = points_data["properties"]["forecast"]
        forecast_data = await make_nws_request(forecast_url)
        
        if not forecast_data:
            return "Unable to get forecast data from NWS"
        
        # Format the forecast
        periods = forecast_data["properties"]["periods"][:5]  # Next 5 periods
        forecast_text = "Weather Forecast:\n\n"
        
        for period in periods:
            forecast_text += f"{period['name']}: {period['detailedForecast']}\n\n"
        
        return forecast_text
        
    except Exception as e:
        logger.error(f"Error getting forecast: {e}")
        return f"Error getting forecast: {str(e)}"

async def get_alerts(state: str) -> str:
    """Get weather alerts for a US state using NWS API."""
    try:
        alerts_url = f"https://api.weather.gov/alerts/active?area={state.upper()}"
        alerts_data = await make_nws_request(alerts_url)
        
        if not alerts_data:
            return f"Unable to get alerts data for {state.upper()}"
        
        features = alerts_data.get("features", [])
        
        if not features:
            return f"No active weather alerts for {state.upper()}"
        
        alerts_text = f"Active Weather Alerts for {state.upper()}:\n\n"
        
        for feature in features[:10]:  # Limit to 10 alerts
            alerts_text += format_alert(feature)
            alerts_text += "\n" + "="*50 + "\n\n"
        
        return alerts_text
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return f"Error getting alerts for {state}: {str(e)}"
    
async def search_files(query: str, access_token: str) -> str:
    """Search for files in SharePoint Online using MS Graph API."""
    payload = {
        "requests": [
            {
                "entityTypes": ["driveItem"],
                "query": {"queryString": query},
                "from": 0,
                "size": 25
            }
        ]
    }

    try:
        import json
        #token_detail = json.loads(access_token)
        token = access_token["access_token"]
        response = await graph_client.post("/search/query", json=payload, access_token=token)
        response.raise_for_status()
        data = response.json()

        hits = (
            data.get("value", [])
            and data["value"][0].get("hitsContainers", [])
            and data["value"][0]["hitsContainers"][0].get("hits", [])
        )

        if not hits:
            return f"No files found for query '{query}'."

        results = []
        for hit in hits:
            resource = hit.get("resource", {})
            name = resource.get("name", "Unknown")
            path = resource.get("webUrl", "No URL")
            results.append(f"Name: {name}\nURL: {path}\n")

        return "Search results:\n\n" + "\n".join(results)

    except httpx.HTTPStatusError as e:
        logger.error(f"Graph search failed: {e.response.text}")
        return f"Graph API returned {e.response.status_code}: {e.response.text}"
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return f"Error searching files: {str(e)}"

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


        # SharePoint search tool
        forecast_tool = Tool(
            name="search_files",
            description="Search files in SharePoint Online.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query to search in SharePoint."
                    }
                },
                "required": ["query"]
            }
        )
        self.tools["search_files"] = forecast_tool
    
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
    
    async def handle_tools_call(self, params: Dict[str, Any], access_token: str) -> Dict[str, Any]:
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
            
        elif tool_name == "search_files":
            query = arguments.get("query")
            if not query:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "Error: Query string is required"
                        }
                    ]
                }
            
            result_text = await search_files(query, access_token)
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

# Initialize MCP-compliant OAuth service
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
mcp_auth = MCPAuthService(BASE_URL)
graph_client = GraphClient(mcp_auth)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MCP Authorization Specification Endpoints (OAuth 2.1)

@app.get("/.well-known/oauth-authorization-server", response_model=AuthorizationServerMetadata)
async def get_authorization_server_metadata(request: Request):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
    # Check for MCP Protocol Version header
    mcp_version = request.headers.get("MCP-Protocol-Version")
    if mcp_version:
        logger.info(f"MCP Protocol Version: {mcp_version}")
    
    return mcp_auth.get_metadata()

@app.post("/register", response_model=ClientRegistrationResponse, status_code=201)
async def register_client(request: ClientRegistrationRequest):
    """Dynamic Client Registration (RFC 7591)"""
    try:
        return mcp_auth.register_client(request)
    except Exception as e:
        logger.error(f"Client registration failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    state: Optional[str] = None,
    scope: Optional[str] = None
):
    """OAuth 2.1 Authorization Endpoint"""
    
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
    if code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="Unsupported code_challenge_method")
    
    try:
        # Create authorization URL that redirects to Azure for third-party auth
        auth_url = await mcp_auth.create_authorization_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            state=state,
            scope=scope
        )
        
        # Redirect user to Azure OAuth
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error(f"Authorization failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/auth/azure/callback")
async def azure_callback(request: Request):
    """Handle Azure OAuth callback (third-party authorization)"""
    # try:
    # Get query parameters manually to handle optional state
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")
    
    logger.info(f"Azure callback received - code: {code[:20] if code else 'None'}..., state: {state[:20] if state else 'None'}...")
    logger.info(f"All query params: {dict(request.query_params)}")
    
    # Handle OAuth error responses
    if error:
        logger.error(f"Azure OAuth error: {error} - {error_description}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "oauth_error",
                "detail": f"Azure OAuth error: {error}",
                "error_description": error_description
            }
        )
    
    # Check for required code parameter
    if not code:
        logger.error("Azure callback missing code parameter")
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_code_parameter",
                "detail": "Authorization code is required for OAuth callback"
            }
        )
    
    # Handle case where state might be missing
    if not state:
        logger.error("Azure callback missing state parameter")
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_state_parameter",
                "detail": "State parameter is required for OAuth callback",
                "code_preview": code[:20] + "..." if code else None
            }
        )
    
    # Process Azure callback and redirect to original client
    redirect_url = await mcp_auth.handle_azure_callback(code, state)
    logger.info(f"Redirecting to: {redirect_url}")
    return RedirectResponse(url=redirect_url)
        
    # except Exception as e:
    #     logger.error(f"Azure callback failed: {e}")
    #     # Return more detailed error for debugging
    #     return JSONResponse(
    #         status_code=400,
    #         content={
    #             "error": "azure_callback_failed",
    #             "detail": str(e),
    #             "state": state,
    #             "code_preview": code[:20] + "..." if code else None
    #         }
    #     )

@app.post("/token", response_model=TokenResponse)
async def token_endpoint(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None)
):
    """OAuth 2.1 Token Endpoint"""
    
    request = TokenRequest(
        grant_type=grant_type,
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=code_verifier,
        refresh_token=refresh_token
    )
    
    try:
        return await mcp_auth.exchange_code_for_token(request)
    except Exception as e:
        logger.error(f"Token exchange failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

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
        }    }

@app.get("/test-auth")
async def test_auth_page():
    """Serve the new MCP OAuth 2.1 test interface"""
    return FileResponse("mcp_oauth_test.html")

@app.get("/auth/me")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {"user": current_user}

# Test client callback endpoint (for testing OAuth flow)
@app.get("/client-callback")
async def client_callback(request: Request):
    """Test client callback endpoint to receive authorization codes"""
    code = request.query_params.get("code")
    state = request.query_params.get("state") 
    error = request.query_params.get("error")
    
    logger.info(f"Client callback received - code: {code[:20] if code else 'None'}..., state: {state[:20] if state else 'None'}...")
    
    # Create a simple HTML response showing the results
    if error:
        html_content = f"""
        <html>
        <head><title>OAuth Error</title></head>
        <body>
            <h1>OAuth Authorization Error</h1>
            <p><strong>Error:</strong> {error}</p>
            <p><strong>State:</strong> {state}</p>
            <a href="/mcp_oauth_test.html">Try Again</a>
        </body>
        </html>
        """
    else:
        html_content = f"""
        <html>
        <head><title>OAuth Success</title></head>
        <body>
            <h1>OAuth Authorization Successful!</h1>
            <p><strong>Authorization Code:</strong> {code}</p>
            <p><strong>State:</strong> {state}</p>
            <p>You can now exchange this authorization code for an access token.</p>
            <a href="/mcp_oauth_test.html">Start New Flow</a>
        </body>
        </html>
        """
    
    return HTMLResponse(content=html_content)

# MCP Tool Endpoints (require authentication)
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
        # Check for MCP Protocol Version header
        mcp_version = request.headers.get("MCP-Protocol-Version")
        if mcp_version and mcp_version != MCP_PROTOCOL_VERSION:
            logger.warning(f"Client using MCP version {mcp_version}, server supports {MCP_PROTOCOL_VERSION}")
        
        message = await request.json()
        logger.info(f"User {current_user.get('email')} sent MCP message: {message}")

        logger.info(f"------------------ User token data: {current_user.get('azure_token')}")
        logger.info(f"------------------ User client id: {current_user.get('azp')} and sub: {current_user.get('sub')} ")
        
        ################################################ now just get the token and pass it to the tool function
        # composite_key = f"{current_user.get('azp')}-{current_user.get('sub')}"
        access_token = await mcp_auth.get_access_token(current_user.get('azp'), current_user.get('sub'))

        logger.info(f"------------------ Access token: {access_token}")

        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        if method == "initialize":
            result = await mcp_server.handle_initialize(params)
            # Add user info and protocol version to initialization response
            result["userInfo"] = {
                "email": current_user.get("email"),
                "name": current_user.get("name"),
                "authenticated": True
            }
            result["serverInfo"]["protocolVersion"] = MCP_PROTOCOL_VERSION
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
            result = await mcp_server.handle_tools_call(params, access_token)
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

# Individual MCP Tool Endpoints (for direct testing)
@app.post("/mcp/get_forecast")
async def get_forecast_endpoint(
    request: Request,
    data: dict = Body(...)
):
    """Direct endpoint for weather forecast tool"""
    # Check for MCP protocol version
    protocol_version = request.headers.get("MCP-Protocol-Version")
    if protocol_version:
        logger.info(f"MCP Protocol Version: {protocol_version}")
    
    # Require authentication
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )
    
    try:
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        
        if latitude is None or longitude is None:
            raise HTTPException(
                status_code=400,
                detail="latitude and longitude are required"
            )
        
        # Call the weather forecast function
        forecast_result = await get_forecast(latitude, longitude)
        return {"result": forecast_result}
        
    except Exception as e:
        logger.error(f"Error in get_forecast: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mcp/get_alerts")
async def get_alerts_endpoint(
    request: Request,
    data: dict = Body(...)
):
    """Direct endpoint for weather alerts tool"""
    # Check for MCP protocol version
    protocol_version = request.headers.get("MCP-Protocol-Version")
    if protocol_version:
        logger.info(f"MCP Protocol Version: {protocol_version}")
    
    # Require authentication
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )
    
    try:
        state = data.get("state")
        
        if not state:
            raise HTTPException(
                status_code=400,
                detail="state is required"
            )
        
        # Call the weather alerts function
        alerts_result = await get_alerts(state)
        return {"result": alerts_result}
        
    except Exception as e:
        logger.error(f"Error in get_alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/mcp/search_files")
async def search_files_endpoint(
    request: Request,
    data: dict = Body(...)
):
    logger.info("Tool search_files called.")
    """Direct endpoint for file search tool"""
    # Check for MCP protocol version
    protocol_version = request.headers.get("MCP-Protocol-Version")
    if protocol_version:
        logger.info(f"MCP Protocol Version: {protocol_version}")
    
    # Require authentication
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )
    
    try:
        query = data.get("query")
        
        if not query:
            raise HTTPException(
                status_code=400,
                detail="query is required"
            )
        
        # Call the search files function
        search_result = await search_files(query)
        return {"result": search_result}
        
    except Exception as e:
        logger.error(f"Error in get_alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

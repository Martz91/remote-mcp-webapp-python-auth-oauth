# Python MCP Weather Server with OAuth 2.1 Authentication

A production-ready Model Context Protocol (MCP) server built with FastAPI that provides weather information using the National Weather Service API. Features **full MCP OAuth 2.1 compliance** with PKCE, dynamic client registration, and Azure AD integration. Ready for deployment to Azure App Service with Azure Developer CLI (azd).

## 🌟 Features

- **MCP OAuth 2.1 Specification Compliant**: Complete implementation of MCP Authorization Specification (2025-03-26)
- **PKCE Required**: Secure authorization with Proof Key for Code Exchange (RFC 7636, S256 method)
- **Dynamic Client Registration**: Automatic client registration per RFC 7591
- **Authorization Server Metadata**: Discovery endpoint per RFC 8414
- **Third-Party Authorization**: Uses Azure AD as authorization server
- **MCP Protocol Headers**: Full support for `MCP-Protocol-Version: 2025-03-26`
- **JWT Token Management**: Secure token-based authentication
- **Weather Tools**:
  - `get_alerts`: Get weather alerts for any US state
  - `get_forecast`: Get detailed weather forecast for any location
- **Azure Ready**: Pre-configured for Azure App Service deployment
- **Web Test Interface**: Built-in OAuth 2.1 flow testing

## 🔐 MCP Authorization Implementation

This server implements the complete [MCP Authorization Specification (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization):

### OAuth 2.1 Endpoints
- `GET /.well-known/oauth-authorization-server` - Authorization server metadata (RFC 8414)
- `POST /register` - Dynamic client registration (RFC 7591) 
- `GET /authorize` - Authorization endpoint with PKCE (RFC 7636)
- `POST /token` - Token endpoint for code exchange and refresh
- `GET /auth/azure/callback` - Third-party authorization callback

### MCP Protocol Features  
- ✅ **Protocol Version Headers**: `MCP-Protocol-Version: 2025-03-26`
- ✅ **PKCE Required**: All clients must use S256 method
- ✅ **Dynamic Registration**: Automatic client onboarding
- ✅ **JWT Authentication**: Bearer token validation on MCP endpoints
- ✅ **Proper Error Handling**: 401/403/400 responses with details
- ✅ **Azure AD Integration**: Enterprise-grade authorization server

**⚠️ Important**: Complete OAuth setup required before use. See [AUTH_SETUP.md](AUTH_SETUP.md) for Azure AD configuration instructions.

## 💻 Local Development

### Prerequisites

- Python 3.8+
- Azure account with completed OAuth setup (see [AUTH_SETUP.md](AUTH_SETUP.md))

### Setup & Run

1. **Complete OAuth setup first**:
   Follow the instructions in [AUTH_SETUP.md](AUTH_SETUP.md) to create your Azure App Registration.

2. **Clone and install dependencies**:
   ```bash
   git clone <your-repo-url>
   cd remote-mcp-webapp-python-auth-oauth
   python -m venv venv
   .\venv\Scripts\Activate.ps1  # Windows
   # source venv/bin/activate   # macOS/Linux
   pip install -r requirements.txt
   ```

3. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your Azure OAuth credentials from AUTH_SETUP.md
   ```

4. **Start the development server**:
   ```bash
   .\start_server.ps1  # Windows
   # or manually:
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

5. **Access the server**:
   - Server: http://localhost:8000/
   - Health Check: http://localhost:8000/health
   - **OAuth 2.1 Test Interface**: http://localhost:8000/mcp_oauth_test.html
   - API Docs: http://localhost:8000/docs

## 🔌 Connect to the Local MCP Server

### Authentication Required

Before connecting any MCP client, you must authenticate:

1. **Get JWT Token**: Visit http://localhost:8000/mcp_oauth_test.html
2. **Complete OAuth Flow**: Use the built-in OAuth 2.1 test interface
3. **Copy JWT Token**: Use the token in your MCP client configuration

### Using MCP Inspector

1. **In a new terminal window, install and run MCP Inspector**:
   ```bash
   npx @modelcontextprotocol/inspector
   ```

2. **CTRL+click the URL** displayed by the app (e.g. http://localhost:5173/#resources)

3. **Configure authenticated connection**:
   - Set transport type to `HTTP`
   - Set URL to: `http://localhost:8000/`
   - **Add Authorization header**: `Bearer <your-jwt-token>`
   
   > 💡 **Getting your JWT token**: Visit http://localhost:8000/mcp_oauth_test.html to complete the OAuth 2.1 flow and obtain your JWT token.

4. **Test the connection**: List Tools, click on a tool, and Run Tool

### Configuration for MCP Clients

```json
{
  "mcpServers": {
    "weather-mcp-server-local": {
      "transport": {
        "type": "http",
        "url": "http://localhost:8000/",
        "headers": {
          "Authorization": "Bearer <your-jwt-token>"
        }
      },
      "name": "Weather MCP Server (Local with Auth)",
      "description": "Authenticated MCP Server with weather tools"
    }
  }
}
```   > 💡 **Replace `<your-jwt-token>`** with the actual JWT token obtained from the OAuth 2.1 flow at `/mcp_oauth_test.html`.

## 🚀 Quick Deploy to Azure

### Prerequisites

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Azure Developer CLI (azd)](https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd)
- Active Azure subscription
- **Completed OAuth setup** (see [AUTH_SETUP.md](AUTH_SETUP.md))

### Deploy in 5 Commands

```bash
# 1. Login to Azure
azd auth login

# 2. Initialize the project  
azd init

# 3. Set OAuth environment variables (from your AUTH_SETUP.md)
azd env set AZURE_CLIENT_ID "your-client-id"
azd env set AZURE_TENANT_ID "your-tenant-id"
azd env set AZURE_CLIENT_SECRET "your-client-secret"
azd env set JWT_SECRET_KEY "your-secure-jwt-secret"

# 4. Deploy to Azure (first time to get the URL)
azd up

# 5. Update environment with deployed URL and redeploy
azd env set BASE_URL "https://app-web-[unique-id].azurewebsites.net"
azd env set AZURE_REDIRECT_URI "https://app-web-[unique-id].azurewebsites.net/auth/azure/callback"
azd env set ENVIRONMENT "production"
azd up
```

### Post-Deployment Setup

**⚠️ Critical**: After deployment, you must update your Azure App Registration:

1. Note your deployed URL: `https://app-web-[unique-id].azurewebsites.net/`
2. Go to Azure Portal → Microsoft Entra ID → App registrations → Your App
3. Click **Authentication** → Add redirect URI:
   `https://app-web-[unique-id].azurewebsites.net/auth/azure/callback`
4. Click **Save**

> 💡 **Note**: The redirect URI must be `/auth/azure/callback` (not `/auth/callback`) for the MCP OAuth 2.1 flow to work correctly.

### Test Your Deployment

After deployment, your authenticated MCP server will be available at:
- **OAuth 2.1 Test Interface**: `https://<your-app>.azurewebsites.net/mcp_oauth_test.html`
- **Health Check**: `https://<your-app>.azurewebsites.net/health`
- **MCP Capabilities**: `https://<your-app>.azurewebsites.net/mcp/capabilities`
- **API Docs**: `https://<your-app>.azurewebsites.net/docs`

## 🔌 Connect to the Remote MCP Server

Follow the same guidance as the local setup, but use your Azure App Service URL and ensure you have a valid JWT token from the deployed authentication endpoint.

**Configuration for deployed server**:
```json
{
  "mcpServers": {
    "weather-mcp-server-azure": {
      "transport": {
        "type": "http", 
        "url": "https://<your-app>.azurewebsites.net/",
        "headers": {
          "Authorization": "Bearer <your-jwt-token>"
        }
      },
      "name": "Weather MCP Server (Azure with Auth)",
      "description": "Authenticated MCP Server hosted on Azure"
    }
  }
}
```

## 🧪 Testing

### Interactive OAuth 2.1 Testing
- **Local**: Visit http://localhost:8000/mcp_oauth_test.html
- **Azure**: Visit `https://<your-app>.azurewebsites.net/mcp_oauth_test.html`

The test interface provides:
1. **Complete OAuth 2.1 Flow**: Dynamic client registration → Authorization → Token exchange
2. **PKCE Validation**: Test the full Proof Key for Code Exchange flow
3. **MCP Endpoint Testing**: Test authenticated weather tools
4. **JWT Token Display**: View and validate your authentication tokens
5. **Client Callback Testing**: Includes `/client-callback` endpoint for OAuth flow validation

### OAuth Flow Architecture
The server implements a complete OAuth 2.1 flow:
- **Client Registration**: Dynamic client registration with auto-generated credentials
- **Authorization**: User redirected to Azure AD for authentication
- **Azure Callback**: Server receives Azure auth code at `/auth/azure/callback`
- **Client Callback**: Server redirects to client's callback (e.g., `/client-callback`) with authorization code
- **Token Exchange**: Client exchanges authorization code for JWT access token

### MCP Client Testing
Test with any MCP-compatible client using the authenticated endpoints and your JWT token.

## 🌦️ Data Source

This server uses the National Weather Service (NWS) API:
- Real-time weather alerts and warnings
- Detailed weather forecasts  
- Official US government weather data
- No API key required
- High reliability and accuracy

## 🔒 Security Features

- ✅ **OAuth 2.1 Compliance**: Full MCP Authorization Specification implementation
- ✅ **PKCE Required**: S256 method for all authorization flows
- ✅ **Dynamic Client Registration**: Secure automatic client onboarding
- ✅ **Azure AD Integration**: Enterprise-grade authorization server
- ✅ **JWT Token Security**: Configurable expiration and secure validation
- ✅ **Protocol Version Enforcement**: MCP-Protocol-Version header validation
- ✅ **Request Logging**: Full audit trail with user identification
- ✅ **CORS Protection**: Proper cross-origin resource sharing policies
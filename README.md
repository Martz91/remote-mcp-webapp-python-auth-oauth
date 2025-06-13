# Python MCP Weather Server with Azure OAuth Authentication

A Model Context Protocol (MCP) server built with FastAPI and Python that provides weather information using the National Weather Service API. Features Azure OAuth 2.0 authentication and is ready for deployment to Azure App Service with Azure Developer CLI (azd).

## 🌟 Features

- **FastAPI Framework**: Modern, fast web framework for building APIs
- **Azure OAuth 2.0 Authentication**: Secure authentication using Microsoft Entra ID
- **MCP Protocol Compliance**: Full support for JSON-RPC 2.0 MCP protocol  
- **HTTP Transport**: HTTP-based communication for web connectivity
- **JWT Token Management**: Secure token-based authentication and authorization
- **Weather Tools**:
  - `get_alerts`: Get weather alerts for any US state
  - `get_forecast`: Get detailed weather forecast for any location
- **Azure Ready**: Pre-configured for Azure App Service deployment
- **Web Test Interface**: Built-in HTML interface for testing authentication and tools
- **National Weather Service API**: Real-time weather data from official US government source

## 🔐 Authentication

This server requires Azure OAuth 2.0 authentication. All MCP endpoints are protected and require a valid JWT token.

**⚠️ Important**: Before running locally or deploying, you must complete the OAuth setup. See [AUTH_SETUP.md](AUTH_SETUP.md) for detailed instructions on:
- Creating an Azure App Registration
- Configuring client secrets and permissions
- Setting up redirect URIs for both local and production environments

## 💻 Local Development

### Prerequisites

- Python 3.8+
- pip (Python package installer)
- Azure account (for OAuth setup)
- **Completed OAuth setup** (see [AUTH_SETUP.md](AUTH_SETUP.md))

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
   - **Authentication Test**: http://localhost:8000/test-auth
   - API Docs: http://localhost:8000/docs

## 🔌 Connect to the Local MCP Server

### Authentication Required

Before connecting any MCP client, you must authenticate:

1. **Get JWT Token**: Visit http://localhost:8000/test-auth
2. **Login with Microsoft**: Complete the OAuth flow
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
```

## 🚀 Quick Deploy to Azure

### Prerequisites

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Azure Developer CLI (azd)](https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd)
- Active Azure subscription
- **Completed OAuth setup** (see [AUTH_SETUP.md](AUTH_SETUP.md))

### Deploy in 4 Commands

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

# 4. Deploy to Azure
azd up
```

### Post-Deployment Setup

**⚠️ Critical**: After deployment, you must update your Azure App Registration:

1. Note your deployed URL: `https://app-web-[unique-id].azurewebsites.net/`
2. Go to Azure Portal → Microsoft Entra ID → App registrations → Your App
3. Click **Authentication** → Add redirect URI:
   `https://app-web-[unique-id].azurewebsites.net/auth/callback`
4. Click **Save**

### Test Your Deployment

After deployment, your authenticated MCP server will be available at:
- **Authentication Test**: `https://<your-app>.azurewebsites.net/test-auth`
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

- **Local**: Visit http://localhost:8000/test-auth for an interactive authentication and testing interface
- **Azure**: Visit `https://<your-app>.azurewebsites.net/test-auth` for your deployed instance

The test interface allows you to:
1. Login with Microsoft OAuth
2. View your JWT token and user information  
3. Test authenticated MCP endpoints
4. Try weather tools with sample data


## 🌦️ Data Source

This server uses the National Weather Service (NWS) API:
- Real-time weather alerts and warnings
- Detailed weather forecasts  
- Official US government weather data
- No API key required
- High reliability and accuracy

## 🔒 Security Features

- ✅ Azure OAuth 2.0 integration with Microsoft Entra ID
- ✅ JWT tokens with configurable expiration (24 hours default)
- ✅ Secure token validation on all protected endpoints
- ✅ User information retrieval from Microsoft Graph API
- ✅ Request logging with user identification
- ✅ CORS protection and HTTPS enforcement
# Azure OAuth Setup for MCP Server

This guide explains how to set up Azure OAuth 2.0 authentication for your MCP (Model Context Protocol) server using Microsoft Entra ID (formerly Azure Active Directory).

## Quick Start

### 1. Set up Virtual Environment

First, create and activate a virtual environment:

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv venv
.\venv\Scripts\activate.bat
```

**macOS/Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Server

**Using the provided scripts:**
- Windows PowerShell: `.\start_server.ps1`
- Windows Command Prompt: `start_server.bat`
- Manual: `uvicorn main:app --host 0.0.0.0 --port 8000 --reload`

## Features

- ✅ Full Azure OAuth 2.0 integration
- ✅ JWT token-based authentication
- ✅ Protected MCP endpoints
- ✅ User information from Microsoft Graph API
- ✅ Interactive test interface
- ✅ Weather tools (alerts and forecasts) with authentication
- ✅ Azure App Service deployment ready
- ✅ Production-grade security

## Azure App Registration Setup

### 1. Create Azure App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** > **App registrations** > **New registration**
3. Fill in the details:
   - **Name**: Your MCP Server App (e.g., "MCP Weather Server")
   - **Supported account types**: Accounts in this organizational directory only (or your preferred option)
   - **Redirect URI**: 
     - For local development: `http://localhost:8000/auth/callback`
     - For production: `https://your-app-name.azurewebsites.net/auth/callback`
4. After creation, note down:
   - **Application (client) ID** (you'll need this)
   - **Directory (tenant) ID** (you'll need this)

### 2. Configure Client Secret

1. Go to **Certificates & secrets** > **Client secrets** > **New client secret**
2. Add a description and set expiration (recommend 24 months)
3. **Important**: Copy the client secret **value** immediately (you won't see it again!)

### 3. Set API Permissions

1. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated permissions**
2. Add these permissions:
   - `openid` (Sign users in)
   - `profile` (View users' basic profile)
   - `email` (View users' email address)
   - `User.Read` (Read user profile)
3. Click **Grant admin consent for [Your Organization]** if you have admin rights
4. If you don't have admin rights, ask your Azure admin to grant consent

### 4. Configure Redirect URIs for Both Local and Production

**Important**: For production deployment, you'll need to add both URIs:

1. Go to **Authentication** 
2. Under **Web** platform, ensure you have:
   - `http://localhost:8000/auth/callback` (for local development)
   - `https://your-deployed-app.azurewebsites.net/auth/callback` (for production)
3. Click **Save**

**Note**: After deploying to Azure, you'll get a URL like `https://app-web-xyz123.azurewebsites.net/`. You'll need to add `/auth/callback` to this URL in your Azure App Registration.

## Local Development Configuration

### 1. Environment Configuration

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your Azure app details:
   ```
   AZURE_CLIENT_ID=your-actual-client-id-from-step-1
   AZURE_CLIENT_SECRET=your-actual-client-secret-from-step-2
   AZURE_TENANT_ID=your-actual-tenant-id-from-step-1
   AZURE_REDIRECT_URI=http://localhost:8000/auth/callback
   JWT_SECRET_KEY=generate-a-secure-random-key-for-jwt-signing
   ```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Local Server

```bash
python main.py
```

Or using uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Test Local Authentication

1. Visit `http://localhost:8000/test-auth`
2. Click "Login with Microsoft"
3. Complete OAuth flow
4. Test the protected endpoints

## Production Deployment

### 1. Deploy to Azure

Follow the instructions in `DEPLOY.md` to deploy using Azure Developer CLI:

```bash
# Set environment variables for production
azd env set AZURE_CLIENT_ID "your-client-id"
azd env set AZURE_TENANT_ID "your-tenant-id" 
azd env set AZURE_CLIENT_SECRET "your-client-secret"
azd env set JWT_SECRET_KEY "your-secure-jwt-secret"

# Deploy
azd up
```

### 2. Update Azure App Registration for Production

**Critical Step**: After deployment, you must update your Azure App Registration:

1. **Get your deployed URL** from azd output (e.g., `https://app-web-xyz123.azurewebsites.net/`)
2. **Go to Azure Portal** → Microsoft Entra ID → App registrations → Your App
3. **Click Authentication** in the left sidebar
4. **Add the production redirect URI**:
   - Click "Add URI" under Web platform
   - Enter: `https://your-app-name.azurewebsites.net/auth/callback`
   - Click **Save**

Now your app registration supports both local development and production URLs.

### 3. Test Production Deployment

1. Visit your deployed app: `https://your-app-name.azurewebsites.net/test-auth`
2. Test the OAuth flow with the production instance
3. Verify MCP endpoints work with authentication

## Authentication Flow

### 1. Login
- Visit `http://localhost:8000/auth/login`
- You'll get an `auth_url` to visit
- Complete Azure OAuth login
- Get redirected back with a JWT token

### 2. Use the Token
- Include the JWT token in the `Authorization` header: `Bearer <your-jwt-token>`
- The token is valid for 24 hours (configurable)

### 3. Test Interface
- Visit `http://localhost:8000/test-auth` for an interactive test page
- Test login, token validation, and MCP endpoints

## Protected Endpoints

All the following endpoints now require authentication:

- `POST /mcp/stream` - Main MCP endpoint
- `GET /tools` - List available tools
- `GET /resources` - List available resources
- `GET /auth/me` - Get current user info

## API Endpoints

### Authentication
- `GET /auth/login` - Start OAuth flow
- `GET /auth/callback` - OAuth callback (automatic)
- `GET /auth/me` - Get current user info

### MCP Protocol
- `POST /mcp/stream` - Main MCP JSON-RPC endpoint
- `GET /mcp/capabilities` - Server capabilities
- `GET /mcp/stream` - Endpoint information

### Tools & Resources
- `GET /tools` - List available tools
- `GET /resources` - List available resources

### Testing
- `GET /test-auth` - Interactive authentication test page
- `GET /` - Server status and authentication info

## MCP Client Configuration

When connecting with an MCP client, you'll need to:

1. First authenticate via the web interface to get a JWT token
2. Include the token in your MCP client's HTTP headers:
   ```json
   {
     "Authorization": "Bearer your-jwt-token-here"
   }
   ```

## Available Tools

1. **get_alerts** - Get weather alerts for a US state
2. **get_forecast** - Get weather forecast for coordinates

## Security Features

- ✅ Azure OAuth 2.0 integration
- ✅ JWT tokens with expiration
- ✅ Secure token validation
- ✅ User information from Microsoft Graph
- ✅ Request logging with user identification
- ✅ CORS protection

## Troubleshooting

### Common Issues

1. **"Invalid client" error**
   - Check your `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`
   - Ensure the client secret hasn't expired

2. **"Redirect URI mismatch"**
   - Verify the redirect URI in Azure matches exactly: `http://localhost:8000/auth/callback`

3. **"Insufficient privileges" error**
   - Make sure you've granted admin consent for the required permissions
   - Check that the user has access to the required scopes

4. **Token expired**
   - Tokens expire after 24 hours by default
   - Re-authenticate to get a new token

### Debug Mode

Set `ENVIRONMENT=development` in your `.env` file for detailed logging.

## Production Deployment

For production deployment:

1. Update the redirect URI to your production domain
2. Use HTTPS for all URLs
3. Generate secure random values for `JWT_SECRET_KEY` and `APP_SECRET_KEY`
4. Set `ENVIRONMENT=production`
5. Consider using Azure Key Vault for secrets
6. Update CORS settings for your specific domains

## Example Usage

```bash
# 1. Get login URL
curl http://localhost:8000/auth/login

# 2. Complete OAuth flow in browser and get JWT token

# 3. Use token to call MCP endpoint
curl -X POST http://localhost:8000/mcp/stream \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'
```

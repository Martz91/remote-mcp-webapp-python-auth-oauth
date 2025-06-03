# Azure Deployment Guide for MCP Server with OAuth

This guide explains how to deploy the Weather MCP Server with Azure OAuth authentication to Azure App Service using Azure Developer CLI (azd).

## Prerequisites for Deployment

1. **Azure Developer CLI (azd)**: [Install azd](https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd)
2. **Azure CLI**: [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
3. **Azure Subscription**: Active Azure subscription
4. **Azure App Registration**: Set up for OAuth (see AUTH_SETUP.md)
5. **Git**: For version control

## Quick Start

### 1. Complete OAuth Setup

Before deploying, ensure you have completed the Azure OAuth setup from `AUTH_SETUP.md`:
- Azure App Registration created
- Client ID, Tenant ID, and Client Secret obtained
- Local testing completed

### 2. Initialize the Azure environment

```bash
azd auth login
azd init
```

When prompted, select "Use code in current directory" and confirm the environment name.

### 3. Set Environment Variables

Configure the OAuth credentials for your deployed application:

```bash
azd env set AZURE_CLIENT_ID "your-client-id"
azd env set AZURE_TENANT_ID "your-tenant-id" 
azd env set AZURE_CLIENT_SECRET "your-client-secret"
azd env set JWT_SECRET_KEY "your-secure-jwt-secret-key"
```

### 4. Deploy to Azure

```bash
azd up
```

This command will:
- Provision Azure resources (App Service, App Service Plan, Application Insights)
- Deploy your application code with OAuth configuration
- Configure the environment variables

### 5. Update Azure App Registration

After deployment, you **must** update your Azure App Registration to include the deployed URL:

1. **Go to Azure Portal**: https://portal.azure.com
2. **Navigate to**: Azure Active Directory → App registrations
3. **Find your app**: Search for your app using the Client ID
4. **Click Authentication** in the left sidebar
5. **Add Redirect URI**:
   - Under "Web" platform, click **"Add URI"**
   - Enter: `https://your-app-name.azurewebsites.net/auth/callback`
   - Click **Save**

### 6. Test Your Deployment

After deployment, azd will provide the URL for your application:
```
Web URI: https://app-web-[unique-id].azurewebsites.net
```

Visit the following URLs to test:
- **Root**: https://app-web-[unique-id].azurewebsites.net/
- **OAuth Login**: https://app-web-[unique-id].azurewebsites.net/auth/login
- **Test Page**: https://app-web-[unique-id].azurewebsites.net/test-auth
- **API Docs**: https://app-web-[unique-id].azurewebsites.net/docs

### 7. Test the Authentication Flow

Once deployed, test your server with authentication:

```bash
# 1. First, get an authentication token by visiting:
# https://your-app-name.azurewebsites.net/auth/login

# 2. Then test the authenticated MCP endpoint:
curl -X POST "https://your-app-name.azurewebsites.net/mcp/stream" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_alerts", "arguments": {"state": "CA"}}}'
```

## OAuth Authentication Flow

### Environment Variables

The following OAuth environment variables are configured during deployment:

- `AZURE_CLIENT_ID`: Your Azure App Registration Client ID
- `AZURE_TENANT_ID`: Your Azure Active Directory Tenant ID  
- `AZURE_CLIENT_SECRET`: Your Azure App Registration Client Secret
- `JWT_SECRET_KEY`: Secret key for JWT token signing
- `APPLICATIONINSIGHTS_CONNECTION_STRING`: For Application Insights monitoring
- `WEBSITES_PORT`: Set to 8000 (FastAPI default)

### Authentication Endpoints

- **Login**: `/auth/login` - Redirects to Microsoft OAuth
- **Callback**: `/auth/callback` - Handles OAuth callback and JWT creation
- **User Info**: `/auth/me` - Get current user information (requires JWT token)
- **Test Page**: `/test-auth` - Web interface for testing authentication

### Protected Endpoints

The following endpoints require authentication (Bearer JWT token):
- `/mcp/stream` - Main MCP endpoint
- `/tools` - List available tools
- `/resources` - List available resources

### Custom Configuration

To add custom environment variables, update `infra/app/web.bicep`:

```bicep
appSettings: [
  // ... existing settings ...
  {
    name: 'YOUR_CUSTOM_VAR'
    value: 'your-value'
  }
]
```

## Architecture

The deployed infrastructure includes:

- **App Service**: Hosts the FastAPI application on Linux with Python 3.11
- **App Service Plan**: B1 tier (Basic, scalable)
- **Application Insights**: Monitoring and telemetry
- **Log Analytics Workspace**: Log storage and analysis

## MCP Inspector Connection with Authentication

After deployment, connect MCP Inspector to your Azure-hosted server with authentication:

### Step 1: Get Authentication Token

1. Visit your deployed app's login page: `https://your-app.azurewebsites.net/auth/login`
2. Complete Microsoft OAuth flow
3. Copy the JWT token from the response

### Step 2: Configure MCP Inspector

Add a new server connection with authentication headers:

```json
{
  "mcpServers": {
    "azure-weather-server-auth": {
      "transport": {
        "type": "http",
        "url": "https://app-web-[your-id].azurewebsites.net/mcp/stream",
        "headers": {
          "Authorization": "Bearer YOUR_JWT_TOKEN_HERE"
        }
      },
      "name": "Azure Weather MCP Server (Authenticated)",
      "description": "Cloud-hosted weather MCP server with Azure OAuth"
    }
  }
}
```

### Step 3: Test Connection

Use the test endpoints to verify authentication:
- **Test Page**: `https://your-app.azurewebsites.net/test-auth`
- **User Info**: `https://your-app.azurewebsites.net/auth/me` (with JWT token)

## Monitoring

### Application Insights

Monitor your application through:
- Azure Portal → Application Insights → your-app-insights
- View metrics: requests, response times, failures
- Application Map: visualize dependencies
- Live Metrics: real-time performance

### Logs

Access application logs:
```bash
azd logs
```

Or through Azure Portal:
- App Service → Monitoring → Log stream

## Troubleshooting

### Common Issues

1. **Deployment Fails**
   ```bash
   azd logs
   ```
   Check for Python dependency issues or configuration errors.

2. **Application Won't Start**
   - Verify `requirements.txt` includes all dependencies
   - Check Application Insights logs in Azure Portal

3. **MCP Connection Issues**
   - Ensure HTTPS URL is used
   - Verify CORS is properly configured
   - Test the `/mcp/capabilities` endpoint

### Debug Commands

```bash
# View deployment logs
azd logs

# Redeploy application only (no infrastructure changes)
azd deploy

# Clean up all resources
azd down

# Show current environment info
azd env get-values
```

## CI/CD Integration

For automated deployments, integrate with GitHub Actions:

```bash
azd pipeline config
```

This creates `.github/workflows/azure-dev.yml` for automatic deployments on push.

## Security

The deployed application includes:
- HTTPS enforcement
- CORS configuration
- Azure App Service security features
- Application Insights for monitoring

For production use, consider:
- Azure Key Vault for secrets
- Azure Active Directory authentication
- Custom domain with SSL certificate
- Azure Front Door for CDN and WAF

## Updates

To update your deployed application:

```bash
# Pull latest changes
git pull

# Deploy updates
azd deploy
```

This preserves your Azure resources and only updates the application code.

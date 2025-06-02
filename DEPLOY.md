# Azure Deployment Guide

This guide explains how to deploy the Weather MCP Server to Azure App Service using Azure Developer CLI (azd).

## 🎉 Current Deployment Status

**The MCP server is successfully deployed and running on Azure!**

- **Live URL**: https://app-web-h5fifvxtt5hca.azurewebsites.net/
- **API Docs**: https://app-web-h5fifvxtt5hca.azurewebsites.net/docs
- **MCP Endpoint**: https://app-web-h5fifvxtt5hca.azurewebsites.net/mcp/stream
- **Resource Group**: `rg-dev`
- **App Service**: `app-web-h5fifvxtt5hca`
- **Region**: East US 2

## Quick Test

Test the deployed weather tools:

```bash
# Test CA weather alerts
curl -X POST "https://app-web-h5fifvxtt5hca.azurewebsites.net/mcp/stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_alerts", "arguments": {"state": "CA"}}}'

# Test San Francisco weather forecast  
curl -X POST "https://app-web-h5fifvxtt5hca.azurewebsites.net/mcp/stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_forecast", "arguments": {"latitude": 37.7749, "longitude": -122.4194}}}'
```

## Prerequisites for Deployment

1. **Azure Developer CLI (azd)**: [Install azd](https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd)
2. **Azure CLI**: [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
3. **Azure Subscription**: Active Azure subscription
4. **Git**: For version control

## Quick Start

### 1. Initialize the Azure environment

```bash
azd auth login
azd init
```

When prompted, select "Use code in current directory" and confirm the environment name.

### 2. Deploy to Azure

```bash
azd up
```

This command will:
- Provision Azure resources (App Service, App Service Plan, Application Insights)
- Deploy your application code
- Configure the environment

### 3. Access your deployed application

After deployment, azd will provide the URL for your application:
```
Web URI: https://app-web-[unique-id].azurewebsites.net
```

## Configuration

### Environment Variables

The following environment variables are automatically configured:
- `APPLICATIONINSIGHTS_CONNECTION_STRING`: For Application Insights monitoring
- `WEBSITES_PORT`: Set to 8000 (FastAPI default)
- `SCM_DO_BUILD_DURING_DEPLOYMENT`: Enables automatic pip install

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

## MCP Inspector Connection

After deployment, connect MCP Inspector to your Azure-hosted server:

1. In MCP Inspector, add a new server connection
2. Use HTTP transport type
3. URL: `https://your-app.azurewebsites.net/mcp/stream`

Example configuration:
```json
{
  "mcpServers": {
    "azure-weather-server": {
      "transport": {
        "type": "http",
        "url": "https://app-web-[your-id].azurewebsites.net/mcp/stream"
      },
      "name": "Azure Weather MCP Server",
      "description": "Cloud-hosted weather MCP server"
    }
  }
}
```

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

## Scaling

### Vertical Scaling (CPU/Memory)

Update the SKU in `infra/core/host/appserviceplan.bicep`:

```bicep
sku: {
  name: 'S1'  // Standard tier
  capacity: 1
}
```

### Horizontal Scaling (Instances)

```bicep
sku: {
  name: 'B1'
  capacity: 3  // Multiple instances
}
```

## Cost Optimization

- **Basic B1**: ~$13/month (1 core, 1.75 GB RAM)
- **Free F1**: Available but with limitations (60 min/day runtime)
- **Application Insights**: Pay-per-use (first 5GB/month free)

To use Free tier, update the SKU:
```bicep
sku: {
  name: 'F1'
  capacity: 1
}
```

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

# Azure OAuth Setup Guide

This guide provides detailed instructions for setting up Azure OAuth 2.0 authentication for the MCP Weather Server. Complete these steps before running the server locally or deploying to Azure.

## Overview

You'll need to create an Azure App Registration to enable OAuth authentication. This involves:
1. Creating the app registration in Azure Portal
2. Configuring client secrets and permissions  
3. Setting up redirect URIs
4. Obtaining the credentials for your `.env` file

## Azure App Registration Setup

### 1. Create Azure App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** > **App registrations** > **New registration**
3. Fill in the details:
   - **Name**: Your MCP Server App (e.g., "MCP Weather Server")
   - **Supported account types**: Accounts in this organizational directory only (or your preferred option)   - **Redirect URI**: 
     - For local development: `http://localhost:8000/auth/azure/callback`
     - For production: `https://your-app-name.azurewebsites.net/auth/azure/callback`
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

**Important**: You need to configure the Azure callback URI (where Azure will send auth codes):

1. Go to **Authentication** 
2. Under **Web** platform, ensure you have:
   - `http://localhost:8000/auth/azure/callback` (for local development)
   - `https://your-deployed-app.azurewebsites.net/auth/azure/callback` (for production)
3. Click **Save**

**Note**: This is where Azure sends the authorization code. It's different from your client's callback URI, which is configured in your OAuth client application.

**Note**: After deploying to Azure, you'll get a URL like `https://app-web-xyz123.azurewebsites.net/`. You'll need to add `/auth/azure/callback` to this URL in your Azure App Registration.

## Environment Configuration

### Create .env File

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your Azure app details:
   ```
   AZURE_CLIENT_ID=your-actual-client-id-from-step-1   AZURE_CLIENT_SECRET=your-actual-client-secret-from-step-2
   AZURE_TENANT_ID=your-actual-tenant-id-from-step-1
   AZURE_REDIRECT_URI=http://localhost:8000/auth/azure/callback
   JWT_SECRET_KEY=generate-a-secure-random-key-for-jwt-signing
   ```

### Generate JWT Secret Key

For the `JWT_SECRET_KEY`, generate a secure random string. You can use:

**Python:**
```python
import secrets
print(secrets.token_urlsafe(32))
```

**PowerShell:**
```powershell
[System.Web.Security.Membership]::GeneratePassword(32, 0)
```

## Post-Deployment Configuration

After deploying to Azure (using the steps in README.md), you **must** update your Azure App Registration:

1. **Get your deployed URL** from azd output (e.g., `https://app-web-xyz123.azurewebsites.net/`)
2. **Go to Azure Portal** → Microsoft Entra ID → App registrations → Your App
3. **Click Authentication** in the left sidebar
4. **Add the production redirect URI**:
   - Click "Add URI" under Web platform
   - Enter: `https://your-app-name.azurewebsites.net/auth/azure/callback`
   - Click **Save**

## Troubleshooting OAuth Issues

### Common Problems

1. **"Invalid client" error**
   - Check your `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`
   - Ensure the client secret hasn't expired (check Azure Portal)

2. **"Redirect URI mismatch"**   
   - Verify the Azure callback URI in Azure App Registration matches exactly:
     - Local: `http://localhost:8000/auth/azure/callback`
     - Production: `https://your-app-name.azurewebsites.net/auth/azure/callback`
   - **Important**: Don't confuse Azure callback URI with your OAuth client's callback URI
   - The Azure callback is where Azure sends auth codes to our server
   - Your OAuth client callback is where our server sends authorization codes to your client

3. **"Insufficient privileges" error**
   - Make sure you've granted admin consent for the required permissions
   - Check that the user has access to the required scopes (`openid`, `profile`, `email`, `User.Read`)

4. **"AADSTS50011: The reply URL specified in the request does not match"**
   - This means your redirect URI configuration is incorrect
   - Double-check the URI in your Azure App Registration matches your deployment URL

5. **Client secret expired**
   - Azure client secrets expire (usually after 24 months)
   - Create a new client secret in Azure Portal
   - Update your environment variables with the new secret

### Debug Mode

Set `ENVIRONMENT=development` in your `.env` file for detailed logging of OAuth flows.

### Testing OAuth Flow

1. **Local Testing**: Visit `http://localhost:8000/mcp_oauth_test.html`
2. **Production Testing**: Visit `https://your-app-name.azurewebsites.net/mcp_oauth_test.html`

The test interface will show you:
- Complete OAuth 2.1 flow with dynamic client registration
- PKCE code challenge/verifier generation
- Azure AD authentication and consent
- Authorization code exchange for JWT tokens
- Protected MCP endpoint testing

### OAuth Flow Architecture

Understanding the redirect URIs:

1. **Azure Callback URI**: `/auth/azure/callback` - Where Azure sends auth codes (configured in Azure App Registration)
2. **Client Callback URI**: `/client-callback` (or your app's URI) - Where our server sends authorization codes to your client
3. **OAuth Client Registration**: Clients register with their own callback URI during dynamic registration

This separation allows multiple OAuth clients to use the same MCP server with different callback endpoints.

## Security Best Practices

- ✅ Use secure random values for `JWT_SECRET_KEY` (32+ characters)
- ✅ Set client secret expiration to maximum 24 months
- ✅ Use HTTPS for all production URLs
- ✅ Regularly rotate client secrets before expiration
- ✅ Monitor Azure AD sign-in logs for unusual activity
- ✅ Consider using Azure Key Vault for production secrets

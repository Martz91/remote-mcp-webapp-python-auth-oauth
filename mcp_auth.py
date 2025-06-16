"""
MCP Authorization Specification Implementation
Provides OAuth 2.1 compliant authorization for MCP servers
"""
import os
import secrets
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode, parse_qs, urlparse
import jwt
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MCP Protocol Version (2025-03-26 Authorization Specification)
MCP_PROTOCOL_VERSION = "2025-03-26"

# Configuration
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

# Azure OAuth URLs (third-party authorization server)
AZURE_AUTH_URL = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/authorize"
AZURE_TOKEN_URL = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
AZURE_GRAPH_URL = "https://graph.microsoft.com/v1.0/me"

# OAuth scopes
SCOPES = ["openid", "profile", "email", "User.Read"]

security = HTTPBearer()

# Pydantic Models for OAuth 2.1
class AuthorizationServerMetadata(BaseModel):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: Optional[str] = None
    response_types_supported: List[str] = ["code"]
    grant_types_supported: List[str] = ["authorization_code", "refresh_token"]
    code_challenge_methods_supported: List[str] = ["S256"]
    token_endpoint_auth_methods_supported: List[str] = ["client_secret_post", "none"]
    scopes_supported: List[str] = ["openid", "profile", "email"]

class ClientRegistrationRequest(BaseModel):
    """Dynamic Client Registration Request (RFC 7591)"""
    redirect_uris: List[str]
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    scope: Optional[str] = None
    contacts: Optional[List[str]] = None
    grant_types: List[str] = ["authorization_code"]
    response_types: List[str] = ["code"]
    token_endpoint_auth_method: str = "none"  # Public client

class ClientRegistrationResponse(BaseModel):
    """Dynamic Client Registration Response (RFC 7591)"""
    client_id: str
    client_secret: Optional[str] = None
    registration_access_token: Optional[str] = None
    registration_client_uri: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: Optional[int] = None
    redirect_uris: List[str]
    grant_types: List[str]
    response_types: List[str]
    client_name: Optional[str] = None
    token_endpoint_auth_method: str

class TokenRequest(BaseModel):
    """OAuth 2.1 Token Request"""
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: str
    code_verifier: Optional[str] = None  # PKCE
    refresh_token: Optional[str] = None

class TokenResponse(BaseModel):
    """OAuth 2.1 Token Response"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

# In-memory storage for demo purposes
# In production, use a proper database
registered_clients: Dict[str, Dict[str, Any]] = {}
authorization_codes: Dict[str, Dict[str, Any]] = {}
refresh_tokens: Dict[str, Dict[str, Any]] = {}

class MCPAuthService:
    """MCP-compliant OAuth 2.1 authorization service"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        
    def get_authorization_base_url(self, mcp_server_url: str) -> str:
        """Extract authorization base URL from MCP server URL"""
        parsed = urlparse(mcp_server_url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def get_metadata(self) -> AuthorizationServerMetadata:
        """Get OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        return AuthorizationServerMetadata(
            issuer=self.base_url,
            authorization_endpoint=f"{self.base_url}/authorize",
            token_endpoint=f"{self.base_url}/token",
            registration_endpoint=f"{self.base_url}/register",
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],            code_challenge_methods_supported=["S256"],
            token_endpoint_auth_methods_supported=["client_secret_post", "none"],
            scopes_supported=["openid", "profile", "email"]
        )
    
    def generate_client_id(self) -> str:
        """Generate a unique client ID"""
        return f"mcp_client_{secrets.token_urlsafe(16)}"
    
    def register_client(self, request: ClientRegistrationRequest) -> ClientRegistrationResponse:
        """Dynamic Client Registration (RFC 7591)"""
        try:
            client_id = self.generate_client_id()
            
            # Ensure required fields have defaults
            redirect_uris = request.redirect_uris if request.redirect_uris else []
            grant_types = request.grant_types if request.grant_types else ["authorization_code"]
            response_types = request.response_types if request.response_types else ["code"]
            client_name = request.client_name if request.client_name else "MCP Client"
            token_endpoint_auth_method = request.token_endpoint_auth_method if request.token_endpoint_auth_method else "client_secret_basic"
            
            # Store client registration
            client_data = {
                "client_id": client_id,
                "redirect_uris": redirect_uris,
                "client_name": client_name,
                "grant_types": grant_types,
                "response_types": response_types,
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "created_at": datetime.utcnow().timestamp()
            }
            
            registered_clients[client_id] = client_data
            
            return ClientRegistrationResponse(
                client_id=client_id,
                redirect_uris=redirect_uris,
                grant_types=grant_types,
                response_types=response_types,
                client_name=client_name,
                token_endpoint_auth_method=token_endpoint_auth_method,
                client_id_issued_at=int(datetime.utcnow().timestamp())
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Client registration failed: {str(e)}")
    
    def validate_pkce(self, code_verifier: str, code_challenge: str) -> bool:
        """Validate PKCE code challenge (RFC 7636)"""
        # S256 method
        verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
        expected_challenge = base64.urlsafe_b64encode(verifier_hash).decode().rstrip('=')
        return expected_challenge == code_challenge
    
    async def create_authorization_url(self, 
                                     client_id: str, 
                                     redirect_uri: str, 
                                     code_challenge: str,
                                     state: Optional[str] = None,
                                     scope: Optional[str] = None) -> str:
        """Create authorization URL for third-party flow"""
          # Validate client (allow testing with unregistered clients in development)
        if client_id not in registered_clients:
            # For development/testing, allow unregistered clients
            if os.getenv("ENVIRONMENT") == "development":
                # Create a temporary client registration for testing
                client = {
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"]
                }
            else:
                raise HTTPException(status_code=400, detail="Invalid client_id")
        else:
            client = registered_clients[client_id]
            if redirect_uri not in client["redirect_uris"]:
                raise HTTPException(status_code=400, detail="Invalid redirect_uri")
        
        # Generate authorization code for later exchange
        auth_code = secrets.token_urlsafe(32)
        
        # Store authorization code with PKCE challenge
        authorization_codes[auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "scope": scope or "openid profile email",
            "created_at": datetime.utcnow().timestamp(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).timestamp()
        }
        
        # Create Azure OAuth URL for third-party authorization
        azure_params = {
            "client_id": AZURE_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": f"{self.base_url}/auth/azure/callback",
            "scope": " ".join(SCOPES),
            "state": auth_code,  # Use our auth code as state
            "response_mode": "query"
        }
        
        azure_url = f"{AZURE_AUTH_URL}?{urlencode(azure_params)}"
        return azure_url
    
    async def handle_azure_callback(self, code: str, state: str) -> str:
        """Handle Azure OAuth callback and return our authorization code"""
        
        # Validate the state (our authorization code)
        if state not in authorization_codes:
            raise HTTPException(status_code=400, detail="Invalid state")
        
        auth_data = authorization_codes[state]
        
        # Check expiration
        if datetime.utcnow().timestamp() > auth_data["expires_at"]:
            del authorization_codes[state]
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Exchange Azure code for token
        azure_token_data = await self._exchange_azure_code(code)
        
        # Get user info from Azure
        user_info = await self._get_azure_user_info(azure_token_data["access_token"])
        
        # Store user info with our authorization code
        auth_data["azure_token"] = azure_token_data
        auth_data["user_info"] = user_info
        
        # Return redirect to client
        client = registered_clients[auth_data["client_id"]]
        redirect_params = {
            "code": state,  # Our authorization code
            "state": auth_data.get("original_state", "")
        }
        
        return f"{auth_data['redirect_uri']}?{urlencode(redirect_params)}"
    
    async def exchange_code_for_token(self, request: TokenRequest) -> TokenResponse:
        """Exchange authorization code for access token (OAuth 2.1)"""
        
        if request.grant_type == "authorization_code":
            return await self._handle_authorization_code_grant(request)
        elif request.grant_type == "refresh_token":
            return await self._handle_refresh_token_grant(request)
        else:
            raise HTTPException(status_code=400, detail="Unsupported grant_type")
    
    async def _handle_authorization_code_grant(self, request: TokenRequest) -> TokenResponse:
        """Handle authorization code grant"""
        
        # Validate authorization code
        if request.code not in authorization_codes:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        auth_data = authorization_codes[request.code]
        
        # Check expiration
        if datetime.utcnow().timestamp() > auth_data["expires_at"]:
            del authorization_codes[request.code]
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Validate client
        if request.client_id != auth_data["client_id"]:
            raise HTTPException(status_code=400, detail="Invalid client")
        
        # Validate PKCE
        if not request.code_verifier:
            raise HTTPException(status_code=400, detail="code_verifier required")
        
        if not self.validate_pkce(request.code_verifier, auth_data["code_challenge"]):
            raise HTTPException(status_code=400, detail="Invalid code_verifier")
        
        # Create JWT token
        user_data = auth_data["user_info"]
        access_token = self._create_jwt_token(user_data)
        refresh_token = secrets.token_urlsafe(32)
        
        # Store refresh token
        refresh_tokens[refresh_token] = {
            "client_id": request.client_id,
            "user_info": user_data,
            "created_at": datetime.utcnow().timestamp(),
            "expires_at": (datetime.utcnow() + timedelta(days=30)).timestamp()
        }
        
        # Clean up authorization code
        del authorization_codes[request.code]
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=JWT_EXPIRATION_HOURS * 3600,
            refresh_token=refresh_token,
            scope=auth_data["scope"]
        )
    
    async def _handle_refresh_token_grant(self, request: TokenRequest) -> TokenResponse:
        """Handle refresh token grant"""
        
        if not request.refresh_token or request.refresh_token not in refresh_tokens:
            raise HTTPException(status_code=400, detail="Invalid refresh_token")
        
        token_data = refresh_tokens[request.refresh_token]
        
        # Check expiration
        if datetime.utcnow().timestamp() > token_data["expires_at"]:
            del refresh_tokens[request.refresh_token]
            raise HTTPException(status_code=400, detail="Refresh token expired")
        
        # Validate client
        if request.client_id != token_data["client_id"]:
            raise HTTPException(status_code=400, detail="Invalid client")
        
        # Create new access token
        access_token = self._create_jwt_token(token_data["user_info"])
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=JWT_EXPIRATION_HOURS * 3600
        )
    
    async def _exchange_azure_code(self, code: str) -> Dict[str, Any]:
        """Exchange Azure authorization code for access token"""
        data = {
            "client_id": AZURE_CLIENT_ID,
            "client_secret": AZURE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{self.base_url}/auth/azure/callback",
            "scope": " ".join(SCOPES),
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(AZURE_TOKEN_URL, data=data)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Azure token exchange failed: {response.text}"
                )
                
            return response.json()
    
    async def _get_azure_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Microsoft Graph API"""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(AZURE_GRAPH_URL, headers=headers)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to get Azure user info: {response.text}"
                )
                
            return response.json()
    
    def _create_jwt_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT token for authenticated user"""
        payload = {
            "sub": user_data.get("id"),
            "email": user_data.get("mail") or user_data.get("userPrincipalName"),
            "name": user_data.get("displayName"),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
        }
        
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get current authenticated user"""
    auth_service = MCPAuthService(os.getenv("BASE_URL", "http://localhost:8000"))
    return auth_service.validate_token(credentials.credentials)

def optional_auth(request: Request) -> Optional[Dict[str, Any]]:
    """Optional authentication dependency"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    try:
        token = auth_header.split(" ")[1]
        auth_service = MCPAuthService(os.getenv("BASE_URL", "http://localhost:8000"))
        return auth_service.validate_token(token)
    except:
        return None

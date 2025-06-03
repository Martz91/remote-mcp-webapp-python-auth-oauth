#!/usr/bin/env python3
"""
Quick test script to verify Azure OAuth configuration
"""
import requests
import json
from urllib.parse import parse_qs, urlparse

def test_server_health():
    """Test if the server is running and healthy"""
    try:
        response = requests.get("http://localhost:8000")
        print("✅ Server Health Check:")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"❌ Server Health Check Failed: {e}")
        return False

def test_protected_endpoint():
    """Test that protected endpoints require authentication"""
    try:
        response = requests.get("http://localhost:8000/tools")
        print("\n✅ Protected Endpoint Test:")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        return response.status_code == 403  # FastAPI returns 403 for unauthenticated
    except Exception as e:
        print(f"❌ Protected Endpoint Test Failed: {e}")
        return False

def test_oauth_redirect():
    """Test that OAuth login redirects properly"""
    try:
        response = requests.get("http://localhost:8000/auth/login", allow_redirects=False)
        print("\n✅ OAuth Redirect Test:")
        print(f"   Status: {response.status_code}")
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            print(f"   Redirect URL: {location}")
            
            # Check if it's a valid Microsoft OAuth URL
            if 'login.microsoftonline.com' in location:
                print("   ✅ Valid Microsoft OAuth redirect")
                
                # Parse URL to check parameters
                parsed = urlparse(location)
                params = parse_qs(parsed.query)
                
                required_params = ['client_id', 'response_type', 'redirect_uri', 'scope']
                for param in required_params:
                    if param in params:
                        print(f"   ✅ {param}: {params[param][0]}")
                    else:
                        print(f"   ❌ Missing {param}")
                        
                return True
            else:
                print("   ❌ Invalid redirect URL")
                return False
        else:
            print(f"   ❌ Expected 302 redirect, got {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ OAuth Redirect Test Failed: {e}")
        return False

def main():
    print("🧪 Testing Azure OAuth MCP Server")
    print("=" * 50)
    
    # Run tests
    health_ok = test_server_health()
    if not health_ok:
        print("\n❌ Server is not running. Please start the server first.")
        return
    
    protected_ok = test_protected_endpoint()
    oauth_ok = test_oauth_redirect()
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    print(f"   Server Health: {'✅' if health_ok else '❌'}")
    print(f"   Protected Endpoints: {'✅' if protected_ok else '❌'}")
    print(f"   OAuth Configuration: {'✅' if oauth_ok else '❌'}")
    
    if health_ok and protected_ok and oauth_ok:
        print("\n🎉 All tests passed! Your Azure OAuth setup is working correctly.")
        print("\n📋 Next steps:")
        print("   1. Visit http://localhost:8000/test-auth to test the full OAuth flow")
        print("   2. Login with your Azure credentials")
        print("   3. Test protected endpoints after authentication")
    else:
        print("\n❌ Some tests failed. Please check your configuration.")

if __name__ == "__main__":
    main()

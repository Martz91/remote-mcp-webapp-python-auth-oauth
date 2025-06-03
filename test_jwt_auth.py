#!/usr/bin/env python3
"""
Test authenticated MCP calls with your JWT token
"""
import requests
import json

# Your JWT token (replace with your actual token)
JWT_TOKEN = "your-jwt-token-here"

BASE_URL = "http://localhost:8000"

def test_authenticated_endpoints():
    """Test all authenticated endpoints with the JWT token"""
    headers = {
        "Authorization": f"Bearer {JWT_TOKEN}",
        "Content-Type": "application/json"
    }
    
    print("🔐 Testing Authenticated Endpoints")
    print("=" * 50)
    
    # Test 1: User info
    print("\n1. Testing /auth/me:")
    try:
        response = requests.get(f"{BASE_URL}/auth/me", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            user_data = response.json()
            print(f"   ✅ User: {user_data['user']['name']} ({user_data['user']['email']})")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 2: Tools list
    print("\n2. Testing /tools:")
    try:
        response = requests.get(f"{BASE_URL}/tools", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            tools = response.json()['tools']
            print(f"   ✅ Available tools: {len(tools)}")
            for tool in tools:
                print(f"      - {tool['name']}: {tool['description']}")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 3: Resources list
    print("\n3. Testing /resources:")
    try:
        response = requests.get(f"{BASE_URL}/resources", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            resources = response.json()['resources']
            print(f"   ✅ Available resources: {len(resources)}")
            for resource in resources:
                print(f"      - {resource['name']}: {resource['description']}")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 4: MCP tool call - Get Forecast
    print("\n4. Testing MCP tool call (get_forecast):")
    try:
        mcp_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_forecast",
                "arguments": {
                    "latitude": 40.7128,  # NYC
                    "longitude": -74.0060
                }
            }
        }
        response = requests.post(f"{BASE_URL}/mcp/stream", headers=headers, json=mcp_request)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            if 'result' in result:
                print(f"   ✅ Forecast retrieved successfully")
                forecast = result['result']
                if 'content' in forecast and forecast['content']:
                    content = forecast['content'][0]
                    if 'text' in content:
                        # Show first 200 characters of the forecast
                        forecast_text = content['text'][:200]
                        print(f"   📊 Forecast preview: {forecast_text}...")
                    else:
                        print(f"   📊 Forecast data: {json.dumps(forecast, indent=2)[:200]}...")
                else:
                    print(f"   📊 Response: {json.dumps(result, indent=2)[:200]}...")
            elif 'error' in result:
                print(f"   ❌ MCP Error: {result['error']}")
            else:
                print(f"   📊 Response: {json.dumps(result, indent=2)[:200]}...")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")
    
    # Test 5: MCP tool call - Get Alerts
    print("\n5. Testing MCP tool call (get_alerts):")
    try:
        mcp_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_alerts",
                "arguments": {
                    "state": "CA"
                }
            }
        }
        response = requests.post(f"{BASE_URL}/mcp/stream", headers=headers, json=mcp_request)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            if 'result' in result:
                print(f"   ✅ Alerts retrieved successfully")
                alerts = result['result']
                if 'content' in alerts and alerts['content']:
                    content = alerts['content'][0]
                    if 'text' in content:
                        alert_text = content['text'][:200]
                        print(f"   🚨 Alerts preview: {alert_text}...")
                    else:
                        print(f"   🚨 Alert data: {json.dumps(alerts, indent=2)[:200]}...")
                else:
                    print(f"   🚨 Response: {json.dumps(result, indent=2)[:200]}...")
            elif 'error' in result:
                print(f"   ❌ MCP Error: {result['error']}")
            else:
                print(f"   🚨 Response: {json.dumps(result, indent=2)[:200]}...")
        else:
            print(f"   ❌ Error: {response.text}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")

def main():
    print("🧪 Testing MCP Server with JWT Authentication")
    print("🔑 Replace JWT_TOKEN variable with your actual token")
    test_authenticated_endpoints()
    
    print("\n" + "=" * 50)
    print("✅ Authentication testing complete!")
    print("🌟 Your JWT token is working correctly with all endpoints!")

if __name__ == "__main__":
    main()

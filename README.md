# FastAPI MCP Server with Weather Tools

A Model Context Protocol (MCP) server built with FastAPI that provides weather information using the National Weather Service API. Features streamable HTTP transport for real-time communication with MCP Inspector.

## 🌐 Live Azure Deployment

- **Azure URL**: https://`<APP-SERVICE-NAME>`.azurewebsites.net/
- **API Documentation**: https://`<APP-SERVICE-NAME>`.azurewebsites.net/docs
- **Health Check**: https://`<APP-SERVICE-NAME>`.azurewebsites.net/
- **MCP Endpoint**: https://`<APP-SERVICE-NAME>`.azurewebsites.net/mcp/stream

You can test the weather tools immediately without local setup:

```bash
# Test weather alerts for California
curl -X POST "https://`<APP-SERVICE-NAME>`.azurewebsites.net/mcp/stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_alerts", "arguments": {"state": "CA"}}}'

# Test weather forecast for San Francisco
curl -X POST "https://`<APP-SERVICE-NAME>`.azurewebsites.net/mcp/stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_forecast", "arguments": {"latitude": 37.7749, "longitude": -122.4194}}}'
```

## Features

- **FastAPI Framework**: Modern, fast web framework for building APIs
- **MCP Protocol Compliance**: Full support for JSON-RPC 2.0 MCP protocol
- **Streamable HTTP Transport**: HTTP-based streaming for MCP Inspector connectivity
- **Weather Tools**: 
  - `get_alerts`: Get weather alerts for any US state
  - `get_forecast`: Get 5-day weather forecast for any location (latitude/longitude)
- **Sample Resources**: Basic resource handling demonstration
- **Virtual Environment**: Properly isolated Python environment
- **Auto-reload**: Development server with automatic reloading
- **National Weather Service API**: Real-time weather data from official US government source

## Prerequisites

- Python 3.8+
- pip (Python package installer)

## Setup

1. **Create and activate virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

2. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Start the server:**
   ```powershell
   .\start_server.ps1
   ```
   
   Or manually:
   ```powershell
   .\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

## Connecting to MCP Inspector

### Method 1: Azure-Hosted Server (No Setup Required)

Connect directly to the live Azure deployment:

**Configuration for MCP Inspector:**
```json
{
  "mcpServers": {
    "weather-mcp-server-azure": {
      "transport": {
        "type": "http",
        "url": "https://`<APP-SERVICE-NAME>`.azurewebsites.net/mcp/stream"
      },
      "name": "Weather MCP Server (Azure)",
      "description": "MCP Server with weather forecast and alerts tools hosted on Azure"
    }
  }
}
```

### Method 2: Local Development Server

1. **Start the MCP server** (it will run on http://localhost:8000)

2. **In MCP Inspector v0.13.0:**
   - Add a new server connection
   - Use HTTP transport type
   - URL: `http://localhost:8000/mcp/stream`

3. **Configuration file** (`mcp-config.json`):
   ```json
   {
     "mcpServers": {
       "weather-mcp-server-local": {
         "transport": {
           "type": "http",
           "url": "http://localhost:8000/mcp/stream"
         },
         "name": "Weather MCP Server (Local)",
         "description": "MCP Server with weather forecast and alerts tools running locally"
       }
     }
   }
   ```

### Method 3: Web Test Interface

Visit http://localhost:8000/test (local) or https://`<APP-SERVICE-NAME>`.azurewebsites.net/test (Azure) to use the built-in web interface for testing HTTP connectivity.

## API Endpoints

- **GET /health**: Server health check
- **POST /mcp/stream**: Main MCP endpoint with streamable HTTP
- **GET /mcp/capabilities**: Get server capabilities
- **GET /test**: Web-based HTTP test interface
- **POST /mcp**: HTTP MCP endpoint (legacy)

## Usage

### Start the server:
```bash
pip install -r requirements.txt
python main.py
```

The server will start on http://localhost:8000

### Example MCP requests:

#### Initialize
```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {},
  "id": 1
}
```

#### List Tools
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}
```

#### Call Weather Alert Tool
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get_alerts",
    "arguments": {
      "state": "CA"
    }
  },
  "id": 3
}
```

#### Call Weather Forecast Tool
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get_forecast",
    "arguments": {
      "latitude": 37.7749,
      "longitude": -122.4194
    }
  },
  "id": 4
}
```

## Testing

### Test with Python client:
```powershell
.\venv\Scripts\python.exe test_http_client.py  # Streamable HTTP client
```

### Test with web interface:
Open http://localhost:8000/test in your browser

## Available Tools

1. **get_alerts**: Get weather alerts for a US state
   ```json
   {
     "name": "get_alerts",
     "arguments": {
       "state": "CA"
     }
   }
   ```
   - **Parameter**: `state` (string) - Two-letter US state code (e.g., CA, NY, TX)
   - **Returns**: Active weather alerts including severity, description, and instructions

2. **get_forecast**: Get weather forecast for a location
   ```json
   {
     "name": "get_forecast", 
     "arguments": {
       "latitude": 37.7749,
       "longitude": -122.4194
     }
   }
   ```
   - **Parameters**: 
     - `latitude` (number) - Latitude coordinate
     - `longitude` (number) - Longitude coordinate
   - **Returns**: 5-day weather forecast with temperature, wind, and detailed conditions

## Weather Data Source

This server uses the **National Weather Service (NWS) API**, which provides:
- Real-time weather alerts and warnings
- Detailed weather forecasts
- Official US government weather data
- No API key required
- High reliability and accuracy

## Available Resources

- **mcp://server/sample**: Sample resource for demonstration

## Troubleshooting

### MCP Inspector Connection Issues:
1. Ensure the server is running on http://localhost:8000
2. Verify MCP endpoint is accessible: http://localhost:8000/mcp/stream
3. Check capabilities endpoint: http://localhost:8000/mcp/capabilities
4. Try the web test interface first: http://localhost:8000/test

### Common Issues:
- **Port already in use**: Change the port in startup commands
- **Virtual environment not activated**: Run `.\venv\Scripts\Activate.ps1`
- **Dependencies missing**: Run `pip install -r requirements.txt`
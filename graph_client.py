from typing import Any, Dict
import httpx
from mcp_auth import MCPAuthService

class GraphClient:
    def __init__(self, auth_service: MCPAuthService):
        self._auth = auth_service
        self._base_url = "https://graph.microsoft.com/v1.0"

    async def post(
        self,
        path: str,
        *,
        json: Dict[str, Any] | None = None,
        data: Dict[str, Any] | None = None,
        access_token: str
    ) -> httpx.Response:

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }

        if json is not None:
            headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient(base_url=self._base_url, headers=headers, timeout=30.0) as client:
            print(f"Sending POST request to {path}")
            return await client.post(path, json=json, data=data)
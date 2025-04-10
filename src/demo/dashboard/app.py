from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import Request
import uvicorn
import json
import asyncio
from typing import Dict, List, Optional
from logger import DemoLogger
from status import StatusReporter

class Dashboard:
    """Dashboard application for ARP Guard demo"""
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        logger: Optional[DemoLogger] = None,
        status_reporter: Optional[StatusReporter] = None
    ):
        self.app = FastAPI()
        self.host = host
        self.port = port
        self.logger = logger or DemoLogger()
        self.status_reporter = status_reporter or StatusReporter()
        self.connections: List[WebSocket] = []
        
        # Setup routes
        self.setup_routes()
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory="static"), name="static")
        
        # Setup templates
        self.templates = Jinja2Templates(directory="templates")
    
    def setup_routes(self):
        """Setup FastAPI routes"""
        @self.app.get("/", response_class=HTMLResponse)
        async def get_dashboard(request: Request):
            return self.templates.TemplateResponse(
                "dashboard.html",
                {"request": request}
            )
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self.handle_websocket(websocket)
    
    async def handle_websocket(self, websocket: WebSocket):
        """Handle WebSocket connections"""
        await websocket.accept()
        self.connections.append(websocket)
        
        try:
            while True:
                # Send status updates
                status = self.status_reporter.get_status()
                await websocket.send_json(status)
                await asyncio.sleep(1)  # Update every second
        except WebSocketDisconnect:
            self.connections.remove(websocket)
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
            if websocket in self.connections:
                self.connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        for connection in self.connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                self.logger.error(f"Failed to send message: {e}")
                if connection in self.connections:
                    self.connections.remove(connection)
    
    def run(self):
        """Run the dashboard server"""
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        ) 
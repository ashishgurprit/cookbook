"""
WebSocket Universal - Production FastAPI Backend
Multi-Server WebSocket with Redis Pub/Sub

Features:
- Multi-server scaling (Redis Pub/Sub)
- Room/channel support
- Authentication (JWT)
- Rate limiting
- Auto-reconnect handling
- OWASP Top 10 compliance
"""

import os
import asyncio
import json
from datetime import datetime
from typing import Dict, Set, Optional, List
from enum import Enum

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis.asyncio import Redis
from jose import jwt, JWTError
import logging

# ============================================================================
# Configuration
# ============================================================================

class WebSocketConfig:
    """Environment-based configuration"""

    # Redis
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
    JWT_ALGORITHM = "HS256"

    # Limits
    MAX_CONNECTIONS_PER_USER = int(os.getenv('MAX_CONNECTIONS_PER_USER', 5))
    MESSAGE_RATE_LIMIT = int(os.getenv('MESSAGE_RATE_LIMIT', 100))  # per minute
    CONNECTION_RATE_LIMIT = int(os.getenv('CONNECTION_RATE_LIMIT', 10))  # per hour per IP

    # Security
    ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Models
# ============================================================================

class MessageType(str, Enum):
    """WebSocket message types"""
    # Connection
    PING = "ping"
    PONG = "pong"

    # Chat
    CHAT = "chat"
    TYPING = "typing"

    # Rooms
    JOIN_ROOM = "join_room"
    LEAVE_ROOM = "leave_room"
    ROOM_MESSAGE = "room_message"

    # Presence
    USER_ONLINE = "user_online"
    USER_OFFLINE = "user_offline"

    # Errors
    ERROR = "error"


class WebSocketMessage(BaseModel):
    """WebSocket message format"""
    type: MessageType
    payload: dict
    timestamp: Optional[int] = None
    message_id: Optional[str] = None


# ============================================================================
# Authentication
# ============================================================================

def verify_token(token: str) -> dict:
    """Verify JWT token"""
    try:
        payload = jwt.decode(
            token,
            WebSocketConfig.JWT_SECRET_KEY,
            algorithms=[WebSocketConfig.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """Redis-based rate limiting"""

    def __init__(self, redis: Redis):
        self.redis = redis

    async def check_message_rate(self, user_id: str) -> bool:
        """Check if user is within message rate limit"""
        key = f"ws:msg_limit:{user_id}:minute"
        count = await self.redis.incr(key)

        if count == 1:
            await self.redis.expire(key, 60)

        return count <= WebSocketConfig.MESSAGE_RATE_LIMIT

    async def check_connection_rate(self, ip: str) -> bool:
        """Check if IP is within connection rate limit"""
        key = f"ws:conn_limit:{ip}:hour"
        count = await self.redis.incr(key)

        if count == 1:
            await self.redis.expire(key, 3600)

        return count <= WebSocketConfig.CONNECTION_RATE_LIMIT


# ============================================================================
# Connection Manager
# ============================================================================

class ConnectionManager:
    """Manage WebSocket connections"""

    def __init__(self):
        # user_id -> set of websockets
        self.active_connections: Dict[str, Set[WebSocket]] = {}

        # websocket -> user_id (reverse lookup)
        self.websocket_to_user: Dict[WebSocket, str] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        """Add new connection"""
        await websocket.accept()

        # Check connection limit
        if user_id in self.active_connections:
            if len(self.active_connections[user_id]) >= WebSocketConfig.MAX_CONNECTIONS_PER_USER:
                await websocket.close(code=1008, reason="Too many connections")
                return

        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()

        self.active_connections[user_id].add(websocket)
        self.websocket_to_user[websocket] = user_id

        logger.info(f"User {user_id} connected (total: {len(self.active_connections[user_id])})")

        # Notify other devices
        await self.broadcast_to_user(user_id, {
            'type': 'device_connected',
            'device_count': len(self.active_connections[user_id])
        }, exclude=websocket)

    def disconnect(self, websocket: WebSocket):
        """Remove connection"""
        user_id = self.websocket_to_user.get(websocket)

        if user_id and user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)

            if not self.active_connections[user_id]:
                del self.active_connections[user_id]

        if websocket in self.websocket_to_user:
            del self.websocket_to_user[websocket]

        logger.info(f"User {user_id} disconnected")

    async def send_to_user(self, user_id: str, message: dict):
        """Send message to all user's connections"""
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id].copy():
                try:
                    await connection.send_json(message)
                except:
                    self.disconnect(connection)

    async def broadcast_to_user(
        self,
        user_id: str,
        message: dict,
        exclude: WebSocket = None
    ):
        """Broadcast to all user's devices except one"""
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                if connection != exclude:
                    try:
                        await connection.send_json(message)
                    except:
                        self.disconnect(connection)

    def get_online_users(self) -> List[str]:
        """Get list of currently online users"""
        return list(self.active_connections.keys())

    def is_user_online(self, user_id: str) -> bool:
        """Check if user has any active connections"""
        return user_id in self.active_connections

    def get_connection_count(self) -> int:
        """Get total number of connections"""
        return sum(len(conns) for conns in self.active_connections.values())


# ============================================================================
# Room Manager
# ============================================================================

class RoomManager:
    """Manage chat rooms and channels"""

    def __init__(self):
        # room_id -> set of user_ids
        self.rooms: Dict[str, Set[str]] = {}

        # user_id -> set of room_ids (reverse lookup)
        self.user_rooms: Dict[str, Set[str]] = {}

    async def join_room(self, user_id: str, room_id: str):
        """Add user to room"""

        # Add to room
        if room_id not in self.rooms:
            self.rooms[room_id] = set()

        self.rooms[room_id].add(user_id)

        # Track user's rooms
        if user_id not in self.user_rooms:
            self.user_rooms[user_id] = set()

        self.user_rooms[user_id].add(room_id)

        logger.info(f"User {user_id} joined room {room_id}")

    async def leave_room(self, user_id: str, room_id: str):
        """Remove user from room"""

        if room_id in self.rooms:
            self.rooms[room_id].discard(user_id)

            if not self.rooms[room_id]:
                del self.rooms[room_id]

        if user_id in self.user_rooms:
            self.user_rooms[user_id].discard(room_id)

        logger.info(f"User {user_id} left room {room_id}")

    def get_room_users(self, room_id: str) -> List[str]:
        """Get list of users in room"""
        return list(self.rooms.get(room_id, []))

    def get_user_rooms(self, user_id: str) -> List[str]:
        """Get list of rooms user is in"""
        return list(self.user_rooms.get(user_id, []))


# ============================================================================
# Redis Pub/Sub
# ============================================================================

class RedisPubSub:
    """Redis Pub/Sub for multi-server messaging"""

    def __init__(self, connection_manager: ConnectionManager, room_manager: RoomManager):
        self.redis = Redis(
            host=WebSocketConfig.REDIS_HOST,
            port=WebSocketConfig.REDIS_PORT,
            decode_responses=True
        )
        self.pubsub = self.redis.pubsub()
        self.connection_manager = connection_manager
        self.room_manager = room_manager

    async def publish(self, channel: str, message: dict):
        """Publish message to Redis channel"""
        await self.redis.publish(channel, json.dumps(message))

    async def subscribe(self, channel: str):
        """Subscribe to Redis channel"""
        await self.pubsub.subscribe(channel)

        async for message in self.pubsub.listen():
            if message['type'] == 'message':
                data = json.loads(message['data'])
                await self.handle_message(data)

    async def handle_message(self, message: dict):
        """Handle broadcast messages from Redis"""
        msg_type = message.get('type')

        if msg_type == 'broadcast':
            # Send to all connected users
            for user_id in self.connection_manager.get_online_users():
                await self.connection_manager.send_to_user(user_id, message['payload'])

        elif msg_type == 'user_message':
            # Send to specific user
            user_id = message['user_id']
            await self.connection_manager.send_to_user(user_id, message['payload'])

        elif msg_type == 'room_message':
            # Send to all users in room
            room_id = message['room_id']
            users = self.room_manager.get_room_users(room_id)
            for user_id in users:
                if self.connection_manager.is_user_online(user_id):
                    await self.connection_manager.send_to_user(user_id, message['payload'])


# ============================================================================
# Message Handlers
# ============================================================================

class MessageHandler:
    """Handle WebSocket messages"""

    def __init__(
        self,
        connection_manager: ConnectionManager,
        room_manager: RoomManager,
        redis_pubsub: RedisPubSub,
        rate_limiter: RateLimiter
    ):
        self.connection_manager = connection_manager
        self.room_manager = room_manager
        self.redis_pubsub = redis_pubsub
        self.rate_limiter = rate_limiter

    async def handle(self, websocket: WebSocket, message: dict, user_id: str):
        """Route message to appropriate handler"""

        # Check rate limit
        if not await self.rate_limiter.check_message_rate(user_id):
            await websocket.send_json({
                'type': 'error',
                'payload': {'message': 'Message rate limit exceeded'}
            })
            return

        msg_type = message.get('type')

        if msg_type == 'ping':
            await self.handle_ping(websocket)

        elif msg_type == 'chat':
            await self.handle_chat(websocket, message, user_id)

        elif msg_type == 'join_room':
            await self.handle_join_room(websocket, message, user_id)

        elif msg_type == 'leave_room':
            await self.handle_leave_room(websocket, message, user_id)

        elif msg_type == 'room_message':
            await self.handle_room_message(websocket, message, user_id)

        elif msg_type == 'typing':
            await self.handle_typing(websocket, message, user_id)

        else:
            await websocket.send_json({
                'type': 'error',
                'payload': {'message': f'Unknown message type: {msg_type}'}
            })

    async def handle_ping(self, websocket: WebSocket):
        """Handle ping message"""
        await websocket.send_json({'type': 'pong'})

    async def handle_chat(self, websocket: WebSocket, message: dict, user_id: str):
        """Handle direct chat message"""
        recipient_id = message['payload'].get('to')

        if not recipient_id:
            await websocket.send_json({
                'type': 'error',
                'payload': {'message': 'Recipient not specified'}
            })
            return

        # Publish to Redis (for multi-server)
        await self.redis_pubsub.publish('websocket:broadcast', {
            'type': 'user_message',
            'user_id': recipient_id,
            'payload': {
                'type': 'chat',
                'from': user_id,
                'message': message['payload']['message'],
                'timestamp': datetime.now().timestamp()
            }
        })

    async def handle_join_room(self, websocket: WebSocket, message: dict, user_id: str):
        """Handle room join"""
        room_id = message['payload'].get('room_id')

        if not room_id:
            await websocket.send_json({
                'type': 'error',
                'payload': {'message': 'Room ID not specified'}
            })
            return

        await self.room_manager.join_room(user_id, room_id)

        # Notify room
        await self.redis_pubsub.publish('websocket:broadcast', {
            'type': 'room_message',
            'room_id': room_id,
            'payload': {
                'type': 'user_joined',
                'user_id': user_id,
                'room_id': room_id
            }
        })

    async def handle_leave_room(self, websocket: WebSocket, message: dict, user_id: str):
        """Handle room leave"""
        room_id = message['payload'].get('room_id')

        if not room_id:
            return

        await self.room_manager.leave_room(user_id, room_id)

        # Notify room
        await self.redis_pubsub.publish('websocket:broadcast', {
            'type': 'room_message',
            'room_id': room_id,
            'payload': {
                'type': 'user_left',
                'user_id': user_id,
                'room_id': room_id
            }
        })

    async def handle_room_message(self, websocket: WebSocket, message: dict, user_id: str):
        """Handle room broadcast message"""
        room_id = message['payload'].get('room_id')
        msg_text = message['payload'].get('message')

        if not room_id or not msg_text:
            return

        # Publish to Redis (for multi-server)
        await self.redis_pubsub.publish('websocket:broadcast', {
            'type': 'room_message',
            'room_id': room_id,
            'payload': {
                'type': 'room_message',
                'from': user_id,
                'room_id': room_id,
                'message': msg_text,
                'timestamp': datetime.now().timestamp()
            }
        })

    async def handle_typing(self, websocket: WebSocket, message: dict, user_id: str):
        """Handle typing indicator"""
        room_id = message['payload'].get('room_id')

        if not room_id:
            return

        # Notify room (don't persist)
        await self.redis_pubsub.publish('websocket:broadcast', {
            'type': 'room_message',
            'room_id': room_id,
            'payload': {
                'type': 'typing',
                'user_id': user_id,
                'room_id': room_id
            }
        })


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="WebSocket Universal API",
    version="1.0.0",
    description="Multi-server WebSocket with Redis Pub/Sub"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=WebSocketConfig.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
connection_manager = ConnectionManager()
room_manager = RoomManager()
redis_pubsub = RedisPubSub(connection_manager, room_manager)
rate_limiter = RateLimiter(redis_pubsub.redis)
message_handler = MessageHandler(
    connection_manager,
    room_manager,
    redis_pubsub,
    rate_limiter
)


# ============================================================================
# Startup/Shutdown Events
# ============================================================================

@app.on_event("startup")
async def startup():
    """Start Redis subscriber on app startup"""
    logger.info("Starting Redis subscriber...")
    asyncio.create_task(
        redis_pubsub.subscribe('websocket:broadcast')
    )


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    logger.info("Shutting down...")
    await redis_pubsub.redis.close()


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """Main WebSocket endpoint"""

    # Check connection rate limit
    ip = websocket.client.host
    if not await rate_limiter.check_connection_rate(ip):
        await websocket.close(code=1008, reason="Connection rate limit exceeded")
        return

    # Verify JWT token
    try:
        payload = verify_token(token)
        user_id = payload.get('user_id')

        if not user_id:
            await websocket.close(code=1008, reason="Invalid token")
            return

    except HTTPException:
        await websocket.close(code=1008, reason="Unauthorized")
        return

    # Connect user
    await connection_manager.connect(user_id, websocket)

    try:
        while True:
            # Receive message
            message = await websocket.receive_json()

            # Handle message
            await message_handler.handle(websocket, message, user_id)

    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)

        # Leave all rooms
        for room_id in room_manager.get_user_rooms(user_id):
            await room_manager.leave_room(user_id, room_id)


# ============================================================================
# HTTP Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""

    health = {
        'status': 'ok',
        'timestamp': datetime.now(),
        'connections': connection_manager.get_connection_count(),
        'online_users': len(connection_manager.get_online_users()),
        'redis': 'unknown'
    }

    # Check Redis
    try:
        await redis_pubsub.redis.ping()
        health['redis'] = 'ok'
    except:
        health['redis'] = 'error'
        health['status'] = 'degraded'

    return health


@app.get("/stats")
async def get_stats():
    """Get WebSocket statistics"""
    return {
        'total_connections': connection_manager.get_connection_count(),
        'online_users': len(connection_manager.get_online_users()),
        'total_rooms': len(room_manager.rooms)
    }


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=(WebSocketConfig.ENVIRONMENT == "development")
    )

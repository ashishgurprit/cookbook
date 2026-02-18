# WebSocket Universal - Quick Start Guide

**Get production WebSocket running in 25 minutes**

## Prerequisites

- Python 3.9+ or Node.js 16+
- Redis (for Pub/Sub)
- JWT tokens for authentication

## Installation (5 minutes)

### Python
```bash
pip install fastapi uvicorn websockets redis python-jose[cryptography]
```

### Redis Setup
```bash
# macOS
brew install redis
brew services start redis

# Linux
sudo apt-get install redis-server
sudo systemctl start redis

# Verify
redis-cli ping  # Should return PONG
```

### Environment Variables
```bash
# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT
JWT_SECRET_KEY=your-secret-key-change-in-production

# Limits
MAX_CONNECTIONS_PER_USER=5
MESSAGE_RATE_LIMIT=100  # per minute
CONNECTION_RATE_LIMIT=10  # per hour per IP

# CORS
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

## Setup (10 minutes)

### 1. Copy Backend Template
```bash
cp .claude/skills/websocket-universal/templates/backend/fastapi-websocket.py app/websocket.py
```

### 2. Generate JWT Token (for testing)
```python
from jose import jwt
from datetime import datetime, timedelta

SECRET_KEY = "your-secret-key"
payload = {
    'user_id': 'user-123',
    'exp': datetime.utcnow() + timedelta(hours=24)
}
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
print(token)
```

### 3. Run Server
```bash
uvicorn app.websocket:app --reload
```

## Smoke Tests (10 minutes)

### Test 1: WebSocket Connection

**JavaScript Client:**
```javascript
const token = 'your-jwt-token';
const ws = new WebSocket(`ws://localhost:8000/ws?token=${token}`);

ws.onopen = () => {
    console.log('Connected!');

    // Send ping
    ws.send(JSON.stringify({ type: 'ping' }));
};

ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('Received:', message);
};

ws.onclose = () => {
    console.log('Disconnected');
};
```

**Expected Response:**
```json
{"type": "pong"}
```

### Test 2: Join Room & Send Message
```javascript
// Join room
ws.send(JSON.stringify({
    type: 'join_room',
    payload: { room_id: 'room-123' }
}));

// Send message to room
ws.send(JSON.stringify({
    type: 'room_message',
    payload: {
        room_id: 'room-123',
        message: 'Hello everyone!'
    }
}));
```

**Expected Response:**
```json
{
    "type": "user_joined",
    "user_id": "user-123",
    "room_id": "room-123"
}

{
    "type": "room_message",
    "from": "user-123",
    "room_id": "room-123",
    "message": "Hello everyone!",
    "timestamp": 1234567890
}
```

### Test 3: Direct Chat
```javascript
// Send direct message
ws.send(JSON.stringify({
    type: 'chat',
    payload: {
        to: 'user-456',
        message: 'Hi there!'
    }
}));
```

### Test 4: Typing Indicator
```javascript
// Send typing indicator
ws.send(JSON.stringify({
    type: 'typing',
    payload: { room_id: 'room-123' }
}));
```

### Test 5: Health Check
```bash
curl http://localhost:8000/health

# Expected:
# {
#   "status": "ok",
#   "connections": 1,
#   "online_users": 1,
#   "redis": "ok"
# }
```

### Test 6: Statistics
```bash
curl http://localhost:8000/stats

# Expected:
# {
#   "total_connections": 1,
#   "online_users": 1,
#   "total_rooms": 1
# }
```

## Production Checklist

### Security (OWASP)
- [ ] A01: JWT authentication required
- [ ] A02: Use WSS (WebSocket Secure) in production
- [ ] A04: Rate limiting (100 msg/min per user, 10 conn/hour per IP)
- [ ] A05: Connection limit per user (5 max)
- [ ] CORS: Whitelist allowed origins
- [ ] SSL/TLS: Valid certificates

### Scaling
- [ ] Redis Cluster (3+ nodes for high availability)
- [ ] Kubernetes deployment (10+ pods)
- [ ] Horizontal Pod Autoscaler (scale at 70% CPU)
- [ ] Load balancer (AWS ALB or NGINX)
- [ ] Session affinity (optional, helps with debugging)

### Monitoring
- [ ] Prometheus metrics (connections, messages, latency)
- [ ] Grafana dashboards
- [ ] PagerDuty alerts (>1% connection drop rate)
- [ ] Distributed tracing (Jaeger)
- [ ] Centralized logging (ELK stack)

### Operations
- [ ] Auto-reconnect logic (client-side)
- [ ] Message queuing for offline users
- [ ] Heartbeat/ping every 30 seconds
- [ ] Graceful shutdown (close connections cleanly)
- [ ] Blue-green deployment (zero downtime)

## Client SDK Example

```javascript
class WebSocketClient {
    constructor(url, token) {
        this.url = url;
        this.token = token;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.pingInterval = null;
    }

    connect() {
        this.ws = new WebSocket(`${this.url}?token=${this.token}`);

        this.ws.onopen = () => {
            console.log('Connected');
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000;

            // Ping every 30 seconds
            this.pingInterval = setInterval(() => {
                this.send({ type: 'ping' });
            }, 30000);
        };

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
        };

        this.ws.onclose = () => {
            console.log('Disconnected');
            clearInterval(this.pingInterval);

            // Auto-reconnect with exponential backoff
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                setTimeout(() => {
                    this.reconnectAttempts++;
                    this.reconnectDelay *= 2;
                    console.log(`Reconnecting (attempt ${this.reconnectAttempts})...`);
                    this.connect();
                }, this.reconnectDelay);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    send(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    joinRoom(roomId) {
        this.send({
            type: 'join_room',
            payload: { room_id: roomId }
        });
    }

    sendRoomMessage(roomId, message) {
        this.send({
            type: 'room_message',
            payload: { room_id: roomId, message: message }
        });
    }

    sendDirectMessage(userId, message) {
        this.send({
            type: 'chat',
            payload: { to: userId, message: message }
        });
    }

    handleMessage(message) {
        switch (message.type) {
            case 'pong':
                console.log('Pong received');
                break;
            case 'chat':
                this.onChatMessage(message);
                break;
            case 'room_message':
                this.onRoomMessage(message);
                break;
            case 'user_joined':
                this.onUserJoined(message);
                break;
            case 'typing':
                this.onTyping(message);
                break;
            default:
                console.log('Unknown message type:', message.type);
        }
    }

    // Override these in your app
    onChatMessage(message) {}
    onRoomMessage(message) {}
    onUserJoined(message) {}
    onTyping(message) {}
}

// Usage
const ws = new WebSocketClient('wss://api.example.com/ws', 'your-jwt-token');
ws.connect();

ws.onRoomMessage = (message) => {
    console.log(`${message.from}: ${message.message}`);
};

ws.joinRoom('room-123');
ws.sendRoomMessage('room-123', 'Hello!');
```

## Kubernetes Deployment

```yaml
# websocket-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: websocket-server
spec:
  replicas: 10
  selector:
    matchLabels:
      app: websocket
  template:
    metadata:
      labels:
        app: websocket
    spec:
      containers:
      - name: websocket
        image: your-registry/websocket-server:latest
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_HOST
          value: "redis-cluster"
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: websocket-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10

---
# Auto-scaling
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: websocket-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: websocket-server
  minReplicas: 10
  maxReplicas: 100
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70

---
# Service
apiVersion: v1
kind: Service
metadata:
  name: websocket-service
spec:
  type: LoadBalancer
  selector:
    app: websocket
  ports:
  - port: 443
    targetPort: 8000
    protocol: TCP
```

## Troubleshooting

### Connection Refused
```
Error: WebSocket connection failed
Solution: Check server is running (uvicorn app:app)
```

### Invalid Token
```
Error: 1008 - Unauthorized
Solution: Verify JWT token is valid and not expired
```

### Rate Limit Exceeded
```
Error: Message rate limit exceeded
Solution: Wait 1 minute or increase MESSAGE_RATE_LIMIT
```

### Redis Connection Error
```
Error: redis.exceptions.ConnectionError
Solution: Check Redis is running (redis-cli ping)
```

### Too Many Connections
```
Error: 1008 - Too many connections
Solution: User has 5+ connections, close some or increase MAX_CONNECTIONS_PER_USER
```

## Cost (100K Connections)

```
Multi-Server + Redis:
- 10 servers (EC2 t3.medium):  $300/month
- Redis Cluster (3 nodes):     $150/month
- Load Balancer (ALB):         $30/month
- Bandwidth (10TB):            $20/month
Total: $500/month

vs Pusher: $2,000/month (100K connections)
Savings: $1,500/month = $18,000/year
```

## Scalability Targets

| Connections | Servers | Redis Nodes | Monthly Cost |
|------------|---------|-------------|--------------|
| 10K | 1 | 1 | $100 |
| 100K | 10 | 3 | $500 |
| 1M | 100 | 5 | $5,000 |

**Performance Targets**:
- Connection success rate: > 99.9%
- Message latency (p95): < 100ms
- Reconnect time: < 2 seconds
- Uptime: 99.99%

## Next Steps

1. Read full guide: `.claude/skills/websocket-universal/SKILL.md`
2. Review 3D decision matrix: `3D-DECISION-MATRIX.md`
3. Set up monitoring in Prometheus + Grafana
4. Load test with k6 or Locust (10K concurrent connections)
5. Configure auto-scaling in Kubernetes

**Total setup time: 25 minutes** ⏱️
**Cost: $500/month** (100K connections) 💰
**Scalability: 1M+ connections** ✅
**Latency: <100ms** ⚡

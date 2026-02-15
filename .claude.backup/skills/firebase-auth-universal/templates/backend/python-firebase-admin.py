"""
Firebase Authentication Backend (Python/FastAPI)
Complete production-ready implementation with Firebase Admin SDK
"""

import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from functools import wraps

import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import asyncpg
from asyncpg.pool import Pool

# =============================================================================
# CONFIGURATION
# =============================================================================

# Environment variables
FIREBASE_CREDENTIALS_PATH = os.getenv("FIREBASE_CREDENTIALS_PATH", "firebase-credentials.json")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/dbname")

# Initialize Firebase Admin SDK
cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
firebase_admin.initialize_app(cred)

# Initialize FastAPI
app = FastAPI(title="Firebase Auth API", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Update with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security scheme
security = HTTPBearer()

# Database connection pool
db_pool: Optional[Pool] = None

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# DATABASE CONNECTION
# =============================================================================

@app.on_event("startup")
async def startup():
    """Initialize database connection pool on startup"""
    global db_pool
    try:
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
        logger.info("Database connection pool created")
    except Exception as e:
        logger.error(f"Failed to create database pool: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    """Close database connection pool on shutdown"""
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database connection pool closed")

async def get_db():
    """Dependency to get database connection"""
    async with db_pool.acquire() as conn:
        yield conn

# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    display_name: Optional[str] = None
    phone_number: Optional[str] = None

class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    photo_url: Optional[str] = None
    phone_number: Optional[str] = None

class CustomClaims(BaseModel):
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    permissions: Optional[list] = None

class FirebaseUser(BaseModel):
    uid: str
    email: Optional[str] = None
    email_verified: bool = False
    phone_number: Optional[str] = None
    display_name: Optional[str] = None
    photo_url: Optional[str] = None
    disabled: bool = False
    custom_claims: Optional[Dict[str, Any]] = None

# =============================================================================
# FIREBASE TOKEN VERIFICATION
# =============================================================================

async def verify_firebase_token(id_token: str) -> Dict[str, Any]:
    """
    Verify Firebase ID token and return decoded claims

    Args:
        id_token: Firebase ID token from client

    Returns:
        Dict containing user claims (uid, email, etc.)

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        # Verify the ID token
        decoded_token = firebase_auth.verify_id_token(id_token)

        # Optionally check if token is not revoked
        # decoded_token = firebase_auth.verify_id_token(id_token, check_revoked=True)

        return {
            'uid': decoded_token['uid'],
            'email': decoded_token.get('email'),
            'email_verified': decoded_token.get('email_verified', False),
            'phone_number': decoded_token.get('phone_number'),
            'display_name': decoded_token.get('name'),
            'photo_url': decoded_token.get('picture'),
            'auth_time': decoded_token.get('auth_time'),
            'custom_claims': {k: v for k, v in decoded_token.items()
                            if k not in ['uid', 'email', 'email_verified', 'phone_number',
                                       'name', 'picture', 'auth_time', 'iss', 'aud', 'exp', 'iat', 'sub']}
        }
    except firebase_auth.InvalidIdTokenError:
        logger.warning(f"Invalid ID token provided")
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except firebase_auth.ExpiredIdTokenError:
        logger.warning(f"Expired ID token provided")
        raise HTTPException(status_code=401, detail="Token has expired")
    except firebase_auth.RevokedIdTokenError:
        logger.warning(f"Revoked ID token provided")
        raise HTTPException(status_code=401, detail="Token has been revoked")
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: asyncpg.Connection = Depends(get_db)
) -> Dict[str, Any]:
    """
    Dependency to get current authenticated user

    Usage:
        @app.get("/protected")
        async def protected_route(user: dict = Depends(get_current_user)):
            return {"user_id": user["id"]}
    """
    # Extract token from Bearer header
    id_token = credentials.credentials

    # Verify Firebase token
    firebase_user = await verify_firebase_token(id_token)

    # Sync user to database and get internal user ID
    user = await sync_firebase_user_to_db(db, firebase_user)

    # Log authentication event
    await log_auth_event(
        db,
        user_id=user['id'],
        firebase_uid=firebase_user['uid'],
        event_type='token_verify',
        event_status='success'
    )

    return user

async def require_role(required_role: str):
    """
    Dependency factory to require specific role

    Usage:
        @app.get("/admin")
        async def admin_route(user: dict = Depends(require_role("admin"))):
            return {"message": "Admin access"}
    """
    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        if user.get('role') != required_role:
            raise HTTPException(status_code=403, detail=f"Requires {required_role} role")
        return user
    return role_checker

# =============================================================================
# DATABASE SYNC FUNCTIONS
# =============================================================================

async def sync_firebase_user_to_db(
    db: asyncpg.Connection,
    firebase_user: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Sync Firebase user to PostgreSQL database
    Creates or updates user record

    Args:
        db: Database connection
        firebase_user: Decoded Firebase token data

    Returns:
        Database user record
    """
    try:
        # Use the helper function from our schema
        user_id = await db.fetchval(
            """
            SELECT upsert_firebase_user($1, $2, $3, $4, $5, $6, $7)
            """,
            firebase_user['uid'],
            firebase_user.get('email'),
            firebase_user.get('email_verified', False),
            firebase_user.get('phone_number'),
            firebase_user.get('display_name'),
            firebase_user.get('photo_url'),
            firebase_user.get('provider_id', 'firebase')
        )

        # Fetch complete user record
        user = await db.fetchrow(
            """
            SELECT * FROM get_user_by_firebase_uid($1)
            """,
            firebase_user['uid']
        )

        return dict(user)
    except Exception as e:
        logger.error(f"Database sync error: {e}")
        raise HTTPException(status_code=500, detail="Failed to sync user data")

async def log_auth_event(
    db: asyncpg.Connection,
    user_id: Optional[str],
    firebase_uid: str,
    event_type: str,
    event_status: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    error_message: Optional[str] = None
):
    """Log authentication event to audit log"""
    try:
        await db.execute(
            """
            INSERT INTO auth_audit_log
            (user_id, firebase_uid, event_type, event_status, ip_address, user_agent, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            user_id, firebase_uid, event_type, event_status,
            ip_address, user_agent, error_message
        )
    except Exception as e:
        logger.error(f"Failed to log auth event: {e}")

# =============================================================================
# USER MANAGEMENT ENDPOINTS
# =============================================================================

@app.post("/auth/users", response_model=FirebaseUser)
async def create_user(
    user_data: UserCreate,
    db: asyncpg.Connection = Depends(get_db)
):
    """
    Create a new Firebase user
    Admin-only endpoint for creating users programmatically
    """
    try:
        # Create Firebase user
        firebase_user = firebase_auth.create_user(
            email=user_data.email,
            password=user_data.password,
            display_name=user_data.display_name,
            phone_number=user_data.phone_number,
            email_verified=False
        )

        # Sync to database
        await sync_firebase_user_to_db(db, {
            'uid': firebase_user.uid,
            'email': firebase_user.email,
            'email_verified': firebase_user.email_verified,
            'phone_number': firebase_user.phone_number,
            'display_name': firebase_user.display_name,
            'photo_url': firebase_user.photo_url
        })

        # Log event
        await log_auth_event(
            db,
            user_id=None,
            firebase_uid=firebase_user.uid,
            event_type='user_created',
            event_status='success'
        )

        return FirebaseUser(
            uid=firebase_user.uid,
            email=firebase_user.email,
            email_verified=firebase_user.email_verified,
            phone_number=firebase_user.phone_number,
            display_name=firebase_user.display_name,
            photo_url=firebase_user.photo_url,
            disabled=firebase_user.disabled
        )
    except firebase_auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail="Email already exists")
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/auth/users/{uid}", response_model=FirebaseUser)
async def get_user(uid: str):
    """Get Firebase user by UID"""
    try:
        firebase_user = firebase_auth.get_user(uid)
        return FirebaseUser(
            uid=firebase_user.uid,
            email=firebase_user.email,
            email_verified=firebase_user.email_verified,
            phone_number=firebase_user.phone_number,
            display_name=firebase_user.display_name,
            photo_url=firebase_user.photo_url,
            disabled=firebase_user.disabled,
            custom_claims=firebase_user.custom_claims
        )
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Get user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/auth/users/{uid}", response_model=FirebaseUser)
async def update_user(
    uid: str,
    user_data: UserUpdate,
    db: asyncpg.Connection = Depends(get_db)
):
    """Update Firebase user"""
    try:
        # Update Firebase user
        firebase_user = firebase_auth.update_user(
            uid,
            display_name=user_data.display_name,
            photo_url=user_data.photo_url,
            phone_number=user_data.phone_number
        )

        # Sync to database
        await sync_firebase_user_to_db(db, {
            'uid': firebase_user.uid,
            'email': firebase_user.email,
            'email_verified': firebase_user.email_verified,
            'phone_number': firebase_user.phone_number,
            'display_name': firebase_user.display_name,
            'photo_url': firebase_user.photo_url
        })

        return FirebaseUser(
            uid=firebase_user.uid,
            email=firebase_user.email,
            email_verified=firebase_user.email_verified,
            phone_number=firebase_user.phone_number,
            display_name=firebase_user.display_name,
            photo_url=firebase_user.photo_url,
            disabled=firebase_user.disabled
        )
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Update user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/auth/users/{uid}")
async def delete_user(
    uid: str,
    db: asyncpg.Connection = Depends(get_db)
):
    """Delete Firebase user"""
    try:
        # Delete from Firebase
        firebase_auth.delete_user(uid)

        # Soft delete in database
        await db.execute(
            """
            UPDATE users
            SET deleted_at = NOW(), status = 'deleted'
            WHERE firebase_uid = $1
            """,
            uid
        )

        # Log event
        await log_auth_event(
            db,
            user_id=None,
            firebase_uid=uid,
            event_type='user_deleted',
            event_status='success'
        )

        return {"message": "User deleted successfully"}
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# =============================================================================
# CUSTOM CLAIMS (ROLES & PERMISSIONS)
# =============================================================================

@app.post("/auth/users/{uid}/claims")
async def set_custom_claims(
    uid: str,
    claims: CustomClaims,
    db: asyncpg.Connection = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """
    Set custom claims for a user (admin only)
    Custom claims are included in the Firebase ID token
    """
    try:
        # Prepare claims dict
        claims_dict = claims.dict(exclude_none=True)

        # Set custom claims in Firebase
        firebase_auth.set_custom_user_claims(uid, claims_dict)

        # Update in database
        await db.execute(
            """
            UPDATE users
            SET custom_claims = $1,
                role = COALESCE($2, role),
                updated_at = NOW()
            WHERE firebase_uid = $3
            """,
            claims_dict,
            claims.role,
            uid
        )

        # Log event
        await log_auth_event(
            db,
            user_id=current_user['id'],
            firebase_uid=uid,
            event_type='claims_updated',
            event_status='success'
        )

        return {"message": "Custom claims updated successfully"}
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Set claims error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# =============================================================================
# TOKEN MANAGEMENT
# =============================================================================

@app.post("/auth/tokens/revoke/{uid}")
async def revoke_user_tokens(
    uid: str,
    db: asyncpg.Connection = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """
    Revoke all refresh tokens for a user
    Forces user to re-authenticate
    """
    try:
        # Revoke all refresh tokens
        firebase_auth.revoke_refresh_tokens(uid)

        # Revoke sessions in database
        await db.execute(
            """
            UPDATE user_sessions
            SET revoked_at = NOW()
            WHERE user_id = (SELECT id FROM users WHERE firebase_uid = $1)
              AND revoked_at IS NULL
            """,
            uid
        )

        # Log event
        await log_auth_event(
            db,
            user_id=current_user['id'],
            firebase_uid=uid,
            event_type='tokens_revoked',
            event_status='success'
        )

        return {"message": "User tokens revoked successfully"}
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Revoke tokens error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/tokens/verify")
async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Verify Firebase ID token (for testing)"""
    id_token = credentials.credentials
    decoded = await verify_firebase_token(id_token)
    return decoded

# =============================================================================
# PROTECTED ROUTE EXAMPLES
# =============================================================================

@app.get("/me")
async def get_current_user_profile(user: dict = Depends(get_current_user)):
    """Get current authenticated user profile"""
    return {
        "id": user["id"],
        "firebase_uid": user["firebase_uid"],
        "email": user["email"],
        "display_name": user["display_name"],
        "role": user["role"],
        "subscription_tier": user["subscription_tier"]
    }

@app.get("/admin/dashboard")
async def admin_dashboard(user: dict = Depends(require_role("admin"))):
    """Admin-only route"""
    return {"message": f"Welcome to admin dashboard, {user['display_name']}"}

# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "firebase-auth-backend"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

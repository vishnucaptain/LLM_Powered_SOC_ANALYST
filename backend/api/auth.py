"""
auth.py
-------
JWT authentication module for FastAPI.
Provides token generation, validation, and dependency injection for secure endpoints.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

logger = logging.getLogger(__name__)

# Use PyJWT for production reliability
try:
    import jwt
    JWT_LIBRARY = "PyJWT"
except ImportError:
    jwt = None
    JWT_LIBRARY = None


class JWTConfig:
    """JWT configuration settings — all values loaded from .env."""
    
    # Must be set in .env as JWT_SECRET_KEY — no hardcoded fallback for security
    SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    
    @classmethod
    def validate(cls):
        """Validate configuration."""
        if not cls.SECRET_KEY:
            raise ValueError("JWT_SECRET_KEY is not set")
        if cls.SECRET_KEY == "your-super-secret-key-change-in-production":
            logger.warning("⚠️  Using default JWT secret key. Change JWT_SECRET_KEY in production!")


class TokenData:
    """JWT token payload."""
    
    def __init__(self, user_id: str, username: str = None, scopes: list = None):
        self.user_id = user_id
        self.username = username or user_id
        self.scopes = scopes or ["read"]
        self.issued_at = datetime.now(timezone.utc)
        self.expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=JWTConfig.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for token encoding."""
        return {
            "sub": self.user_id,
            "username": self.username,
            "scopes": self.scopes,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenData":
        """Create from decoded token."""
        token_data = cls(
            user_id=data.get("sub"),
            username=data.get("username"),
            scopes=data.get("scopes", ["read"])
        )
        # Override issued_at and expires_at with values from token
        token_data.issued_at = datetime.fromtimestamp(data.get("iat", 0), tz=timezone.utc)
        token_data.expires_at = datetime.fromtimestamp(data.get("exp", 0), tz=timezone.utc)
        return token_data


class JWTHandler:
    """
    Handles JWT token creation and validation.
    Uses PyJWT for production reliability and security.
    """
    
    def __init__(self):
        JWTConfig.validate()
        
        if JWT_LIBRARY is None:
            raise RuntimeError(
                "PyJWT not installed. Install with: pip install PyJWT"
            )
        
        self.secret_key = JWTConfig.SECRET_KEY
        self.algorithm = JWTConfig.ALGORITHM
    
    def create_token(self, user_id: str, username: str = None) -> str:
        """
        Create a new JWT token.
        
        Args:
            user_id: Unique user identifier
            username: Optional username for logging
        
        Returns:
            Encoded JWT token string
        """
        token_data = TokenData(user_id=user_id, username=username)
        payload = token_data.to_dict()
        
        try:
            encoded_jwt = jwt.encode(
                payload,
                self.secret_key,
                algorithm=self.algorithm
            )
            logger.info(f"Token created for user: {user_id}")
            return encoded_jwt
        except Exception as e:
            logger.error(f"Token creation error: {e}")
            raise
    
    def verify_token(self, token: str) -> TokenData:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token string
        
        Returns:
            TokenData with decoded claims
        
        Raises:
            HTTPException on invalid/expired token
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            user_id = payload.get("sub")
            
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: missing user ID",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            token_data = TokenData.from_dict(payload)
            logger.debug(f"Token verified for user: {user_id}")
            return token_data
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication error",
                headers={"WWW-Authenticate": "Bearer"},
            )


# Global JWT handler instance
jwt_handler = JWTHandler()

# Security scheme for FastAPI documentation
security = HTTPBearer(description="JWT Bearer Token")


async def get_current_user(
    credentials = Depends(security),
) -> TokenData:
    """
    Dependency for protected endpoints.
    Validates JWT token and returns user data.
    
    Usage in endpoints:
        @app.get("/protected")
        async def protected_endpoint(current_user: TokenData = Depends(get_current_user)):
            return {"user_id": current_user.user_id}
    """
    token = credentials.credentials
    return jwt_handler.verify_token(token)


async def get_current_user_optional(
    credentials: Optional = Depends(security),
) -> Optional[TokenData]:
    """
    Optional dependency for endpoints that work with or without auth.
    """
    if credentials is None:
        return None
    
    try:
        return jwt_handler.verify_token(credentials.credentials)
    except HTTPException:
        return None


class AuthService:
    """
    Service for user authentication and token management.
    In production, this would validate against a user database.
    """
    
    # Demo users (in production, use a proper user database)
    VALID_USERS = {
        "analyst": "password123",  # Change in production!
        "admin": "admin123",
        "soc_team": "team123",
    }
    
    @staticmethod
    def authenticate_user(username: str, password: str) -> Optional[str]:
        """
        Authenticate user credentials.
        In production, query actual user database with bcrypt hashing.
        
        Args:
            username: User's username
            password: User's password
        
        Returns:
            User ID if authenticated, None otherwise
        """
        # Demo validation (DON'T USE IN PRODUCTION)
        if username in AuthService.VALID_USERS:
            if AuthService.VALID_USERS[username] == password:
                logger.info(f"User authenticated: {username}")
                return username
        
        logger.warning(f"Authentication failed for user: {username}")
        return None
    
    @staticmethod
    def create_access_token(user_id: str, username: str = None) -> str:
        """Create JWT token for authenticated user."""
        return jwt_handler.create_token(user_id, username)


# Example token response models (for FastAPI schema)
class TokenResponse:
    """Response format for token endpoint."""
    
    def __init__(self, access_token: str, token_type: str = "bearer"):
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = JWTConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }


if __name__ == "__main__":
    # Test JWT functionality
    print("Testing JWT Handler...\n")
    
    # Create token
    handler = JWTHandler()
    token = handler.create_token(user_id="analyst1", username="john_analyst")
    print(f"Generated Token: {token[:50]}...\n")
    
    # Verify token
    try:
        decoded = handler.verify_token(token)
        print(f"Token verified successfully!")
        print(f"User ID: {decoded.user_id}")
        print(f"Username: {decoded.username}")
        print(f"Scopes: {decoded.scopes}")
    except Exception as e:
        print(f"Error: {e}")

"""
Firebase Authentication Utilities
Handles Firebase Admin SDK initialization and JWT token verification
"""

import os
import firebase_admin
from firebase_admin import credentials, auth
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import logging
from sqlalchemy.ext.asyncio import AsyncSession

# Import get_db directly - no circular dependency
from app.utils.database import get_db

logger = logging.getLogger(__name__)

# Initialize Firebase Admin SDK
_firebase_app: Optional[firebase_admin.App] = None

def initialize_firebase_admin():
    """
    Initialize Firebase Admin SDK with service account key
    
    The service account key file should be located at:
    - backend/serviceAccountKey.json (default)
    - Or path specified in FIREBASE_SERVICE_ACCOUNT_KEY environment variable
    """
    global _firebase_app
    
    if _firebase_app is not None:
        logger.info("Firebase Admin SDK already initialized")
        return _firebase_app
    
    try:
        # Get path to service account key
        service_account_key_path = os.getenv(
            "FIREBASE_SERVICE_ACCOUNT_KEY",
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "serviceAccountKey.json")
        )
        
        # Check if file exists
        if not os.path.exists(service_account_key_path):
            logger.error(f"Firebase service account key not found at: {service_account_key_path}")
            raise FileNotFoundError(f"Firebase service account key not found at: {service_account_key_path}")
        
        # Initialize Firebase Admin SDK
        cred = credentials.Certificate(service_account_key_path)
        _firebase_app = firebase_admin.initialize_app(cred)
        
        logger.info("✅ Firebase Admin SDK initialized successfully")
        return _firebase_app
        
    except Exception as e:
        logger.error(f"Failed to initialize Firebase Admin SDK: {e}")
        raise


def get_firebase_app() -> firebase_admin.App:
    """
    Get the initialized Firebase Admin app instance
    
    Returns:
        Firebase Admin app instance
        
    Raises:
        RuntimeError: If Firebase Admin SDK is not initialized
    """
    if _firebase_app is None:
        raise RuntimeError("Firebase Admin SDK not initialized. Call initialize_firebase_admin() first.")
    return _firebase_app


async def verify_firebase_token(token: str) -> dict:
    """
    Verify Firebase ID token and return decoded token claims
    
    Args:
        token: Firebase ID token (JWT) string
        
    Returns:
        dict: Decoded token claims including uid, email, etc.
        
    Raises:
        HTTPException: If token is invalid, expired, or verification fails
    """
    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(token)
        
        # Return the decoded token claims
        return {
            "uid": decoded_token["uid"],
            "email": decoded_token.get("email"),
            "email_verified": decoded_token.get("email_verified", False),
            "name": decoded_token.get("name"),
            "firebase_claims": decoded_token
        }
        
    except auth.InvalidIdTokenError:
        logger.warning("Invalid Firebase ID token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    except auth.ExpiredIdTokenError:
        logger.warning("Expired Firebase ID token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired"
        )
    except auth.RevokedIdTokenError:
        logger.warning("Revoked Firebase ID token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked"
        )
    except Exception as e:
        logger.error(f"Error verifying Firebase token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to verify authentication token"
        )


# HTTPBearer security scheme for FastAPI
# Use auto_error=False to handle missing headers manually with proper 401 status
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> dict:
    """
    FastAPI dependency to get the current authenticated user
    
    Verifies Firebase token and checks if user exists in database and is enabled
    
    Usage:
        @router.get("/protected")
        async def protected_route(current_user: dict = Depends(get_current_user)):
            uid = current_user["uid"]
            ...
    
    Args:
        credentials: HTTPAuthorizationCredentials from the Authorization header
        db: Database session (injected by FastAPI)
        
    Returns:
        dict: Decoded token claims with uid, email, etc. + user data from database
        
    Raises:
        HTTPException: If token is missing, invalid, user doesn't exist, or user is disabled
            - 401 Unauthorized if Authorization header is missing
            - 401 Unauthorized if token is invalid/expired
            - 404 Not Found if user doesn't exist in database
            - 403 Forbidden if user account is disabled
    """
    if credentials is None:
        logger.warning("Missing Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify Firebase token
    token = credentials.credentials
    user_info = await verify_firebase_token(token)
    
    # Check if user exists in database and is enabled
    # Import here to avoid circular dependencies
    from app.services.user_service import get_user_service
    
    try:
        # Get user from database using the provided session
        user_service = get_user_service(db)
        db_users = await user_service.get_all_users()
        if db_users is None:
            logger.warning(f"No users found in database")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No users found in database. Please contact administrator."
            )
        
        if len(db_users) == 0:
            logger.warning(f"No users found in database")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No users found in database. Please contact administrator."
            )
        
        for db_user in db_users:
            print(db_user)
        
        if db_user is None:
            logger.warning(f"User with uid '{user_info['uid']}' not found in database")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User account not found. Please contact administrator."
            )
        db_user = await user_service.get_user(user_info["uid"])
        
        if db_user is None:
            logger.warning(f"User with uid '{user_info['uid']}' not found in database")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User account not found. Please contact administrator."
            )
        
        if not db_user.enabled:
            logger.warning(f"User with uid '{user_info['uid']}' account is disabled")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is disabled. Please contact administrator."
            )
        
        # Add database user info to the response
        user_info["role"] = db_user.role
        user_info["enabled"] = db_user.enabled
        user_info["created_at"] = db_user.created_at.isoformat() if db_user.created_at else None
        user_info["updated_at"] = db_user.updated_at.isoformat() if db_user.updated_at else None
        
        return user_info
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking user in database: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify user account. Please try again."
        )


# Optional: Create a dependency that can be used to optionally require auth
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
) -> Optional[dict]:
    """
    FastAPI dependency to optionally get the current authenticated user
    
    Returns None if no token is provided, otherwise verifies and returns user info
    
    Usage:
        @router.get("/public-or-protected")
        async def route(current_user: Optional[dict] = Depends(get_current_user_optional)):
            if current_user:
                # User is authenticated
                ...
            else:
                # Public access
                ...
    
    Args:
        credentials: Optional HTTPAuthorizationCredentials from the Authorization header
        
    Returns:
        Optional[dict]: Decoded token claims if authenticated, None otherwise
    """
    if credentials is None:
        return None
    
    try:
        token = credentials.credentials
        return await verify_firebase_token(token)
    except HTTPException:
        return None


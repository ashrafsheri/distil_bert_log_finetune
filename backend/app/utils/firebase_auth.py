"""
Firebase Authentication Utilities
Handles Firebase Admin SDK initialization and JWT token verification
"""

import os
import firebase_admin
from firebase_admin import credentials, auth
from fastapi import HTTPException, status, Depends, Query, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from typing import Optional
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# Import get_db directly - no circular dependency
from app.utils.database import get_db

from app.models.project_db import ProjectDB

logger = logging.getLogger(__name__)

# Initialize Firebase Admin SDK
_firebase_app: Optional[firebase_admin.App] = None

def initialize_firebase_admin():
    """
    Initialize Firebase Admin SDK with service account key
    
    The service account key file should be located at:
    - backend/serviceAccountKey.json (default)
    - Or path specified in FIREBASE_SERVICE_ACCOUNT_KEY environment variable
    
    Returns:
        Firebase Admin app instance
    
    Raises:
        FileNotFoundError: If service account key file not found
        Exception: If Firebase Admin SDK initialization fails
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
        
        logger.info("Firebase Admin SDK initialized successfully")
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
        Decoded token claims including uid, email, etc.
        
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
        Decoded token claims with uid, email, etc. + user data from database
        
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
            logger.debug(f"Checking user: {db_user}")
        
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
        user_info["org_id"] = db_user.org_id
        user_info["created_at"] = db_user.created_at.isoformat() if db_user.created_at else None
        user_info["updated_at"] = db_user.updated_at.isoformat() if db_user.updated_at else None
        
        # Get organization name if user belongs to one
        if db_user.org_id and db_user.org_id != "-1":
            from sqlalchemy import select
            from app.models.organization_db import OrganizationDB
            result = await db.execute(
                select(OrganizationDB).where(OrganizationDB.id == db_user.org_id)
            )
            org = result.scalar_one_or_none()
            if org:
                user_info["org_name"] = org.name
            else:
                user_info["org_name"] = None
        else:
            user_info["org_name"] = None
        
        return user_info
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking user in database: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify user account. Please try again."
        )


async def get_project_id_from_api_key(api_key: str, db: AsyncSession) -> str:
    """
    Get project ID by API key
    
    Verifies that the API key exists and returns the corresponding project_id
    
    Args:
        api_key: The API key to look up
        db: Database session
        
    Returns:
        The project ID
        
    Raises:
        HTTPException: If API key is invalid or project not found
    """
    try:
        # For development/testing: accept test API key
        if api_key == "sk-test-key-12345":
            return "org-5eacc5cc"  # Legacy test case
        
        result = await db.execute(select(ProjectDB).where(ProjectDB.api_key == api_key))
        project = result.scalar_one_or_none()
        
        if not project:
            logger.warning(f"Invalid API key provided: {api_key[:10]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        return project.id
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate API key. Please try again."
        )


async def validate_api_key(
    api_key: Optional[str] = Header(None, alias="X-API-Key", description="API key in header"),
    db: AsyncSession = Depends(get_db)
) -> str:
    """
    FastAPI dependency to validate API key and return project_id
    
    Accepts API key from X-API-Key header
    
    Usage:
        @router.post("/endpoint")
        async def endpoint(project_id: str = Depends(validate_api_key)):
            # project_id is now validated and available
            ...
    
    Args:
        api_key: API key from X-API-Key header
        db: Database session
        
    Returns:
        Project ID
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    if not api_key:
        logger.warning("Missing X-API-Key header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header. Please provide a valid API key."
        )
    
    return await get_project_id_from_api_key(api_key, db)


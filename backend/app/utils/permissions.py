"""
Permission Utilities
FastAPI dependencies and utilities for role-based access control
"""

from fastapi import HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.utils.database import get_db
from app.utils.firebase_auth import get_current_user
from app.services.permission_service import get_permission_service

logger = logging.getLogger(__name__)


def check_permission(api_path: str, http_method: str):
    """
    Factory function to create a permission check dependency
    
    This function creates a FastAPI dependency that:
    1. First verifies JWT token (via get_current_user)
    2. Then checks if the user's role has permission to access the API endpoint
    
    Args:
        api_path: API path to check permission for (e.g., "/api/v1/users/create")
        http_method: HTTP method to check (GET, POST, PUT, PATCH, DELETE)
        
    Returns:
        FastAPI dependency function that checks both JWT and permissions
    """
    async def permission_checker(
        current_user: dict = Depends(get_current_user),  # First: Verify JWT token
        db: AsyncSession = Depends(get_db)
    ):
        """
        Permission checker dependency
        
        This dependency performs two checks in sequence:
        1. JWT Token Verification: get_current_user verifies the Firebase JWT token
           and checks if user exists in database and is enabled
        2. Role Permission Check: Verifies if the user's role has permission
           to access the specified API endpoint
        
        Raises:
            HTTPException: 
                - 401 Unauthorized if JWT token is invalid or user not found/disabled
                - 403 Forbidden if user doesn't have permission for this endpoint
        """
        # JWT token and user existence already verified by get_current_user dependency
        
        # Second check: Verify role permissions
        user_role = current_user.get("role")
        
        if not user_role:
            logger.warning(f"User {current_user.get('uid')} has no role assigned")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User role not found. Access denied."
            )
        
        permission_service = get_permission_service(db)
        has_permission = await permission_service.check_permission(
            role=user_role,
            api_path=api_path,
            http_method=http_method
        )
        
        if not has_permission:
            logger.warning(
                f"User {current_user.get('uid')} with role {user_role} "
                f"attempted to access {http_method} {api_path} without permission"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You don't have permission to perform {http_method} on {api_path}"
            )
        
        return current_user
    
    return permission_checker


async def has_permission(
    role: str,
    api_path: str,
    http_method: str,
    db: AsyncSession
) -> bool:
    """
    Check if a role has permission to access an API endpoint
    
    Args:
        role: User role (admin, manager, employee)
        api_path: API path
        http_method: HTTP method
        db: Database session
        
    Returns:
        True if role has permission, False otherwise
    """
    permission_service = get_permission_service(db)
    return await permission_service.check_permission(role, api_path, http_method)


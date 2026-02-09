"""
Permission Service
Handles role-based access control (RBAC) permission checking
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
import logging

from app.models.role_permission_db import RolePermissionDB, HTTPMethodEnum
from app.models.user_db import RoleEnum

logger = logging.getLogger(__name__)


class PermissionService:
    """
    Permission Service
    Service class for permission checking and role-based access control
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize PermissionService
        
        Args:
            db: Async database session
            
        Returns:
            None
        """
        self.db = db
    
    async def check_permission(
        self,
        role: str,
        api_path: str,
        http_method: str
    ) -> bool:
        """
        Check if a role has permission to access a specific API endpoint
        
        Args:
            role: User role (admin, manager, employee)
            api_path: API path (e.g., "/api/v1/users/create")
            http_method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            
        Returns:
            True if role has permission, False otherwise
        """
        try:
            # Convert string role to RoleEnum
            try:
                role_enum = RoleEnum[role.upper()]
            except (KeyError, AttributeError):
                logger.warning(f"Invalid role: {role}")
                return False
            
            # Convert string http_method to HTTPMethodEnum
            try:
                method_enum = HTTPMethodEnum[http_method.upper()]
            except (KeyError, AttributeError):
                logger.warning(f"Invalid HTTP method: {http_method}")
                return False
            
            # Query permission
            result = await self.db.execute(
                select(RolePermissionDB).where(
                    RolePermissionDB.role == role_enum,
                    RolePermissionDB.api_path == api_path,
                    RolePermissionDB.http_method == method_enum
                )
            )
            permission = result.scalar_one_or_none()
            
            return permission is not None
            
        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False
    
    async def add_permission(
        self,
        role: str,
        api_path: str,
        http_method: str
    ) -> bool:
        """
        Add a permission for a role
        
        Args:
            role: User role
            api_path: API path
            http_method: HTTP method
            
        Returns:
            True if permission was added, False if it already exists
        """
        try:
            # Check if permission already exists
            has_permission = await self.check_permission(role, api_path, http_method)
            if has_permission:
                return False
            
            # Convert to enums
            role_enum = RoleEnum[role.upper()]
            method_enum = HTTPMethodEnum[http_method.upper()]
            
            # Create new permission
            permission = RolePermissionDB(
                role=role_enum,
                api_path=api_path,
                http_method=method_enum
            )
            
            self.db.add(permission)
            await self.db.flush()
            
            logger.info(f"Added permission: {role} -> {http_method} {api_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding permission: {e}")
            await self.db.rollback()
            raise
    
    async def remove_permission(
        self,
        role: str,
        api_path: str,
        http_method: str
    ) -> bool:
        """
        Remove a permission for a role
        
        Args:
            role: User role
            api_path: API path
            http_method: HTTP method
            
        Returns:
            True if permission was removed, False if it didn't exist
        """
        try:
            role_enum = RoleEnum[role.upper()]
            method_enum = HTTPMethodEnum[http_method.upper()]
            
            result = await self.db.execute(
                select(RolePermissionDB).where(
                    RolePermissionDB.role == role_enum,
                    RolePermissionDB.api_path == api_path,
                    RolePermissionDB.http_method == method_enum
                )
            )
            permission = result.scalar_one_or_none()
            
            if permission:
                await self.db.delete(permission)
                await self.db.flush()
                logger.info(f"Removed permission: {role} -> {http_method} {api_path}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error removing permission: {e}")
            await self.db.rollback()
            raise


def get_permission_service(db: AsyncSession) -> PermissionService:
    """
    Get PermissionService instance with database session
    
    Args:
        db: Async database session
        
    Returns:
        PermissionService instance
    """
    return PermissionService(db)


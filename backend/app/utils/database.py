"""
Database Configuration and Connection
Handles PostgreSQL database connection using SQLAlchemy
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
from typing import AsyncGenerator
import os
import logging

logger = logging.getLogger(__name__)


# Build database URL (using asyncpg for async support)
DATABASE_URL = os.getenv(
    "DATABASE_URL"
)

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  
    poolclass=NullPool, 
    future=True
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Base class for models
Base = declarative_base()


async def create_default_admin_user(
    uid: str = None, 
    email: str = None,
    org_id: str = None,
    session: AsyncSession = None
) -> bool:
    """
    Create a default admin user if it doesn't exist
    
    Args:
        uid: Unique user ID (defaults to environment variable DEFAULT_ADMIN_UID or hardcoded value)
        email: Admin email (defaults to environment variable DEFAULT_ADMIN_EMAIL or hardcoded value)
        org_id: Organization ID (optional)
        session: Existing database session (optional, creates new if not provided)
    
    Returns:
        True if user was created, False if already exists
    
    Raises:
        Exception: If user creation fails
    """
    from app.models.user_db import UserDB, RoleEnum
    from sqlalchemy import select
    
    # Use provided values or fallback to environment variables or defaults
    admin_uid = uid or os.getenv("DEFAULT_ADMIN_UID", "l4m9lfnNfhgtt52goNmydFdpNP63")
    admin_email = email or os.getenv("DEFAULT_ADMIN_EMAIL", "maazkshf123@gmail.com")
    admin_org_id = org_id or os.getenv("DEFAULT_ADMIN_ORG_ID", None)
    
    # Use provided session or create new one
    should_close_session = session is None
    if session is None:
        session = AsyncSessionLocal()
    
    try:
        # Check if admin user already exists
        result = await session.execute(
            select(UserDB).where(UserDB.uid == admin_uid)
        )
        existing_admin = result.scalar_one_or_none()
        
        if existing_admin is None:
            # Create default admin user
            admin_user = UserDB(
                uid=admin_uid,
                email=admin_email,
                role=RoleEnum.ADMIN,
                org_id=admin_org_id,
                enabled=True
            )
            session.add(admin_user)
            await session.commit()
            logger.info(f"Default admin user created successfully: {admin_email}")
            return True
        else:
            logger.info(f"Default admin user already exists: {admin_email}")
            return False
            
    except Exception as e:
        await session.rollback()
        logger.error(f"Failed to create default admin user: {e}")
        raise
    finally:
        if should_close_session:
            await session.close()


async def init_db():
    """
    Initialize database - create all tables, create default admin user, and initialize permissions
    
    Returns:
        None
    
    Raises:
        Exception: If database initialization fails
    """
    # Import models to register them with Base
    from app.models.user_db import UserDB, RoleEnum

    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created successfully")
    
    # Initialize default permissions
    await _init_default_permissions()
    
    # Create default admin user if it doesn't exist
    try:
        await create_default_admin_user()
    except Exception as e:
        logger.warning(f"Could not create default admin user: {e}")


async def _init_default_permissions():
    """
    Initialize default role permissions in the database
    
    Returns:
        None
    
    Raises:
        Exception: If permission initialization fails
    """
    from app.models.user_db import RoleEnum
    from app.models.role_permission_db import RolePermissionDB, HTTPMethodEnum
    from sqlalchemy import select
    
    # Default permissions configuration
    # Format: (role, api_path, http_method)
    default_permissions = [
        # Admin - Full access to all user endpoints
        (RoleEnum.ADMIN, "/api/v1/users/create", "POST"),
        (RoleEnum.ADMIN, "/api/v1/users/", "GET"),
        (RoleEnum.ADMIN, "/api/v1/users/uid", "GET"),
        (RoleEnum.ADMIN, "/api/v1/users/uid/{uid}/enabled", "PUT"),
        (RoleEnum.ADMIN, "/api/v1/users/uid/{uid}", "DELETE"),
        (RoleEnum.ADMIN, "/api/v1/users/uid/{uid}/role", "PATCH"),
        (RoleEnum.ADMIN, "/api/v1/users/uid/{uid}/password", "PUT"),
        (RoleEnum.ADMIN, "/api/v1/correctLog", "POST"),
        (RoleEnum.ADMIN, "/api/v1/admin/create-org", "POST"),
        (RoleEnum.ADMIN, "/api/v1/admin/delete-org", "DELETE"),
        (RoleEnum.ADMIN, "/api/v1/admin/regenerate-api-key", "POST"),
        (RoleEnum.ADMIN, "/api/v1/admin/orgs", "GET"),
        (RoleEnum.ADMIN, "/api/v1/search", "GET"),
        (RoleEnum.ADMIN, "/api/v1/export", "GET"),
        (RoleEnum.ADMIN, "/api/v1/admin/org/{org_id}/log-type", "GET"),
        (RoleEnum.ADMIN, "/api/v1/admin/org/log-type", "PUT"),
        (RoleEnum.ADMIN, "/api/v1/generate-report", "POST"),
        # Manager - Can view users
        (RoleEnum.MANAGER, "/api/v1/users/create", "POST"),
        (RoleEnum.MANAGER, "/api/v1/users/", "GET"),
        (RoleEnum.MANAGER, "/api/v1/users/uid", "GET"),
        (RoleEnum.MANAGER, "/api/v1/users/uid/{uid}/enabled", "PUT"),
        (RoleEnum.MANAGER, "/api/v1/correctLog", "POST"),
        (RoleEnum.MANAGER, "/api/v1/search", "GET"),
        (RoleEnum.MANAGER, "/api/v1/export", "GET"),
        (RoleEnum.MANAGER, "/api/v1/admin/org/{org_id}/log-type", "GET"),
        (RoleEnum.MANAGER, "/api/v1/admin/org/log-type", "PUT"),
        (RoleEnum.MANAGER, "/api/v1/generate-report", "POST"),
        
        # Employee - Limited access, only their own profile
        (RoleEnum.EMPLOYEE, "/api/v1/users/uid", "GET"),
        (RoleEnum.EMPLOYEE, "/api/v1/users/uid/{uid}/password", "PUT"),
        
        # All roles - Log endpoints (you can customize these)
        (RoleEnum.ADMIN, "/api/v1/fetch", "GET"),
        (RoleEnum.MANAGER, "/api/v1/fetch", "GET"),
        (RoleEnum.EMPLOYEE, "/api/v1/fetch", "GET"),
        
        # All roles - WebSocket (you may want to restrict this)
        (RoleEnum.ADMIN, "/ws", "GET"),
        (RoleEnum.MANAGER, "/ws", "GET"),
        (RoleEnum.EMPLOYEE, "/ws", "GET"),
    ]
    
    try:
        async with AsyncSessionLocal() as session:
            added_count = 0
            existing_count = 0
            
            for role_enum, api_path, http_method in default_permissions:
                # Check if permission already exists
                method_enum = HTTPMethodEnum[http_method.upper()]
                result = await session.execute(
                    select(RolePermissionDB).where(
                        RolePermissionDB.role == role_enum,
                        RolePermissionDB.api_path == api_path,
                        RolePermissionDB.http_method == method_enum
                    )
                )
                existing = result.scalar_one_or_none()
                
                if not existing:
                    # Create new permission
                    permission = RolePermissionDB(
                        role=role_enum,
                        api_path=api_path,
                        http_method=method_enum
                    )
                    session.add(permission)
                    added_count += 1
                else:
                    existing_count += 1
            
            await session.commit()
            
            if added_count > 0:
                logger.info(f"Initialized {added_count} default permissions")
            if existing_count > 0:
                logger.info(f"{existing_count} permissions already exist")
            
    except Exception as e:
        logger.warning(f"Could not initialize default permissions: {e}")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session
    
    Yields a database session and closes it after use
    
    Returns:
        AsyncGenerator yielding database sessions
    
    Raises:
        Exception: If database session fails
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_db():
    """
    Close database connections
    
    Returns:
        None
    """
    await engine.dispose()
    logger.info("Database connections closed")


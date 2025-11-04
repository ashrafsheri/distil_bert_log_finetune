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

# Get database connection details from environment
POSTGRES_USER = os.getenv("POSTGRES_USER", "logguard_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "logguard_password")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "logguard_db")

# Build database URL (using asyncpg for async support)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    poolclass=NullPool,  # Use NullPool for async connections
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


async def init_db():
    """
    Initialize database - create all tables, create default admin user, and initialize permissions
    """
    # Import models to register them with Base
    from app.models import user_db  # noqa: F401
    from app.models.user_db import UserDB, RoleEnum
    from app.models.role_permission_db import RolePermissionDB  # noqa: F401
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created successfully")
    
    # Initialize default permissions
    await _init_default_permissions()
    
    # Create default admin user if it doesn't exist
    try:
        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            
            # Check if admin user already exists
            result = await session.execute(
                select(UserDB).where(UserDB.uid == "l4m9lfnNfhgtt52goNmydFdpNP63")
            )
            existing_admin = result.scalar_one_or_none()
            
            if existing_admin is None:
                # Create default admin user
                admin_user = UserDB(
                    uid="l4m9lfnNfhgtt52goNmydFdpNP63",
                    email="maazkshf123@gmail.com",
                    role=RoleEnum.ADMIN
                )
                session.add(admin_user)
                await session.commit()
                logger.info("✅ Default admin user created successfully")
            else:
                logger.info("✅ Default admin user already exists")
    except Exception as e:
        logger.warning(f"⚠️  Could not create default admin user: {e}")


async def _init_default_permissions():
    """
    Initialize default role permissions in the database
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
        
        # Manager - Can view users
        (RoleEnum.MANAGER, "/api/v1/users/", "GET"),
        (RoleEnum.MANAGER, "/api/v1/users/uid", "GET"),
        (RoleEnum.MANAGER, "/api/v1/users/uid/{uid}/enabled", "PUT"),
        
        # Employee - Limited access, only their own profile
        (RoleEnum.EMPLOYEE, "/api/v1/users/uid", "GET"),
        (RoleEnum.EMPLOYEE, "/api/v1/users/uid/{uid}/password", "PUT"),
        
        # All roles - Log endpoints (you can customize these)
        (RoleEnum.ADMIN, "/api/v1/fetch", "GET"),
        (RoleEnum.MANAGER, "/api/v1/fetch", "GET"),
        (RoleEnum.EMPLOYEE, "/api/v1/fetch", "GET"),
        # Search logs - restricted to admin and manager
        (RoleEnum.ADMIN, "/api/v1/search", "GET"),
        (RoleEnum.MANAGER, "/api/v1/search", "GET"),
        
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
                logger.info(f"✅ Initialized {added_count} default permissions")
            if existing_count > 0:
                logger.info(f"✅ {existing_count} permissions already exist")
            
    except Exception as e:
        logger.warning(f"⚠️  Could not initialize default permissions: {e}")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session
    Yields a database session and closes it after use
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
    """
    await engine.dispose()
    logger.info("Database connections closed")


"""
User Controller
Handles user-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserCreate, UserUpdate, UserResponse, RoleType, RoleUpdate, PasswordUpdate, UserCreateWithPassword
from app.services.user_service import UserService, get_user_service
from app.utils.database import get_db
from app.utils.firebase_auth import get_current_user
from app.utils.permissions import check_permission

router = APIRouter()


@router.post("/create", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreateWithPassword,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/create", "POST"))
):
    """
    Create a new user with complete logic (Firebase + Database)
    This endpoint creates both Firebase user and database record
    
    Args:
        user_data: User creation data (email, password, role)
        db: Database session
        current_user: Current authenticated user (permission checked via dependency)
        
    Returns:
        Created user data
        
    Raises:
        HTTPException: If user creation fails, user already exists, or unauthorized
    """
    # Check if trying to create admin user - only admins can do this
    if user_data.role == "admin":
        if current_user["role"] != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can create admin users"
            )
    
    # HORIZONTAL PRIVILEGE SEPARATION:
    # Managers can only create users in their own organization
    if current_user["role"] == "manager":
        # If organization_id is provided, ensure it matches manager's org
        if user_data.organization_id and user_data.organization_id != current_user["org_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only create users in your own organization"
            )
        # Enforce manager's organization
        org_id_to_use = current_user["org_id"]
    elif current_user["role"] == "admin":
        # VERTICAL PRIVILEGE SEPARATION:
        # Admins can create users in any organization
        if user_data.role == "admin":
            org_id_to_use = "-1"  # Admins are not tied to a specific org
        else:
            # For non-admin users, organization_id is required
            if not user_data.organization_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="organization_id is required when creating non-admin users"
                )
            # Verify organization exists
            from sqlalchemy import select
            from app.models.organization_db import OrganizationDB
            result = await db.execute(
                select(OrganizationDB).where(OrganizationDB.id == user_data.organization_id)
            )
            org = result.scalar_one_or_none()
            if not org:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Organization {user_data.organization_id} not found"
                )
            org_id_to_use = user_data.organization_id
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to create users"
        )
    
    from firebase_admin import auth
    from app.utils.firebase_auth import get_firebase_app
    
    firebase_uid = None
    try:
        # Initialize Firebase Admin SDK
        get_firebase_app()
        
        # Create Firebase user
        try:
            firebase_user = auth.create_user(
                email=user_data.email,
                password=user_data.password,
                email_verified=True  # Email verification can be done separately
            )
            firebase_uid = firebase_user.uid
        except auth.EmailAlreadyExistsError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with email '{user_data.email}' already exists in Firebase"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to create Firebase user: {str(e)}"
            )
        
        # Create user in database
        try:
            user_service = get_user_service(db)
            user = await user_service.create_user(UserCreate(
                email=user_data.email,
                uid=firebase_uid,
                role=user_data.role,
                org_id=org_id_to_use
            ))
            
            # Get organization name if user belongs to one
            org_name = None
            if user.org_id and user.org_id != "-1":
                from sqlalchemy import select
                from app.models.organization_db import OrganizationDB
                result = await db.execute(
                    select(OrganizationDB).where(OrganizationDB.id == user.org_id)
                )
                org = result.scalar_one_or_none()
                if org:
                    org_name = org.name
            
            return UserResponse(
                email=user.email,
                uid=user.uid,
                role=user.role,
                org_id=user.org_id,
                enabled=user.enabled,
                created_at=user.created_at,
                updated_at=user.updated_at,
                org_name=org_name
            )
        except ValueError as e:
            # If database creation fails, rollback Firebase user
            try:
                auth.delete_user(firebase_uid)
            except Exception as rollback_error:
                # Log but don't fail on rollback
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to rollback Firebase user {firebase_uid}: {rollback_error}")
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            # If database creation fails, rollback Firebase user
            try:
                auth.delete_user(firebase_uid)
            except Exception as rollback_error:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to rollback Firebase user {firebase_uid}: {rollback_error}")
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create user in database: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        # Cleanup Firebase user if it was created but something else failed
        if firebase_uid:
            try:
                auth.delete_user(firebase_uid)
            except Exception:
                pass  # Ignore cleanup errors
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )

@router.get("/", response_model=List[UserResponse])
async def get_all_users(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/", "GET"))
):
    """
    Get all users
    
    Args:
        user_service: User service dependency
        
    Returns:
        List of all users
    """
    try:
        user_service = get_user_service(db)
        # HORIZONTAL PRIVILEGE SEPARATION: Filter users by org_id unless current user is admin
        if current_user["role"] == "admin":
            users = await user_service.get_all_users()
        else:
            users = await user_service.get_all_users(org_id=current_user["org_id"])
        
        # Get organization names for all users
        from sqlalchemy import select
        from app.models.organization_db import OrganizationDB
        org_ids = {user.org_id for user in users if user.org_id and user.org_id != "-1"}
        org_names = {}
        if org_ids:
            result = await db.execute(
                select(OrganizationDB).where(OrganizationDB.id.in_(org_ids))
            )
            orgs = result.scalars().all()
            org_names = {org.id: org.name for org in orgs}
        
        return [
            UserResponse(
                email=user.email,
                uid=user.uid,
                role=user.role,
                org_id=user.org_id,
                enabled=user.enabled,
                created_at=user.created_at,
                updated_at=user.updated_at,
                org_name=org_names.get(user.org_id) if user.org_id and user.org_id != "-1" else None
            )
            for user in users
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve users: {str(e)}"
        )


@router.get("/uid", response_model=UserResponse)
async def get_user(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid", "GET"))
):
    """
    Get current user's data
    
    Args:
        db: Database session
        current_user: Current authenticated user (from JWT)
        
    Returns:
        Current user's data
        
    Raises:
        HTTPException: If user not found
    """
    try:
        user_service = get_user_service(db)
        user = await user_service.get_user(current_user["uid"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with uid '{current_user['uid']}' not found"
            )
        
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
            org_id=user.org_id,
            enabled=user.enabled,
            created_at=user.created_at,
            updated_at=user.updated_at,
            org_name=current_user.get("org_name")  # Already available in current_user
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user: {str(e)}"
        )


@router.put("/uid/{uid}/enabled", response_model=UserResponse)
async def update_user_enabled(
    uid: str,
    user_data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid/{uid}/enabled", "PUT"))
):
    """
    Update user enabled status
    
    Args:
        uid: User ID (Firebase UID)
        user_data: User update data (only enabled field)
        db: Database session
        current_user: Current authenticated user (permission checked via dependency)
        
    Returns:
        Updated user data
        
    Raises:
        HTTPException: If user not found or validation fails
    """
    try:
        user_service = get_user_service(db)
        
        # Check organization access unless current user is admin
        if current_user["role"] != "admin":
            existing_user = await user_service.get_user(uid)
            if not existing_user or existing_user.org_id != current_user["org_id"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You can only update users in your organization"
                )
        
        user = await user_service.update_user(uid, user_data)
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
            org_id=user.org_id,
            enabled=user.enabled,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user: {str(e)}"
        )


@router.patch("/uid/{uid}/role", response_model=UserResponse)
async def update_user_role(
    uid: str,
    role_data: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid/{uid}/role", "PATCH"))
):
    """
    Update user role
    
    Args:
        uid: User ID (Firebase UID)
        role_data: Role update data
        db: Database session
        current_user: Current authenticated user
        
    Returns:
        Updated user data
        
    Raises:
        HTTPException: If user not found or validation fails
    """
    try:
        user_service = get_user_service(db)
        
        # Check organization access unless current user is admin
        if current_user["role"] != "admin":
            existing_user = await user_service.get_user(uid)
            if not existing_user or existing_user.org_id != current_user["org_id"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You can only update users in your organization"
                )
        
        # Check if trying to set role to admin - only admins can do this
        if role_data.role == "admin" and current_user["role"] != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can set user roles to admin"
            )
        
        user = await user_service.update_user_role(uid, role_data.role)
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
            org_id=user.org_id,
            enabled=user.enabled,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user role: {str(e)}"
        )


@router.put("/uid/{uid}/password", status_code=status.HTTP_200_OK)
async def update_user_password(
    uid: str,
    password_data: PasswordUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid/{uid}/password", "PUT"))
):
    """
    Update user password using Firebase Admin SDK
    
    Args:
        uid: User ID (Firebase UID)
        password_data: Password update data (new_password, optional current_password)
        db: Database session
        current_user: Current authenticated user (permission checked via dependency)
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If user not found, unauthorized, or update fails
    """
    from firebase_admin import auth
    from app.utils.firebase_auth import get_firebase_app
    
    try:
        # Verify user exists in database
        user_service = get_user_service(db)
        db_user = await user_service.get_user(uid)
        
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Additional check: Users can only update passwords of users in their organization unless they're admin
        if current_user.get("role") != "admin" and db_user.org_id != current_user["org_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update passwords for users in your organization"
            )
        
        # Update password using Firebase Admin SDK
        get_firebase_app()  # Ensure Firebase Admin is initialized
        auth.update_user(uid, password=password_data.new_password)
        
        return {"message": "Password updated successfully"}
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update password: {str(e)}"
        )


@router.delete("/uid/{uid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    uid: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid/{uid}", "DELETE"))
):
    """
    Delete (remove) a user
    
    Args:
        uid: User ID (Firebase UID)
        user_service: User service dependency
        
    Returns:
        No content (204 status)
        
    Raises:
        HTTPException: If user not found
    """
    try:
        user_service = get_user_service(db)
        
        # Check organization access unless current user is admin
        if current_user["role"] != "admin":
            existing_user = await user_service.get_user(uid)
            if not existing_user or existing_user.org_id != current_user["org_id"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You can only delete users in your organization"
                )
        
        await user_service.remove_user(uid)
        return None
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}"
        )

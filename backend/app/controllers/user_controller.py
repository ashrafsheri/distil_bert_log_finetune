"""
User Controller
Handles user-related API endpoints
"""

import logging
from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserCreate, UserUpdate, UserResponse, RoleType, RoleUpdate, PasswordUpdate, UserCreateWithPassword
from app.services.user_service import UserService, get_user_service
from app.utils.database import get_db
from app.utils.firebase_auth import get_current_user
from app.utils.permissions import check_permission

router = APIRouter()
logger = logging.getLogger(__name__)


def _ensure_admin_creation_allowed(user_role: str, target_role: str) -> None:
    if target_role == "admin" and user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create admin users"
        )


async def _validate_organization(
    organization_id: str,
    db: AsyncSession,
):
    from sqlalchemy import select
    from app.models.organization_db import OrganizationDB

    result = await db.execute(
        select(OrganizationDB).where(OrganizationDB.id == organization_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found"
        )
    return org


async def _resolve_user_org_id(
    user_data: UserCreateWithPassword,
    current_user: dict,
    db: AsyncSession,
) -> str:
    user_role = current_user["role"]

    if user_role == "manager":
        if user_data.organization_id and user_data.organization_id != current_user["org_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only create users in your own organization"
            )
        return current_user["org_id"]

    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to create users"
        )

    if user_data.role == "admin":
        return "-1"

    if not user_data.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="organization_id is required when creating non-admin users"
        )

    await _validate_organization(user_data.organization_id, db)
    return user_data.organization_id


def _create_firebase_user(user_data: UserCreateWithPassword):
    from firebase_admin import auth

    try:
        return auth.create_user(
            email=user_data.email,
            password=user_data.password,
            email_verified=True
        )
    except auth.EmailAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with email '{user_data.email}' already exists in Firebase"
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create Firebase user: {str(exc)}"
        ) from exc


def _rollback_firebase_user(firebase_uid: str | None) -> None:
    if not firebase_uid:
        return

    from firebase_admin import auth

    try:
        auth.delete_user(firebase_uid)
    except Exception as rollback_error:
        logger.error("Failed to rollback Firebase user %s: %s", firebase_uid, rollback_error)


async def _get_org_name(org_id: str | None, db: AsyncSession) -> str | None:
    if not org_id or org_id == "-1":
        return None

    organization = await _validate_organization(org_id, db)
    return organization.name


async def _create_database_user(
    user_data: UserCreateWithPassword,
    firebase_uid: str,
    org_id_to_use: str,
    db: AsyncSession,
):
    user_service = get_user_service(db)
    return await user_service.create_user(
        UserCreate(
            email=user_data.email,
            uid=firebase_uid,
            role=user_data.role,
            org_id=org_id_to_use
        )
    )


async def _build_user_response(user, db: AsyncSession) -> UserResponse:
    org_name = await _get_org_name(user.org_id, db)
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


@router.post("/create", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreateWithPassword,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/create", "POST"))],
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
    _ensure_admin_creation_allowed(current_user["role"], user_data.role)
    org_id_to_use = await _resolve_user_org_id(user_data, current_user, db)

    from app.utils.firebase_auth import get_firebase_app

    firebase_uid = None
    try:
        get_firebase_app()
        firebase_uid = _create_firebase_user(user_data).uid

        try:
            user = await _create_database_user(user_data, firebase_uid, org_id_to_use, db)
            return await _build_user_response(user, db)
        except ValueError as exc:
            _rollback_firebase_user(firebase_uid)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc)
            ) from exc
        except Exception as exc:
            _rollback_firebase_user(firebase_uid)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create user in database: {str(exc)}"
            ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        _rollback_firebase_user(firebase_uid)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(exc)}"
        ) from exc

@router.get("/", response_model=List[UserResponse])
async def get_all_users(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/", "GET"))],
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/uid", "GET"))],
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/uid/{uid}/enabled", "PUT"))],
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/uid/{uid}/role", "PATCH"))],
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/uid/{uid}/password", "PUT"))],
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/users/uid/{uid}", "DELETE"))],
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

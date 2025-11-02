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
                email_verified=False  # Email verification can be done separately
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
                role=user_data.role
            ))
            
            return UserResponse(
                email=user.email,
                uid=user.uid,
                role=user.role,
                enabled=user.enabled,
                created_at=user.created_at,
                updated_at=user.updated_at
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


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
    # Note: Registration endpoint is public (no auth required) as it's called during user creation
):
    """
    Register a new user with user ID and role
    This endpoint receives user information after Firebase account creation
    DEPRECATED: Use /create endpoint instead for complete user creation
    
    Args:
        user_data: User creation data (uid, email, role)
        user_service: User service dependency
        
    Returns:
        Created user data
        
    Raises:
        HTTPException: If user already exists or validation fails
    """
    try:
        user_service = get_user_service(db)
        user = await user_service.create_user(user_data)
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
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
            detail=f"Failed to register user: {str(e)}"
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
        users = await user_service.get_all_users()
        return [
            UserResponse(
                email=user.email,
                uid=user.uid,
                role=user.role,
                enabled=user.enabled,
                created_at=user.created_at,
                updated_at=user.updated_at
            )
            for user in users
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve users: {str(e)}"
        )


@router.get("/email/{email}", response_model=UserResponse)
async def get_user_by_email(
    email: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/email/{email}", "GET"))
):
    """
    Get a user by email address
    
    Args:
        email: User email address
        user_service: User service dependency
        
    Returns:
        User data
        
    Raises:
        HTTPException: If user not found
    """
    try:
        user_service = get_user_service(db)
        user = await user_service.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with email '{email}' not found"
            )
        
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
            enabled=user.enabled,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user: {str(e)}"
        )


@router.get("/uid/{uid}", response_model=UserResponse)
async def get_user(
    uid: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid/{uid}", "GET"))
):
    """
    Get a user by uid
    
    Args:
        uid: User ID (Firebase UID)
        user_service: User service dependency
        
    Returns:
        User data
        
    Raises:
        HTTPException: If user not found
    """
    try:
        user_service = get_user_service(db)
        user = await user_service.get_user(uid)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with uid '{uid}' not found"
            )
        
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
            enabled=user.enabled,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user: {str(e)}"
        )


@router.put("/uid/{uid}", response_model=UserResponse)
async def update_user(
    uid: str,
    user_data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/users/uid/{uid}", "PUT"))
):
    """
    Update an existing user
    
    Args:
        uid: User ID (Firebase UID)
        user_data: User update data (only provided fields will be updated)
        user_service: User service dependency
        
    Returns:
        Updated user data
        
    Raises:
        HTTPException: If user not found or validation fails
    """
    try:
        user_service = get_user_service(db)
        user = await user_service.update_user(uid, user_data)
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
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
        user = await user_service.update_user(uid, UserUpdate(role=role_data.role))
        return UserResponse(
            email=user.email,
            uid=user.uid,
            role=user.role,
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
        
        # Additional check: Users can only update their own password unless they're admin
        # (Permission system handles role-based access, but we check ownership here)
        if uid != current_user["uid"] and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update your own password"
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

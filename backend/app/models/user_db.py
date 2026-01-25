"""
User Database Model
SQLAlchemy model for user table in PostgreSQL
"""

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, Boolean, text
from sqlalchemy.sql import func
import enum

# Import Base from database module
# This is safe because Base is defined before models are imported in init_db
from app.utils.database import Base


class RoleEnum(str, enum.Enum):
    """User role enumeration"""
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"


class UserDB(Base):
    """SQLAlchemy model for users table"""
    __tablename__ = "users"

    org_id = Column(String, nullable=True)
    uid = Column(String, primary_key=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    role = Column(SQLEnum(RoleEnum), nullable=False, default=RoleEnum.EMPLOYEE)
    enabled = Column(Boolean, default=True, nullable=False, server_default=text('true'))  # Boolean with default True
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<UserDB(uid={self.uid}, email={self.email}, role={self.role.value}, enabled={self.enabled})>"


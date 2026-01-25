"""
IP Database Model
SQLAlchemy model for ip table in PostgreSQL
"""

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, text
from sqlalchemy.sql import func
import enum

# Import Base from database module
from app.utils.database import Base


class IPStatusEnum(str, enum.Enum):
    """IP status enumeration"""
    CLEAN = "clean"
    MALICIOUS = "malicious"


class IPDB(Base):
    """SQLAlchemy model for ip table"""
    __tablename__ = "ip"

    ip = Column(String, primary_key=True, index=True, nullable=False)
    status = Column(SQLEnum(IPStatusEnum), nullable=False)
    org = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<IPDB(ip={self.ip}, status={self.status.value})>"


"""
Organization Database Model
SQLAlchemy model for organization table in PostgreSQL
"""

from sqlalchemy import Column, String, DateTime, text
from sqlalchemy.sql import func

# Import Base from database module
from app.utils.database import Base


class OrgDB(Base):
    """SQLAlchemy model for organizations table"""
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    created_by = Column(String, nullable=False)  # uid of creator
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<OrgDB(id={self.id}, name={self.name}, api_key={self.api_key[:10]}...)>"
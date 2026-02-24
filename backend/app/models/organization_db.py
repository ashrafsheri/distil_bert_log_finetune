"""
Organization Database Model (Top Level)
SQLAlchemy model for organization table in PostgreSQL
Organizations are the top-level entity that contain multiple projects
"""

from sqlalchemy import Column, String, DateTime
from sqlalchemy.sql import func

from app.utils.database import Base


class OrganizationDB(Base):
    """SQLAlchemy model for organizations table"""
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    created_by = Column(String, nullable=False)  # uid of creator (admin)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<OrganizationDB(id={self.id}, name={self.name})>"

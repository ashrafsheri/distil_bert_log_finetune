"""
Project Database Model
SQLAlchemy model for project table in PostgreSQL
Projects belong to organizations and have their own API keys and log types
"""

from sqlalchemy import Column, String, DateTime, Integer, Float, Enum as SQLEnum, ForeignKey, text
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
import enum

from app.utils.database import Base


class ModelStatus(str, enum.Enum):
    """Enum for project model training status"""
    warmup = "warmup"
    training = "training"
    ready = "ready"
    failed = "failed"


# Create PostgreSQL enum type that matches the existing database enum
model_status_enum = PgEnum(
    'warmup', 'training', 'ready', 'failed',
    name='modelstatus',
    create_type=True  # Create the type if it doesn't exist
)


class ProjectDB(Base):
    """SQLAlchemy model for projects table"""
    __tablename__ = "projects"

    id = Column(String, primary_key=True, index=True, nullable=False)
    org_id = Column(String, ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    created_by = Column(String, nullable=False)  # uid of creator
    log_type = Column(String, nullable=False, server_default=text("'apache'"))  # Log format type: apache or nginx
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Model tracking fields - use PostgreSQL enum type
    model_status = Column(model_status_enum, default="warmup", nullable=True)
    log_count = Column(Integer, default=0, nullable=True)
    warmup_threshold = Column(Integer, default=10000, nullable=True)
    warmup_progress = Column(Float, default=0.0, nullable=True)
    student_trained_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<ProjectDB(id={self.id}, name={self.name}, org_id={self.org_id}, api_key={self.api_key[:10]}...)>"

"""
Organization Database Model
SQLAlchemy model for organization table in PostgreSQL
"""

from sqlalchemy import Column, String, DateTime, Integer, Float, Enum, text
from sqlalchemy.sql import func
import enum

# Import Base from database module
from app.utils.database import Base


class ModelStatus(str, enum.Enum):
    """Enum for organization model training status"""
    warmup = "warmup"
    training = "training"
    ready = "ready"
    failed = "failed"


class OrgDB(Base):
    """SQLAlchemy model for organizations table"""
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    created_by = Column(String, nullable=False)  # uid of creator
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Model tracking fields
    model_status = Column(String, default="warmup", nullable=True)  # warmup, training, ready, failed
    log_count = Column(Integer, default=0, nullable=True)
    warmup_threshold = Column(Integer, default=10000, nullable=True)
    warmup_progress = Column(Float, default=0.0, nullable=True)
    student_trained_at = Column(DateTime(timezone=True), nullable=True)
    manager_email = Column(String, nullable=True)

    def __repr__(self):
        return f"<OrgDB(id={self.id}, name={self.name}, api_key={self.api_key[:10]}...)>"
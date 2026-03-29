-- Migration: Add model tracking fields to organizations table
-- Run this migration if upgrading from a previous version

-- Create the model status enum type if it doesn't exist
DO $$ BEGIN
    CREATE TYPE modelstatusenum AS ENUM ('warmup', 'training', 'active', 'suspended', 'error');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add new columns to organizations table
ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS model_status modelstatusenum DEFAULT 'warmup' NOT NULL;

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS log_count INTEGER DEFAULT 0 NOT NULL;

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS warmup_threshold INTEGER DEFAULT 10000 NOT NULL;

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS warmup_progress FLOAT DEFAULT 0.0 NOT NULL;

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS student_trained_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS manager_email VARCHAR;

-- Update existing organizations to have warmup status
UPDATE organizations 
SET model_status = 'warmup', log_count = 0, warmup_progress = 0.0 
WHERE model_status IS NULL;

-- Add index for faster API key lookups (if not exists)
CREATE INDEX IF NOT EXISTS idx_organizations_api_key ON organizations(api_key);

-- Add index for model status queries
CREATE INDEX IF NOT EXISTS idx_organizations_model_status ON organizations(model_status);

-- Migration: Persist traffic profile for project-level detector activation
-- Run this against deployments that already have the projects table.

ALTER TABLE projects
ADD COLUMN IF NOT EXISTS traffic_profile VARCHAR DEFAULT 'standard' NOT NULL;

UPDATE projects
SET traffic_profile = 'standard'
WHERE traffic_profile IS NULL OR traffic_profile = '';

CREATE INDEX IF NOT EXISTS idx_projects_traffic_profile ON projects(traffic_profile);

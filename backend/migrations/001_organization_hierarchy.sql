-- Migration Script: Organization Hierarchy Update
-- Version: 2.0.0
-- Description: Adds organization → project hierarchy with project-level access control

-- ================================================================
-- STEP 1: BACKUP EXISTING DATA
-- ================================================================

CREATE TABLE IF NOT EXISTS organizations_backup AS 
SELECT * FROM organizations;

CREATE TABLE IF NOT EXISTS users_backup AS 
SELECT * FROM users;

-- ================================================================
-- STEP 2: CREATE NEW TABLES
-- ================================================================

-- Create new top-level organizations table
CREATE TABLE IF NOT EXISTS organizations_new (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    created_by VARCHAR NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Rename old organizations to projects_temp for migration
ALTER TABLE organizations RENAME TO projects_temp;

-- Create projects table (replaces old organizations)
CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR PRIMARY KEY,
    org_id VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    api_key VARCHAR UNIQUE NOT NULL,
    created_by VARCHAR NOT NULL,
    log_type VARCHAR NOT NULL DEFAULT 'apache',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    model_status modelstatus DEFAULT 'warmup',
    log_count INTEGER DEFAULT 0,
    warmup_threshold INTEGER DEFAULT 10000,
    warmup_progress FLOAT DEFAULT 0.0,
    student_trained_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_projects_org FOREIGN KEY (org_id) 
        REFERENCES organizations_new(id) ON DELETE CASCADE
);

CREATE INDEX idx_projects_org_id ON projects(org_id);
CREATE INDEX idx_projects_api_key ON projects(api_key);

-- Create project_members table for project-level access control
CREATE TABLE IF NOT EXISTS project_members (
    id VARCHAR PRIMARY KEY,
    project_id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    role VARCHAR NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    CONSTRAINT fk_project_members_project FOREIGN KEY (project_id) 
        REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT fk_project_members_user FOREIGN KEY (user_id) 
        REFERENCES users(uid) ON DELETE CASCADE,
    CONSTRAINT uq_project_member UNIQUE (project_id, user_id)
);

CREATE INDEX idx_project_members_project_id ON project_members(project_id);
CREATE INDEX idx_project_members_user_id ON project_members(user_id);

-- ================================================================
-- STEP 3: MIGRATE DATA
-- ================================================================

-- 3a: Create organizations from existing org_ids in users table
-- This creates one organization per unique org_id
INSERT INTO organizations_new (id, name, created_by, created_at)
SELECT DISTINCT 
    u.org_id as id,
    COALESCE(pt.name, 'Organization ' || u.org_id) as name,
    MIN(u.uid) as created_by,  -- Use first user as creator
    MIN(u.created_at) as created_at
FROM users u
LEFT JOIN projects_temp pt ON pt.id = u.org_id
WHERE u.org_id IS NOT NULL
GROUP BY u.org_id, pt.name
ON CONFLICT (id) DO NOTHING;

-- Also create organizations for any projects without users
INSERT INTO organizations_new (id, name, created_by, created_at)
SELECT DISTINCT
    pt.id as id,
    'Legacy Organization ' || pt.name as name,
    pt.created_by,
    pt.created_at
FROM projects_temp pt
WHERE NOT EXISTS (
    SELECT 1 FROM organizations_new o WHERE o.id = pt.id
)
ON CONFLICT (id) DO NOTHING;

-- 3b: Migrate old organizations to projects
-- Each old organization becomes a project within an organization
INSERT INTO projects (
    id, org_id, name, api_key, created_by, log_type,
    created_at, updated_at, model_status, log_count,
    warmup_threshold, warmup_progress, student_trained_at
)
SELECT 
    'proj-' || substr(md5(pt.id || pt.name), 1, 8) as id,  -- Generate new project ID
    pt.id as org_id,  -- Old org ID becomes the parent org
    pt.name,
    pt.api_key,
    pt.created_by,
    COALESCE(pt.log_type, 'apache') as log_type,
    pt.created_at,
    pt.updated_at,
    pt.model_status,
    COALESCE(pt.log_count, 0) as log_count,
    COALESCE(pt.warmup_threshold, 10000) as warmup_threshold,
    COALESCE(pt.warmup_progress, 0.0) as warmup_progress,
    pt.student_trained_at
FROM projects_temp pt;

-- 3c: Create project memberships for all users
-- Map users to projects based on their org_id
INSERT INTO project_members (id, project_id, user_id, role, created_at)
SELECT 
    'pm-' || substr(md5(random()::text || u.uid || p.id), 1, 8) as id,
    p.id as project_id,
    u.uid as user_id,
    CASE 
        WHEN u.role = 'admin' THEN 'owner'
        WHEN u.role = 'manager' THEN 'owner'
        WHEN u.role = 'employee' THEN 'editor'
        ELSE 'viewer'
    END as role,
    NOW() as created_at
FROM users u
INNER JOIN projects p ON p.org_id = u.org_id
WHERE u.org_id IS NOT NULL
ON CONFLICT (project_id, user_id) DO NOTHING;

-- ================================================================
-- STEP 4: UPDATE RELATED TABLES
-- ================================================================

-- Rename organizations_new to organizations
ALTER TABLE organizations_new RENAME TO organizations;

-- Update role_permissions table to support project-level permissions
ALTER TABLE role_permissions 
ADD COLUMN IF NOT EXISTS project_id VARCHAR,
ADD COLUMN IF NOT EXISTS permission_level VARCHAR DEFAULT 'organization';

-- Set existing permissions to organization level
UPDATE role_permissions 
SET permission_level = 'organization' 
WHERE permission_level IS NULL;

-- ================================================================
-- STEP 5: CREATE USEFUL VIEWS (OPTIONAL)
-- ================================================================

-- View to see organization hierarchy
CREATE OR REPLACE VIEW v_organization_hierarchy AS
SELECT 
    o.id as org_id,
    o.name as org_name,
    COUNT(DISTINCT p.id) as project_count,
    COUNT(DISTINCT u.uid) as user_count,
    o.created_at as org_created_at
FROM organizations o
LEFT JOIN projects p ON o.id = p.org_id
LEFT JOIN users u ON o.id = u.org_id
GROUP BY o.id, o.name, o.created_at;

-- View to see user access across projects
CREATE OR REPLACE VIEW v_user_project_access AS
SELECT 
    u.uid,
    u.email,
    u.role as org_role,
    o.id as org_id,
    o.name as org_name,
    p.id as project_id,
    p.name as project_name,
    pm.role as project_role
FROM users u
INNER JOIN organizations o ON u.org_id = o.id
INNER JOIN projects p ON o.id = p.org_id
LEFT JOIN project_members pm ON p.id = pm.project_id AND u.uid = pm.user_id;

-- ================================================================
-- STEP 6: VERIFY MIGRATION
-- ================================================================

-- Check counts match
SELECT 
    'organizations_backup' as table_name,
    COUNT(*) as count 
FROM organizations_backup
UNION ALL
SELECT 
    'organizations_new' as table_name,
    COUNT(*) as count 
FROM organizations
UNION ALL
SELECT 
    'projects' as table_name,
    COUNT(*) as count 
FROM projects
UNION ALL
SELECT 
    'project_members' as table_name,
    COUNT(*) as count 
FROM project_members;

-- ================================================================
-- STEP 7: CLEANUP (RUN AFTER VERIFICATION)
-- ================================================================

-- Drop temporary table after verification
-- DROP TABLE IF EXISTS projects_temp;

-- Drop backups after confirming migration success (optional, keep for safety)
-- DROP TABLE IF EXISTS organizations_backup;
-- DROP TABLE IF EXISTS users_backup;

-- ================================================================
-- ROLLBACK SCRIPT (USE IF MIGRATION FAILS)
-- ================================================================

-- Uncomment and run if you need to rollback:
/*
DROP TABLE IF EXISTS project_members CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;

ALTER TABLE organizations_backup RENAME TO organizations;
-- Note: You may need to restore indexes and constraints
*/

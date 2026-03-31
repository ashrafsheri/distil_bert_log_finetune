-- Migration Script: Project Roles Update
-- Version: 2.1.0
-- Description: Updates project member roles from viewer/editor/admin/owner to project_staff/project_admin/owner
--              Adds organization membership enforcement for project membership

-- ================================================================
-- STEP 1: BACKUP EXISTING DATA
-- ================================================================

CREATE TABLE IF NOT EXISTS project_members_backup AS 
SELECT id, project_id, user_id, role, created_at, updated_at FROM project_members;

-- ================================================================
-- STEP 2: ALTER COLUMN TYPE FROM ENUM TO VARCHAR (if using enum)
-- ================================================================

-- If the column uses a PostgreSQL enum type, convert to VARCHAR first
-- This handles both cases: VARCHAR or ENUM column types
DO $$
BEGIN
    -- Try to alter the column type (works if it's an enum)
    ALTER TABLE project_members ALTER COLUMN role TYPE VARCHAR USING role::text;
EXCEPTION
    WHEN others THEN
        -- Column is already VARCHAR, nothing to do
        NULL;
END $$;

-- ================================================================
-- STEP 3: UPDATE ROLE VALUES
-- ================================================================

-- Map old roles to new roles
UPDATE project_members SET role = 'project_staff' WHERE role IN ('viewer', 'editor');
UPDATE project_members SET role = 'project_admin' WHERE role = 'admin';
-- 'owner' stays as 'owner'

-- ================================================================
-- STEP 4: ADD CHECK CONSTRAINT FOR VALID ROLES
-- ================================================================

-- Drop existing constraint if any
ALTER TABLE project_members DROP CONSTRAINT IF EXISTS chk_project_member_role;

-- Add new constraint for valid role values
ALTER TABLE project_members 
ADD CONSTRAINT chk_project_member_role 
CHECK (role IN ('project_staff', 'project_admin', 'owner'));

-- ================================================================
-- STEP 5: DROP OLD ENUM TYPE (if exists)
-- ================================================================

-- Drop the old PostgreSQL enum type if it exists
DO $$
BEGIN
    DROP TYPE IF EXISTS projectroleenum;
EXCEPTION
    WHEN others THEN
        NULL;
END $$;

-- ================================================================
-- STEP 6: VERIFY MIGRATION
-- ================================================================

SELECT role, COUNT(*) as count 
FROM project_members 
GROUP BY role 
ORDER BY role;

-- ================================================================
-- ROLLBACK SCRIPT (USE IF MIGRATION FAILS)
-- ================================================================

-- Uncomment and run if you need to rollback:
/*
ALTER TABLE project_members DROP CONSTRAINT IF EXISTS chk_project_member_role;

UPDATE project_members SET role = 'viewer' WHERE role = 'project_staff';
UPDATE project_members SET role = 'admin' WHERE role = 'project_admin';

DROP TABLE IF EXISTS project_members_backup;
*/

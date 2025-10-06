-- Add request_id column to audit_log table for better traceability
ALTER TABLE audit_log ADD COLUMN request_id TEXT;

-- Create index for request_id for better query performance
CREATE INDEX idx_audit_log_request_id ON audit_log(request_id);
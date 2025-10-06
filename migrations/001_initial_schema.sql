-- Initial database schema for RustBase
-- This migration creates the core tables for collections, users, and audit logging

-- Collections metadata table
CREATE TABLE collections (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL DEFAULT 'base',
    schema_json TEXT NOT NULL,
    list_rule TEXT,
    view_rule TEXT,
    create_rule TEXT,
    update_rule TEXT,
    delete_rule TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Collection fields definition table
CREATE TABLE collection_fields (
    id TEXT PRIMARY KEY,
    collection_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    required BOOLEAN DEFAULT FALSE,
    unique_constraint BOOLEAN DEFAULT FALSE,
    options_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
    UNIQUE(collection_id, name)
);

-- Built-in users collection
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    verified BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Audit log for administrative actions
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details_json TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes for better performance
CREATE INDEX idx_collections_name ON collections(name);
CREATE INDEX idx_collections_type ON collections(type);
CREATE INDEX idx_collection_fields_collection_id ON collection_fields(collection_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
# FerriteDB Entity Relationships

FerriteDB persists metadata in fixed tables and materializes dynamic record tables per collection. The canonical SQLite schema established by `migrations/001_initial_schema.sql` and `002_add_request_id_to_audit_log.sql` is summarized below.

```
collections (id TEXT PK, name UNIQUE, type, schema_json, list_rule, view_rule,
             create_rule, update_rule, delete_rule, created_at, updated_at)
    └─< collection_fields (id TEXT PK, collection_id FK → collections.id,
                          name, type JSON, required, unique_constraint,
                          options_json, created_at)

users (id TEXT PK, email UNIQUE, password_hash, role, verified,
       created_at, updated_at)
    └─< audit_log (id TEXT PK, user_id FK → users.id, action, resource_type,
                  resource_id, details_json, ip_address, user_agent,
                  request_id, created_at)
```

## Dynamic Record Tables
- For each user-defined collection, `SchemaManager` creates a physical table named `records_{collection}` with shared columns (`id`, `created_at`, `updated_at`) plus per-field columns generated from `collection_fields`.
- Relation fields produce foreign-key-like columns referencing other `records_*` tables; cascading delete behavior depends on the field definition.
- Auxiliary indexes are added per unique field and relation to support query performance.

## Auxiliary Structures
- `audit_log` captures CRUD and security events with optional linkage to users and resources.
- `collection_fields.options_json` stores serialized `FieldOptions` (constraints such as min/max, enum values).
- Seed routines initialise canonical `users` and `posts` collections plus their accompanying `records_users` and `records_posts` tables.

This hybrid model keeps schema metadata in normalized tables while delegating record storage to per-collection tables so dynamic schemas can be enforced at runtime without resorting to schemaless blobs.

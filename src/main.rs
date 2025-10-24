use clap::{Parser, Subcommand};
use ferritedb_core::CoreConfig;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "ferritedb")]
#[command(about = "A production-ready, developer-friendly backend service")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the FerriteDB server
    Serve {
        /// Server host address
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Server port
        #[arg(long, default_value = "8090")]
        port: u16,

        /// Database file path
        #[arg(long, default_value = "data/ferritedb.db")]
        database: PathBuf,
    },
    /// Database migration commands
    Migrate {
        #[command(subcommand)]
        action: MigrateCommands,
    },
    /// Admin user management commands
    Admin {
        #[command(subcommand)]
        action: AdminCommands,
    },
    /// Data import/export commands
    Import {
        /// Collection name
        collection: String,
        /// Input file path (JSON or CSV)
        file: PathBuf,
    },
    Export {
        /// Collection name
        collection: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate JWT token for testing
    GenJwt {
        /// User ID or email
        user: String,
        /// Token expiration in seconds
        #[arg(long, default_value = "3600")]
        expires: u64,
    },
    /// Initialize example collections and seed data
    Seed {
        /// Force recreate collections if they exist
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum MigrateCommands {
    /// Run pending migrations
    Run,
    /// Revert last migration
    Revert,
    /// Show migration status
    Status,
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Create admin user
    Create {
        /// Admin email
        email: String,
        /// Admin password (will prompt if not provided)
        #[arg(long)]
        password: Option<String>,
    },
    /// List users
    List,
    /// Delete user
    Delete {
        /// User email or ID
        user: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize tracing
    init_tracing(cli.debug);

    // Load configuration
    let config = load_config(cli.config.as_deref()).await?;

    // Execute command
    match cli.command {
        Commands::Serve {
            host,
            port,
            database,
        } => {
            info!("Starting FerriteDB server on {}:{}", host, port);
            serve_command(config, host, port, database).await?;
        }
        Commands::Migrate { action } => {
            migrate_command(config, action).await?;
        }
        Commands::Admin { action } => {
            admin_command(config, action).await?;
        }
        Commands::Import { collection, file } => {
            import_command(config, collection, file).await?;
        }
        Commands::Export { collection, output } => {
            export_command(config, collection, output).await?;
        }
        Commands::GenJwt { user, expires } => {
            gen_jwt_command(config, user, expires).await?;
        }
        Commands::Seed { force } => {
            seed_command(config, force).await?;
        }
    }

    Ok(())
}

fn init_tracing(debug: bool) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = if debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn load_config(config_path: Option<&std::path::Path>) -> Result<CoreConfig, ConfigError> {
    use figment::{
        providers::{Env, Format, Toml},
        Figment,
    };

    let mut figment = Figment::new();

    // Load from config file if provided
    if let Some(path) = config_path {
        figment = figment.merge(Toml::file(path));
    } else {
        // Try default config locations
        figment = figment
            .merge(Toml::file("ferritedb.toml"))
            .merge(Toml::file("config/ferritedb.toml"));
    }

    // Override with environment variables
    figment = figment.merge(Env::prefixed("FERRITEDB_"));

    figment.extract().map_err(ConfigError::Figment)
}

async fn serve_command(
    mut config: CoreConfig,
    host: String,
    port: u16,
    database: PathBuf,
) -> Result<(), FerriteDbError> {
    // Override config with CLI arguments
    config.server.host = host;
    config.server.port = port;
    config.database.url = format!("sqlite:{}", database.display());

    // Create and start the server
    let server = ferritedb_server::Server::new(config).await.map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::configuration(format!(
            "Server initialization failed: {}",
            e
        )))
    })?;

    server.serve().await.map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::configuration(format!(
            "Server error: {}",
            e
        )))
    })?;

    Ok(())
}

async fn migrate_command(
    config: CoreConfig,
    action: MigrateCommands,
) -> Result<(), FerriteDbError> {
    use ferritedb_core::Database;

    // Create database connection
    let database = Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.connection_timeout,
    )
    .await
    .map_err(FerriteDbError::Core)?;

    match action {
        MigrateCommands::Run => {
            info!("Running migrations...");
            database.migrate().await.map_err(FerriteDbError::Core)?;
            info!("✅ Migrations completed successfully");
        }
        MigrateCommands::Revert => {
            info!("Reverting last migration...");

            // Get migration info
            let migration_info = sqlx::query_as::<_, (i64, String)>(
                "SELECT version, description FROM _sqlx_migrations ORDER BY version DESC LIMIT 1",
            )
            .fetch_optional(database.pool())
            .await
            .map_err(|e| {
                FerriteDbError::Core(ferritedb_core::CoreError::validation(e.to_string()))
            })?;

            if let Some((version, description)) = migration_info {
                info!("Found migration to revert: {} - {}", version, description);

                // Note: SQLx doesn't support automatic rollbacks, so we'll provide guidance
                error!("❌ Automatic migration rollback is not supported by SQLx");
                error!("To revert migration {}, you need to manually create a new migration that undoes the changes", version);
                error!("Consider creating a new migration file with the reverse operations");

                return Err(FerriteDbError::Core(
                    ferritedb_core::CoreError::Configuration(
                        "Automatic rollback not supported. Create a new migration to undo changes."
                            .to_string(),
                    ),
                ));
            } else {
                info!("No migrations found to revert");
            }
        }
        MigrateCommands::Status => {
            info!("Checking migration status...");

            // Check if migrations table exists
            let table_exists = sqlx::query_as::<_, (String,)>(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations'",
            )
            .fetch_optional(database.pool())
            .await
            .map_err(|e| {
                FerriteDbError::Core(ferritedb_core::CoreError::validation(e.to_string()))
            })?;

            if table_exists.is_none() {
                info!("📋 No migrations have been run yet");
                return Ok(());
            }

            // Get applied migrations
            let migrations = sqlx::query_as::<_, (i64, String, String)>(
                "SELECT version, description, installed_on FROM _sqlx_migrations ORDER BY version",
            )
            .fetch_all(database.pool())
            .await
            .map_err(|e| {
                FerriteDbError::Core(ferritedb_core::CoreError::validation(e.to_string()))
            })?;

            if migrations.is_empty() {
                info!("📋 No migrations have been applied");
            } else {
                info!("📋 Applied migrations:");
                for (version, description, installed_on) in migrations {
                    info!(
                        "  ✅ {} - {} (applied: {})",
                        version, description, installed_on
                    );
                }
            }

            // Check database health
            database
                .health_check()
                .await
                .map_err(FerriteDbError::Core)?;
            info!("💚 Database connection is healthy");
        }
    }
    Ok(())
}

async fn admin_command(config: CoreConfig, action: AdminCommands) -> Result<(), FerriteDbError> {
    use ferritedb_core::{
        auth::AuthService, CreateUserRequest, Database, UserRepository, UserRole,
    };
    use std::io::{self, Write};

    // Create database connection
    let database = Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.connection_timeout,
    )
    .await
    .map_err(FerriteDbError::Core)?;

    // Ensure migrations are run
    database.migrate().await.map_err(FerriteDbError::Core)?;

    let user_repo = UserRepository::new(database.pool().clone());
    let auth_service = AuthService::new(config.auth.clone()).map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::Authentication(e.to_string()))
    })?;

    match action {
        AdminCommands::Create { email, password } => {
            info!("Creating admin user: {}", email);

            // Check if user already exists
            if let Some(_existing) = user_repo
                .find_by_email(&email)
                .await
                .map_err(FerriteDbError::Core)?
            {
                error!("❌ User with email '{}' already exists", email);
                return Err(FerriteDbError::Core(ferritedb_core::CoreError::validation(
                    format!("User with email '{}' already exists", email),
                )));
            }

            // Get password if not provided
            let password = if let Some(pwd) = password {
                pwd
            } else {
                print!("Enter password for admin user: ");
                io::stdout().flush().unwrap();

                // Read password from stdin (note: this will be visible, in production you'd use a proper password input)
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(FerriteDbError::Io)?;
                input.trim().to_string()
            };

            if password.is_empty() {
                error!("❌ Password cannot be empty");
                return Err(FerriteDbError::Core(ferritedb_core::CoreError::Validation(
                    "Password cannot be empty".to_string(),
                )));
            }

            // Hash password
            let password_hash = auth_service.hash_password(&password).map_err(|e| {
                FerriteDbError::Core(ferritedb_core::CoreError::Authentication(e.to_string()))
            })?;

            // Create admin user
            let create_request = CreateUserRequest {
                email: email.clone(),
                password: password.clone(),
                role: Some(UserRole::Admin),
                verified: true,
            };

            let user = user_repo
                .create(create_request, password_hash)
                .await
                .map_err(FerriteDbError::Core)?;

            info!("✅ Admin user created successfully:");
            info!("  ID: {}", user.id);
            info!("  Email: {}", user.email);
            info!("  Role: {}", user.role);
            info!("  Verified: {}", user.verified);
        }
        AdminCommands::List => {
            info!("Listing users...");

            let users = user_repo.list(100, 0).await.map_err(FerriteDbError::Core)?;

            if users.is_empty() {
                info!("📋 No users found");
            } else {
                info!("📋 Found {} users:", users.len());
                println!();
                println!(
                    "{:<36} {:<30} {:<10} {:<10} {:<20}",
                    "ID", "Email", "Role", "Verified", "Created"
                );
                println!("{}", "-".repeat(106));

                for user in users {
                    println!(
                        "{:<36} {:<30} {:<10} {:<10} {:<20}",
                        user.id,
                        user.email,
                        user.role,
                        if user.verified { "✅" } else { "❌" },
                        user.created_at.format("%Y-%m-%d %H:%M")
                    );
                }
            }
        }
        AdminCommands::Delete { user } => {
            info!("Deleting user: {}", user);

            // Try to parse as UUID first, then fall back to email
            let user_to_delete = if let Ok(user_id) = uuid::Uuid::parse_str(&user) {
                user_repo
                    .find_by_id(user_id)
                    .await
                    .map_err(FerriteDbError::Core)?
            } else {
                user_repo
                    .find_by_email(&user)
                    .await
                    .map_err(FerriteDbError::Core)?
            };

            if let Some(user_record) = user_to_delete {
                // Confirm deletion
                print!(
                    "Are you sure you want to delete user '{}' ({})?  [y/N]: ",
                    user_record.email, user_record.id
                );
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(FerriteDbError::Io)?;
                let confirmation = input.trim().to_lowercase();

                if confirmation == "y" || confirmation == "yes" {
                    let deleted = user_repo
                        .delete(user_record.id)
                        .await
                        .map_err(FerriteDbError::Core)?;

                    if deleted {
                        info!("✅ User '{}' deleted successfully", user_record.email);
                    } else {
                        error!("❌ Failed to delete user '{}'", user_record.email);
                    }
                } else {
                    info!("❌ User deletion cancelled");
                }
            } else {
                error!("❌ User '{}' not found", user);
                return Err(FerriteDbError::Core(ferritedb_core::CoreError::validation(
                    format!("User '{}' not found", user),
                )));
            }
        }
    }
    Ok(())
}

async fn import_command(
    config: CoreConfig,
    collection: String,
    file: PathBuf,
) -> Result<(), FerriteDbError> {
    use ferritedb_core::{CollectionRepository, CollectionService, Database, RecordService};
    use std::fs;

    info!(
        "Importing data to collection '{}' from {:?}",
        collection, file
    );

    // Check if file exists
    if !file.exists() {
        error!("❌ File {:?} does not exist", file);
        return Err(FerriteDbError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File {:?} not found", file),
        )));
    }

    // Create database connection
    let database = Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.connection_timeout,
    )
    .await
    .map_err(FerriteDbError::Core)?;

    let collection_repo = CollectionRepository::new(database.pool().clone());
    let collection_service = CollectionService::new(collection_repo.clone());
    let record_service = RecordService::new(database.pool().clone(), collection_service);

    // Check if collection exists
    let _collection_record = collection_repo
        .find_by_name(&collection)
        .await
        .map_err(FerriteDbError::Core)?;
    let _collection_record = match _collection_record {
        Some(c) => c,
        None => {
            error!("❌ Collection '{}' not found", collection);
            return Err(FerriteDbError::Core(ferritedb_core::CoreError::validation(
                format!("Collection '{}' not found", collection),
            )));
        }
    };

    // Read and parse file
    let file_content = fs::read_to_string(&file).map_err(FerriteDbError::Io)?;

    let records: Vec<serde_json::Value> =
        if file.extension().and_then(|s| s.to_str()) == Some("csv") {
            // Parse CSV
            let mut reader = csv::Reader::from_reader(file_content.as_bytes());
            let headers = reader
                .headers()
                .map_err(|e| {
                    FerriteDbError::Core(ferritedb_core::CoreError::validation(format!(
                        "Failed to read CSV headers: {}",
                        e
                    )))
                })?
                .clone();

            let mut records = Vec::new();
            for result in reader.records() {
                let record = result.map_err(|e| {
                    FerriteDbError::Core(ferritedb_core::CoreError::Validation(format!(
                        "Failed to read CSV record: {}",
                        e
                    )))
                })?;

                let mut json_record = serde_json::Map::new();
                for (i, field) in record.iter().enumerate() {
                    if let Some(header) = headers.get(i) {
                        // Try to parse as number, boolean, or keep as string
                        let value = if let Ok(num) = field.parse::<f64>() {
                            serde_json::Value::Number(
                                serde_json::Number::from_f64(num)
                                    .unwrap_or_else(|| serde_json::Number::from(0)),
                            )
                        } else if let Ok(bool_val) = field.parse::<bool>() {
                            serde_json::Value::Bool(bool_val)
                        } else {
                            serde_json::Value::String(field.to_string())
                        };
                        json_record.insert(header.to_string(), value);
                    }
                }
                records.push(serde_json::Value::Object(json_record));
            }
            records
        } else {
            // Parse JSON
            let parsed: serde_json::Value = serde_json::from_str(&file_content).map_err(|e| {
                FerriteDbError::Core(ferritedb_core::CoreError::validation(format!(
                    "Failed to parse JSON: {}",
                    e
                )))
            })?;

            match parsed {
                serde_json::Value::Array(records) => records,
                serde_json::Value::Object(_) => vec![parsed],
                _ => {
                    error!("❌ JSON file must contain an array of objects or a single object");
                    return Err(FerriteDbError::Core(ferritedb_core::CoreError::validation(
                        "JSON file must contain an array of objects or a single object".to_string(),
                    )));
                }
            }
        };

    info!("📥 Found {} records to import", records.len());

    // Import records
    let mut imported_count = 0;
    let mut error_count = 0;

    for (index, record_data) in records.iter().enumerate() {
        match record_service
            .create_record(&collection, record_data.clone())
            .await
        {
            Ok(_) => {
                imported_count += 1;
                if imported_count % 100 == 0 {
                    info!("📥 Imported {} records...", imported_count);
                }
            }
            Err(e) => {
                error_count += 1;
                error!("❌ Failed to import record {}: {}", index + 1, e);
            }
        }
    }

    info!("✅ Import completed:");
    info!("  📥 Successfully imported: {} records", imported_count);
    if error_count > 0 {
        info!("  ❌ Failed to import: {} records", error_count);
    }

    Ok(())
}

async fn export_command(
    config: CoreConfig,
    collection: String,
    output: Option<PathBuf>,
) -> Result<(), FerriteDbError> {
    use ferritedb_core::{CollectionRepository, CollectionService, Database, RecordService};
    use std::fs;

    info!("Exporting collection '{}' to {:?}", collection, output);

    // Create database connection
    let database = Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.connection_timeout,
    )
    .await
    .map_err(FerriteDbError::Core)?;

    let collection_repo = CollectionRepository::new(database.pool().clone());
    let collection_service = CollectionService::new(collection_repo.clone());
    let record_service = RecordService::new(database.pool().clone(), collection_service);

    // Check if collection exists
    let collection_record = collection_repo
        .find_by_name(&collection)
        .await
        .map_err(FerriteDbError::Core)?;
    let _collection_record = match collection_record {
        Some(c) => c,
        None => {
            error!("❌ Collection '{}' not found", collection);
            return Err(FerriteDbError::Core(ferritedb_core::CoreError::Validation(
                format!("Collection '{}' not found", collection),
            )));
        }
    };

    // Get all records from collection
    info!("📤 Fetching records from collection '{}'...", collection);
    let records = record_service
        .list_records(&collection, 1000, 0)
        .await
        .map_err(FerriteDbError::Core)?;

    info!("📤 Found {} records to export", records.len());

    // Determine output file
    let output_file =
        output.unwrap_or_else(|| PathBuf::from(format!("{}_export.json", collection)));

    // Convert records to JSON
    let records_json: Vec<serde_json::Value> = records
        .into_iter()
        .map(|record| {
            let mut json_obj = serde_json::Map::new();
            json_obj.insert(
                "id".to_string(),
                serde_json::Value::String(record.id.to_string()),
            );
            json_obj.insert(
                "created_at".to_string(),
                serde_json::Value::String(record.created_at.to_rfc3339()),
            );
            json_obj.insert(
                "updated_at".to_string(),
                serde_json::Value::String(record.updated_at.to_rfc3339()),
            );

            // Add all data fields
            for (key, value) in record.data {
                json_obj.insert(key, value);
            }

            serde_json::Value::Object(json_obj)
        })
        .collect();

    // Write to file
    let json_output = serde_json::to_string_pretty(&records_json).map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::validation(format!(
            "Failed to serialize records: {}",
            e
        )))
    })?;

    fs::write(&output_file, json_output).map_err(FerriteDbError::Io)?;

    info!("✅ Export completed:");
    info!("  📤 Exported {} records", records_json.len());
    info!("  📁 Output file: {:?}", output_file);

    Ok(())
}

async fn gen_jwt_command(
    config: CoreConfig,
    user: String,
    expires: u64,
) -> Result<(), FerriteDbError> {
    use ferritedb_core::{auth::AuthService, Database, UserRepository};

    info!(
        "Generating JWT for user '{}' (expires in {}s)",
        user, expires
    );

    // Create database connection
    let database = Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.connection_timeout,
    )
    .await
    .map_err(FerriteDbError::Core)?;

    let user_repo = UserRepository::new(database.pool().clone());

    // Create auth service with custom TTL
    let mut auth_config = config.auth.clone();
    auth_config.token_ttl = expires;

    let auth_service = AuthService::new(auth_config).map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::Authentication(e.to_string()))
    })?;

    // Find user by ID or email
    let user_record = if let Ok(user_id) = uuid::Uuid::parse_str(&user) {
        user_repo
            .find_by_id(user_id)
            .await
            .map_err(FerriteDbError::Core)?
    } else {
        user_repo
            .find_by_email(&user)
            .await
            .map_err(FerriteDbError::Core)?
    };

    let user_record = match user_record {
        Some(u) => u,
        None => {
            error!("❌ User '{}' not found", user);
            return Err(FerriteDbError::Core(ferritedb_core::CoreError::validation(
                format!("User '{}' not found", user),
            )));
        }
    };

    // Generate tokens
    let tokens = auth_service.generate_tokens(&user_record).map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::Authentication(e.to_string()))
    })?;

    info!("✅ JWT tokens generated successfully:");
    println!();
    println!("User Information:");
    println!("  ID: {}", user_record.id);
    println!("  Email: {}", user_record.email);
    println!("  Role: {}", user_record.role);
    println!("  Verified: {}", user_record.verified);
    println!();
    println!("Access Token:");
    println!("  {}", tokens.access_token);
    println!();
    println!("Refresh Token:");
    println!("  {}", tokens.refresh_token);
    println!();
    println!("Token Details:");
    println!("  Type: {}", tokens.token_type);
    println!("  Expires in: {} seconds", tokens.expires_in);
    println!(
        "  Expires at: {}",
        chrono::Utc::now() + chrono::Duration::seconds(tokens.expires_in)
    );
    println!();
    println!("Usage Example:");
    println!(
        "  curl -H \"Authorization: Bearer {}\" http://localhost:8090/api/collections",
        tokens.access_token
    );

    Ok(())
}

async fn seed_command(config: CoreConfig, force: bool) -> Result<(), FerriteDbError> {
    use ferritedb_core::{auth::AuthService, Database, SeedService};

    info!("Initializing example collections and seed data...");

    // Create database connection
    let database = Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.connection_timeout,
    )
    .await
    .map_err(FerriteDbError::Core)?;

    // Ensure migrations are run
    database.migrate().await.map_err(FerriteDbError::Core)?;

    // Create auth service
    let auth_service = AuthService::new(config.auth.clone()).map_err(|e| {
        FerriteDbError::Core(ferritedb_core::CoreError::authentication_error(
            e.to_string(),
        ))
    })?;

    // Create seed service
    let seed_service = SeedService::new(database.pool().clone(), auth_service);

    if force {
        info!("🔄 Force mode enabled - will recreate existing collections");
        // TODO: Add logic to drop existing collections if force is true
    }

    // Initialize examples
    seed_service
        .initialize_examples()
        .await
        .map_err(FerriteDbError::Core)?;

    info!("✅ Example collections and seed data initialized successfully!");
    info!("📋 Created collections:");
    info!("  - users (built-in authentication collection)");
    info!("  - posts (example content collection with relations)");
    info!("👥 Created demo users:");
    info!("  - admin@ferritedb.dev (admin)");
    info!("  - alice@example.com (user)");
    info!("  - bob@example.com (user)");
    info!("  - carol@example.com (user)");
    info!("🔒 Demo credentials use development-only passwords. Rotate or recreate these accounts before any production deployment.");
    info!("📝 Created example posts with various statuses and ownership");
    info!("");
    info!("🚀 You can now start the server with: ferritedb serve");
    info!("🌐 Admin interface will be available at: http://localhost:8090/admin");

    Ok(())
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum FerriteDbError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("Core error: {0}")]
    Core(#[from] ferritedb_core::CoreError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Figment error: {0}")]
    Figment(#[from] figment::Error),
}

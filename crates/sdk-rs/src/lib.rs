//! FerriteDB Rust SDK
//!
//! A Rust client library for interacting with FerriteDB backend services.
//!
//! # Example
//!
//! ```rust
//! use ferritedb_sdk_rs::FerriteDbClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = FerriteDbClient::new("http://localhost:8090");
//!     // Use the client to interact with FerriteDB
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod realtime;
pub mod types;

pub use client::FerriteDbClient;
pub use error::{SdkError, SdkResult};
pub use realtime::RealtimeClient;

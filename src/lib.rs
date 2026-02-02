pub mod auth;
pub mod config;
pub mod credentials;
pub mod error;
pub mod protocol;
pub mod transport;

// Re-exports for convenient access
pub use auth::Authenticator;
pub use credentials::Credentials;
pub use error::AuthError;

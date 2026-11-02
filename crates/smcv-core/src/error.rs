use thiserror::Error;

/// A result whose errors are safe to route through the domain boundary.
pub type DomainResult<T> = Result<T, DomainError>;

/// Stable error categories that never embed protected values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DomainError {
    /// The request was not authenticated.
    #[error("authentication required")]
    Unauthenticated,
    /// The principal cannot perform the requested action.
    #[error("resource unavailable")]
    Forbidden,
    /// The resource is absent or intentionally concealed.
    #[error("resource unavailable")]
    NotFound,
    /// A supplied optimistic-concurrency precondition is stale.
    #[error("request conflicts with current state")]
    Conflict,
    /// Input violated a documented bound or invariant.
    #[error("request is invalid")]
    InvalidInput,
    /// Integrity validation failed.
    #[error("protected data integrity check failed")]
    Integrity,
    /// A required dependency is temporarily unavailable.
    #[error("service temporarily unavailable")]
    Unavailable,
}

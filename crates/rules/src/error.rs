use thiserror::Error;

pub type RuleResult<T> = Result<T, RuleError>;

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Evaluation error: {0}")]
    Evaluation(String),
    
    #[error("Invalid rule: {0}")]
    Invalid(String),
}
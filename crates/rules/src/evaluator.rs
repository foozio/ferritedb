use serde_json::Value;
use std::collections::HashMap;

use crate::error::{RuleError, RuleResult};
use crate::parser::{AstNode, BinaryOperator, UnaryOperator};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Minimal User type for rule evaluation (temporary for testing)
#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
    Service,
}

impl User {
    pub fn new(email: String, role: UserRole) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            role,
            verified: false,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Context for rule evaluation containing record, user, and request data
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// The record being accessed (if any)
    pub record: Option<Value>,
    /// The authenticated user (if any)
    pub user: Option<User>,
    /// Request context information
    pub request: RequestContext,
}

/// Request context information available during rule evaluation
#[derive(Debug, Clone, serde::Serialize)]
pub struct RequestContext {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Query parameters
    pub query: HashMap<String, String>,
    /// Client IP address
    pub ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            query: HashMap::new(),
            ip: None,
            user_agent: None,
        }
    }
}

impl EvaluationContext {
    /// Create a new evaluation context
    pub fn new() -> Self {
        Self {
            record: None,
            user: None,
            request: RequestContext::default(),
        }
    }
    
    /// Set the record for evaluation
    pub fn with_record(mut self, record: Value) -> Self {
        self.record = Some(record);
        self
    }
    
    /// Set the user for evaluation
    pub fn with_user(mut self, user: User) -> Self {
        self.user = Some(user);
        self
    }
    
    /// Set the request context for evaluation
    pub fn with_request(mut self, request: RequestContext) -> Self {
        self.request = request;
        self
    }
}

impl Default for EvaluationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Expression evaluator for rule ASTs
pub struct ExpressionEvaluator;

impl ExpressionEvaluator {
    /// Evaluate an AST node in the given context
    pub fn evaluate(ast: &AstNode, context: &EvaluationContext) -> RuleResult<Value> {
        match ast {
            AstNode::String(s) => Ok(Value::String(s.clone())),
            AstNode::Number(n) => Ok(Value::Number(serde_json::Number::from_f64(*n).unwrap())),
            AstNode::Boolean(b) => Ok(Value::Bool(*b)),
            AstNode::Null => Ok(Value::Null),
            AstNode::Array(elements) => {
                let mut array = Vec::new();
                for element in elements {
                    array.push(Self::evaluate(element, context)?);
                }
                Ok(Value::Array(array))
            }
            
            AstNode::Identifier(name) => {
                Self::resolve_identifier(name, context)
            }
            
            AstNode::MemberAccess { object, property } => {
                let object_value = Self::evaluate(object, context)?;
                Self::access_member(&object_value, property, context)
            }
            
            AstNode::BinaryOp { left, operator, right } => {
                Self::evaluate_binary_op(left, operator, right, context)
            }
            
            AstNode::UnaryOp { operator, operand } => {
                Self::evaluate_unary_op(operator, operand, context)
            }
            
            AstNode::FunctionCall { name, args } => {
                Self::evaluate_function_call(name, args, context)
            }
        }
    }
    
    fn resolve_identifier(name: &str, context: &EvaluationContext) -> RuleResult<Value> {
        match name {
            "record" => {
                context.record.clone()
                    .ok_or_else(|| RuleError::Evaluation("No record in context".to_string()))
            }
            "user" => {
                if let Some(user) = &context.user {
                    Ok(serde_json::to_value(user)
                        .map_err(|e| RuleError::Evaluation(format!("Failed to serialize user: {}", e)))?)
                } else {
                    Err(RuleError::Evaluation("No user in context".to_string()))
                }
            }
            "@request" => {
                Ok(serde_json::to_value(&context.request)
                    .map_err(|e| RuleError::Evaluation(format!("Failed to serialize request: {}", e)))?)
            }
            _ => Err(RuleError::Evaluation(format!("Unknown identifier: {}", name))),
        }
    }
    
    fn access_member(object: &Value, property: &str, context: &EvaluationContext) -> RuleResult<Value> {
        match object {
            Value::Object(map) => {
                Ok(map.get(property).cloned().unwrap_or(Value::Null))
            }
            _ => Err(RuleError::Evaluation(format!(
                "Cannot access property '{}' on non-object value",
                property
            ))),
        }
    }
    
    fn evaluate_binary_op(
        left: &AstNode,
        operator: &BinaryOperator,
        right: &AstNode,
        context: &EvaluationContext,
    ) -> RuleResult<Value> {
        match operator {
            BinaryOperator::And => {
                let left_val = Self::evaluate(left, context)?;
                if !Self::is_truthy(&left_val) {
                    return Ok(Value::Bool(false));
                }
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::is_truthy(&right_val)))
            }
            
            BinaryOperator::Or => {
                let left_val = Self::evaluate(left, context)?;
                if Self::is_truthy(&left_val) {
                    return Ok(Value::Bool(true));
                }
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::is_truthy(&right_val)))
            }
            
            BinaryOperator::Equal => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::values_equal(&left_val, &right_val)))
            }
            
            BinaryOperator::NotEqual => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(!Self::values_equal(&left_val, &right_val)))
            }
            
            BinaryOperator::LessThan => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::compare_values(&left_val, &right_val)? < 0))
            }
            
            BinaryOperator::LessThanOrEqual => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::compare_values(&left_val, &right_val)? <= 0))
            }
            
            BinaryOperator::GreaterThan => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::compare_values(&left_val, &right_val)? > 0))
            }
            
            BinaryOperator::GreaterThanOrEqual => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Ok(Value::Bool(Self::compare_values(&left_val, &right_val)? >= 0))
            }
            
            BinaryOperator::Add => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Self::add_values(&left_val, &right_val)
            }
            
            BinaryOperator::Subtract => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Self::subtract_values(&left_val, &right_val)
            }
            
            BinaryOperator::Multiply => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Self::multiply_values(&left_val, &right_val)
            }
            
            BinaryOperator::Divide => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Self::divide_values(&left_val, &right_val)
            }
            
            BinaryOperator::Modulo => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Self::modulo_values(&left_val, &right_val)
            }
            
            BinaryOperator::In => {
                let left_val = Self::evaluate(left, context)?;
                let right_val = Self::evaluate(right, context)?;
                Self::in_operation(&left_val, &right_val)
            }
        }
    }
    
    fn evaluate_unary_op(
        operator: &UnaryOperator,
        operand: &AstNode,
        context: &EvaluationContext,
    ) -> RuleResult<Value> {
        let operand_val = Self::evaluate(operand, context)?;
        
        match operator {
            UnaryOperator::Not => {
                Ok(Value::Bool(!Self::is_truthy(&operand_val)))
            }
            UnaryOperator::Negate => {
                match operand_val {
                    Value::Number(n) => {
                        let num = n.as_f64().ok_or_else(|| {
                            RuleError::Evaluation("Invalid number for negation".to_string())
                        })?;
                        Ok(Value::Number(serde_json::Number::from_f64(-num).unwrap()))
                    }
                    _ => Err(RuleError::Evaluation("Cannot negate non-number value".to_string())),
                }
            }
        }
    }
    
    fn evaluate_function_call(
        name: &str,
        args: &[AstNode],
        context: &EvaluationContext,
    ) -> RuleResult<Value> {
        match name {
            "size" | "length" => {
                if args.len() != 1 {
                    return Err(RuleError::Evaluation(format!(
                        "Function '{}' expects 1 argument, got {}",
                        name, args.len()
                    )));
                }
                
                let arg_val = Self::evaluate(&args[0], context)?;
                match arg_val {
                    Value::Array(arr) => Ok(Value::Number(serde_json::Number::from(arr.len()))),
                    Value::String(s) => Ok(Value::Number(serde_json::Number::from(s.len()))),
                    Value::Object(obj) => Ok(Value::Number(serde_json::Number::from(obj.len()))),
                    _ => Err(RuleError::Evaluation("Cannot get size of non-collection value".to_string())),
                }
            }
            
            "contains" => {
                if args.len() != 2 {
                    return Err(RuleError::Evaluation(format!(
                        "Function 'contains' expects 2 arguments, got {}",
                        args.len()
                    )));
                }
                
                let container = Self::evaluate(&args[0], context)?;
                let item = Self::evaluate(&args[1], context)?;
                
                match container {
                    Value::Array(arr) => {
                        Ok(Value::Bool(arr.iter().any(|v| Self::values_equal(v, &item))))
                    }
                    Value::String(s) => {
                        if let Value::String(substr) = item {
                            Ok(Value::Bool(s.contains(&substr)))
                        } else {
                            Ok(Value::Bool(false))
                        }
                    }
                    _ => Err(RuleError::Evaluation("Cannot check contains on non-collection value".to_string())),
                }
            }
            
            "startsWith" => {
                if args.len() != 2 {
                    return Err(RuleError::Evaluation(format!(
                        "Function 'startsWith' expects 2 arguments, got {}",
                        args.len()
                    )));
                }
                
                let string_val = Self::evaluate(&args[0], context)?;
                let prefix_val = Self::evaluate(&args[1], context)?;
                
                match (string_val, prefix_val) {
                    (Value::String(s), Value::String(prefix)) => {
                        Ok(Value::Bool(s.starts_with(&prefix)))
                    }
                    _ => Err(RuleError::Evaluation("startsWith requires string arguments".to_string())),
                }
            }
            
            "endsWith" => {
                if args.len() != 2 {
                    return Err(RuleError::Evaluation(format!(
                        "Function 'endsWith' expects 2 arguments, got {}",
                        args.len()
                    )));
                }
                
                let string_val = Self::evaluate(&args[0], context)?;
                let suffix_val = Self::evaluate(&args[1], context)?;
                
                match (string_val, suffix_val) {
                    (Value::String(s), Value::String(suffix)) => {
                        Ok(Value::Bool(s.ends_with(&suffix)))
                    }
                    _ => Err(RuleError::Evaluation("endsWith requires string arguments".to_string())),
                }
            }
            
            _ => Err(RuleError::Evaluation(format!("Unknown function: {}", name))),
        }
    }
    
    fn is_truthy(value: &Value) -> bool {
        match value {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::Array(arr) => !arr.is_empty(),
            Value::Object(obj) => !obj.is_empty(),
        }
    }
    
    fn values_equal(left: &Value, right: &Value) -> bool {
        match (left, right) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => {
                a.as_f64().unwrap_or(0.0) == b.as_f64().unwrap_or(0.0)
            }
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| Self::values_equal(x, y))
            }
            (Value::Object(a), Value::Object(b)) => {
                a.len() == b.len() && a.iter().all(|(k, v)| {
                    b.get(k).map_or(false, |v2| Self::values_equal(v, v2))
                })
            }
            _ => false,
        }
    }
    
    fn compare_values(left: &Value, right: &Value) -> RuleResult<i32> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                let a_f64 = a.as_f64().unwrap_or(0.0);
                let b_f64 = b.as_f64().unwrap_or(0.0);
                Ok(a_f64.partial_cmp(&b_f64).unwrap_or(std::cmp::Ordering::Equal) as i32)
            }
            (Value::String(a), Value::String(b)) => {
                Ok(a.cmp(b) as i32)
            }
            _ => Err(RuleError::Evaluation("Cannot compare incompatible types".to_string())),
        }
    }
    
    fn add_values(left: &Value, right: &Value) -> RuleResult<Value> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                let a_f64 = a.as_f64().unwrap_or(0.0);
                let b_f64 = b.as_f64().unwrap_or(0.0);
                Ok(Value::Number(serde_json::Number::from_f64(a_f64 + b_f64).unwrap()))
            }
            (Value::String(a), Value::String(b)) => {
                Ok(Value::String(format!("{}{}", a, b)))
            }
            _ => Err(RuleError::Evaluation("Cannot add incompatible types".to_string())),
        }
    }
    
    fn subtract_values(left: &Value, right: &Value) -> RuleResult<Value> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                let a_f64 = a.as_f64().unwrap_or(0.0);
                let b_f64 = b.as_f64().unwrap_or(0.0);
                Ok(Value::Number(serde_json::Number::from_f64(a_f64 - b_f64).unwrap()))
            }
            _ => Err(RuleError::Evaluation("Cannot subtract non-number values".to_string())),
        }
    }
    
    fn multiply_values(left: &Value, right: &Value) -> RuleResult<Value> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                let a_f64 = a.as_f64().unwrap_or(0.0);
                let b_f64 = b.as_f64().unwrap_or(0.0);
                Ok(Value::Number(serde_json::Number::from_f64(a_f64 * b_f64).unwrap()))
            }
            _ => Err(RuleError::Evaluation("Cannot multiply non-number values".to_string())),
        }
    }
    
    fn divide_values(left: &Value, right: &Value) -> RuleResult<Value> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                let a_f64 = a.as_f64().unwrap_or(0.0);
                let b_f64 = b.as_f64().unwrap_or(0.0);
                if b_f64 == 0.0 {
                    return Err(RuleError::Evaluation("Division by zero".to_string()));
                }
                Ok(Value::Number(serde_json::Number::from_f64(a_f64 / b_f64).unwrap()))
            }
            _ => Err(RuleError::Evaluation("Cannot divide non-number values".to_string())),
        }
    }
    
    fn modulo_values(left: &Value, right: &Value) -> RuleResult<Value> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                let a_f64 = a.as_f64().unwrap_or(0.0);
                let b_f64 = b.as_f64().unwrap_or(0.0);
                if b_f64 == 0.0 {
                    return Err(RuleError::Evaluation("Modulo by zero".to_string()));
                }
                Ok(Value::Number(serde_json::Number::from_f64(a_f64 % b_f64).unwrap()))
            }
            _ => Err(RuleError::Evaluation("Cannot modulo non-number values".to_string())),
        }
    }
    
    fn in_operation(left: &Value, right: &Value) -> RuleResult<Value> {
        match right {
            Value::Array(arr) => {
                Ok(Value::Bool(arr.iter().any(|v| Self::values_equal(left, v))))
            }
            Value::String(s) => {
                if let Value::String(substr) = left {
                    Ok(Value::Bool(s.contains(substr)))
                } else {
                    Ok(Value::Bool(false))
                }
            }
            _ => Err(RuleError::Evaluation("'in' operator requires array or string on right side".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::RuleParser;
    use serde_json::json;

    fn create_test_user() -> User {
        User::new(
            "test@example.com".to_string(),
            UserRole::User,
        )
    }

    fn create_admin_user() -> User {
        User::new(
            "admin@example.com".to_string(),
            UserRole::Admin,
        )
    }

    #[test]
    fn test_evaluate_literals() {
        let context = EvaluationContext::new();
        
        let ast = RuleParser::parse_rule("true").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("42").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, json!(42.0));
        
        let ast = RuleParser::parse_rule("\"hello\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::String("hello".to_string()));
    }
    
    #[test]
    fn test_evaluate_user_context() {
        let user = create_test_user();
        let context = EvaluationContext::new().with_user(user.clone());
        
        let ast = RuleParser::parse_rule("user.role").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::String("user".to_string()));
        
        let ast = RuleParser::parse_rule("user.email").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::String("test@example.com".to_string()));
    }
    
    #[test]
    fn test_evaluate_record_context() {
        let record = json!({
            "id": "123",
            "title": "Test Post",
            "published": true,
            "owner_id": "user-456"
        });
        let context = EvaluationContext::new().with_record(record);
        
        let ast = RuleParser::parse_rule("record.title").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::String("Test Post".to_string()));
        
        let ast = RuleParser::parse_rule("record.published").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_equality_operations() {
        let user = create_admin_user();
        let context = EvaluationContext::new().with_user(user);
        
        let ast = RuleParser::parse_rule("user.role == \"admin\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("user.role != \"user\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_logical_operations() {
        let user = create_admin_user();
        let record = json!({
            "published": true,
            "owner_id": user.id.to_string()
        });
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(record);
        
        let ast = RuleParser::parse_rule("user.role == \"admin\" && record.published == true").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("user.role == \"user\" || record.published == true").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_comparison_operations() {
        let context = EvaluationContext::new();
        
        let ast = RuleParser::parse_rule("10 > 5").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("\"apple\" < \"banana\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_arithmetic_operations() {
        let context = EvaluationContext::new();
        
        let ast = RuleParser::parse_rule("10 + 5").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, json!(15.0));
        
        let ast = RuleParser::parse_rule("\"hello\" + \"world\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::String("helloworld".to_string()));
    }
    
    #[test]
    fn test_evaluate_unary_operations() {
        let user = create_test_user();
        let context = EvaluationContext::new().with_user(user);
        
        let ast = RuleParser::parse_rule("!user.verified").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true)); // User is not verified by default
        
        let ast = RuleParser::parse_rule("-42").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, json!(-42.0));
    }
    
    #[test]
    fn test_evaluate_in_operation() {
        let user = create_admin_user();
        let context = EvaluationContext::new().with_user(user);
        
        let ast = RuleParser::parse_rule("user.role in [\"admin\", \"moderator\"]").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("user.role in [\"user\", \"guest\"]").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(false));
    }
    
    #[test]
    fn test_evaluate_function_calls() {
        let record = json!({
            "tags": ["important", "urgent", "review"],
            "title": "Test Post"
        });
        let context = EvaluationContext::new().with_record(record);
        
        let ast = RuleParser::parse_rule("size(record.tags)").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Number(serde_json::Number::from(3)));
        
        let ast = RuleParser::parse_rule("contains(record.tags, \"important\")").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("startsWith(record.title, \"Test\")").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_request_context() {
        let request = RequestContext {
            method: "POST".to_string(),
            path: "/api/posts".to_string(),
            ..Default::default()
        };
        let context = EvaluationContext::new().with_request(request);
        
        let ast = RuleParser::parse_rule("@request.method == \"POST\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_complex_rule() {
        let user = create_admin_user();
        let record = json!({
            "published": false,
            "owner_id": user.id.to_string(),
            "tags": ["draft"]
        });
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(record);
        
        // Rule: Admin can access any record, or owner can access their own records
        let rule = "user.role == \"admin\" || record.owner_id == user.id";
        let ast = RuleParser::parse_rule(rule).unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_evaluate_error_cases() {
        let context = EvaluationContext::new();
        
        // Division by zero
        let ast = RuleParser::parse_rule("10 / 0").unwrap();
        assert!(ExpressionEvaluator::evaluate(&ast, &context).is_err());
        
        // Unknown identifier
        let ast = RuleParser::parse_rule("unknown_var").unwrap();
        assert!(ExpressionEvaluator::evaluate(&ast, &context).is_err());
        
        // Type mismatch
        let ast = RuleParser::parse_rule("\"string\" + 42").unwrap();
        assert!(ExpressionEvaluator::evaluate(&ast, &context).is_err());
    }
    
    #[test]
    fn test_evaluate_edge_cases() {
        let context = EvaluationContext::new();
        
        // Test null comparisons
        let ast = RuleParser::parse_rule("null == null").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let ast = RuleParser::parse_rule("null != \"something\"").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        // Test boolean operations with different types
        let ast = RuleParser::parse_rule("0 && true").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(false));
        
        let ast = RuleParser::parse_rule("\"\" || false").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(false));
        
        let ast = RuleParser::parse_rule("\"hello\" && 42").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        // Test array operations
        let ast = RuleParser::parse_rule("\"test\" in []").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(false));
        
        // Test function edge cases
        let record = json!({
            "empty_array": [],
            "empty_string": "",
            "null_field": null
        });
        let context = EvaluationContext::new().with_record(record);
        
        let ast = RuleParser::parse_rule("size(record.empty_array)").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, json!(0));
        
        let ast = RuleParser::parse_rule("size(record.empty_string)").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, json!(0));
        
        // Test contains with empty string
        let ast = RuleParser::parse_rule("contains(record.empty_string, \"\")").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_member_access_edge_cases() {
        // Test accessing non-existent properties
        let record = json!({
            "existing_field": "value"
        });
        let context = EvaluationContext::new().with_record(record);
        
        let ast = RuleParser::parse_rule("record.nonexistent_field == null").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        // Test nested object access
        let record = json!({
            "nested": {
                "field": "value"
            }
        });
        let context = EvaluationContext::new().with_record(record);
        
        let ast = RuleParser::parse_rule("record.nested").unwrap();
        let result = ExpressionEvaluator::evaluate(&ast, &context).unwrap();
        assert_eq!(result, json!({"field": "value"}));
    }
}
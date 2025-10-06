use serde_json::Value;
use std::collections::HashMap;

use crate::error::RuleResult;
use crate::evaluator::{EvaluationContext, ExpressionEvaluator};
use crate::parser::{AstNode, RuleParser};
use crate::evaluator::User;

/// Main rules engine for evaluating access control expressions
#[derive(Debug, Clone)]
pub struct RuleEngine {
    /// Cache of parsed ASTs to avoid re-parsing the same rules
    ast_cache: HashMap<String, AstNode>,
}

impl RuleEngine {
    /// Create a new rules engine
    pub fn new() -> Self {
        Self {
            ast_cache: HashMap::new(),
        }
    }
    
    /// Create a new rules engine with pre-validated rules
    pub fn with_rules(rules: &[&str]) -> RuleResult<Self> {
        let engine = Self::new();
        for rule in rules {
            engine.validate_syntax(rule)?;
        }
        Ok(engine)
    }
    
    /// Evaluate a rule expression in the given context
    pub fn evaluate(&mut self, rule: &str, context: &EvaluationContext) -> RuleResult<bool> {
        // Handle empty or whitespace-only rules (default deny)
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(false);
        }
        
        // Get or parse the AST
        let ast = if let Some(cached_ast) = self.ast_cache.get(rule) {
            cached_ast.clone()
        } else {
            let parsed_ast = RuleParser::parse_rule(rule)?;
            self.ast_cache.insert(rule.to_string(), parsed_ast.clone());
            parsed_ast
        };
        
        // Evaluate the AST
        let result = ExpressionEvaluator::evaluate(&ast, context)?;
        
        // Convert result to boolean
        match result {
            Value::Bool(b) => Ok(b),
            Value::Null => Ok(false),
            Value::Number(n) => Ok(n.as_f64().unwrap_or(0.0) != 0.0),
            Value::String(s) => Ok(!s.is_empty()),
            Value::Array(arr) => Ok(!arr.is_empty()),
            Value::Object(obj) => Ok(!obj.is_empty()),
        }
    }
    
    /// Validate rule syntax without evaluating
    pub fn validate_syntax(&self, rule: &str) -> RuleResult<()> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(());
        }
        
        RuleParser::validate_syntax(rule)
    }
    
    /// Clear the AST cache (useful for memory management)
    pub fn clear_cache(&mut self) {
        self.ast_cache.clear();
    }
    
    /// Get the number of cached ASTs
    pub fn cache_size(&self) -> usize {
        self.ast_cache.len()
    }
    
    /// Evaluate a collection rule for a specific operation
    pub fn evaluate_collection_rule(
        &mut self,
        rules: &CollectionRules,
        operation: RuleOperation,
        context: &EvaluationContext,
    ) -> RuleResult<bool> {
        if let Some(rule) = operation.get_rule(rules) {
            self.evaluate(rule, context)
        } else {
            // Default deny when no rule is specified
            Ok(false)
        }
    }
    
    /// Batch validate multiple rules and return detailed error information
    pub fn validate_rules(&self, rules: &[(&str, &str)]) -> Vec<(String, RuleResult<()>)> {
        rules
            .iter()
            .map(|(name, rule)| (name.to_string(), self.validate_syntax(rule)))
            .collect()
    }
    
    /// Check if a rule would allow access (returns true if rule passes or no rule exists)
    pub fn check_access(
        &mut self,
        rule: Option<&str>,
        context: &EvaluationContext,
    ) -> RuleResult<bool> {
        match rule {
            Some(rule_str) => self.evaluate(rule_str, context),
            None => Ok(false), // Default deny
        }
    }
    
    /// Evaluate a rule with just a user context (no record)
    pub fn evaluate_user_rule(&mut self, rule: &str, user: Option<&User>) -> RuleResult<bool> {
        let mut context = EvaluationContext::new();
        if let Some(user) = user {
            context = context.with_user(user.clone());
        }
        self.evaluate(rule, &context)
    }
    
    /// Evaluate a rule with user and record context
    pub fn evaluate_record_rule(
        &mut self,
        rule: &str,
        user: Option<&User>,
        record: Option<&Value>,
    ) -> RuleResult<bool> {
        let mut context = EvaluationContext::new();
        if let Some(user) = user {
            context = context.with_user(user.clone());
        }
        if let Some(record) = record {
            context = context.with_record(record.clone());
        }
        self.evaluate(rule, &context)
    }
    
    /// Evaluate multiple rules with OR logic (any rule passes)
    pub fn evaluate_any(&mut self, rules: &[&str], context: &EvaluationContext) -> RuleResult<bool> {
        for rule in rules {
            if self.evaluate(rule, context)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    
    /// Evaluate multiple rules with AND logic (all rules must pass)
    pub fn evaluate_all(&mut self, rules: &[&str], context: &EvaluationContext) -> RuleResult<bool> {
        for rule in rules {
            if !self.evaluate(rule, context)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Collection access rules for different operations
#[derive(Debug, Clone)]
pub struct CollectionRules {
    pub list_rule: Option<String>,
    pub view_rule: Option<String>,
    pub create_rule: Option<String>,
    pub update_rule: Option<String>,
    pub delete_rule: Option<String>,
}

impl CollectionRules {
    /// Create new collection rules with all rules set to None (default deny)
    pub fn new() -> Self {
        Self {
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
        }
    }
    
    /// Create collection rules that allow public read access
    pub fn public_read() -> Self {
        Self {
            list_rule: Some("true".to_string()),
            view_rule: Some("true".to_string()),
            create_rule: None,
            update_rule: None,
            delete_rule: None,
        }
    }
    
    /// Create collection rules for user-owned resources
    pub fn user_owned() -> Self {
        Self {
            list_rule: Some("user.id != ''".to_string()),
            view_rule: Some("record.owner_id == user.id || user.role == \"admin\"".to_string()),
            create_rule: Some("user.id != ''".to_string()),
            update_rule: Some("record.owner_id == user.id || user.role == \"admin\"".to_string()),
            delete_rule: Some("record.owner_id == user.id || user.role == \"admin\"".to_string()),
        }
    }
    
    /// Create collection rules that allow all operations for authenticated users
    pub fn authenticated_users() -> Self {
        let rule = "@request.auth.id != ''".to_string();
        Self {
            list_rule: Some(rule.clone()),
            view_rule: Some(rule.clone()),
            create_rule: Some(rule.clone()),
            update_rule: Some(rule.clone()),
            delete_rule: Some(rule),
        }
    }
    
    /// Create collection rules that allow all operations for admin users only
    pub fn admin_only() -> Self {
        let rule = "user.role == \"admin\"".to_string();
        Self {
            list_rule: Some(rule.clone()),
            view_rule: Some(rule.clone()),
            create_rule: Some(rule.clone()),
            update_rule: Some(rule.clone()),
            delete_rule: Some(rule),
        }
    }
    
    /// Create collection rules for a typical blog post scenario
    pub fn blog_post_rules() -> Self {
        Self {
            list_rule: Some("record.published == true || user.role == \"admin\"".to_string()),
            view_rule: Some("record.published == true || record.owner_id == user.id || user.role == \"admin\"".to_string()),
            create_rule: Some("user.id != ''".to_string()),
            update_rule: Some("record.owner_id == user.id || user.role == \"admin\"".to_string()),
            delete_rule: Some("user.role == \"admin\"".to_string()),
        }
    }
    
    /// Validate all rules in the collection
    pub fn validate(&self, engine: &RuleEngine) -> RuleResult<()> {
        if let Some(rule) = &self.list_rule {
            engine.validate_syntax(rule)?;
        }
        if let Some(rule) = &self.view_rule {
            engine.validate_syntax(rule)?;
        }
        if let Some(rule) = &self.create_rule {
            engine.validate_syntax(rule)?;
        }
        if let Some(rule) = &self.update_rule {
            engine.validate_syntax(rule)?;
        }
        if let Some(rule) = &self.delete_rule {
            engine.validate_syntax(rule)?;
        }
        Ok(())
    }
    
    /// Validate all rules and return detailed results
    pub fn validate_detailed(&self, engine: &RuleEngine) -> Vec<(String, RuleResult<()>)> {
        let mut results = Vec::new();
        
        if let Some(rule) = &self.list_rule {
            results.push(("list_rule".to_string(), engine.validate_syntax(rule)));
        }
        if let Some(rule) = &self.view_rule {
            results.push(("view_rule".to_string(), engine.validate_syntax(rule)));
        }
        if let Some(rule) = &self.create_rule {
            results.push(("create_rule".to_string(), engine.validate_syntax(rule)));
        }
        if let Some(rule) = &self.update_rule {
            results.push(("update_rule".to_string(), engine.validate_syntax(rule)));
        }
        if let Some(rule) = &self.delete_rule {
            results.push(("delete_rule".to_string(), engine.validate_syntax(rule)));
        }
        
        results
    }
    
    /// Check if any rules are defined
    pub fn has_rules(&self) -> bool {
        self.list_rule.is_some()
            || self.view_rule.is_some()
            || self.create_rule.is_some()
            || self.update_rule.is_some()
            || self.delete_rule.is_some()
    }
    
    /// Get all defined rules as a vector
    pub fn get_all_rules(&self) -> Vec<(&str, &str)> {
        let mut rules = Vec::new();
        
        if let Some(rule) = &self.list_rule {
            rules.push(("list_rule", rule.as_str()));
        }
        if let Some(rule) = &self.view_rule {
            rules.push(("view_rule", rule.as_str()));
        }
        if let Some(rule) = &self.create_rule {
            rules.push(("create_rule", rule.as_str()));
        }
        if let Some(rule) = &self.update_rule {
            rules.push(("update_rule", rule.as_str()));
        }
        if let Some(rule) = &self.delete_rule {
            rules.push(("delete_rule", rule.as_str()));
        }
        
        rules
    }
}

impl Default for CollectionRules {
    fn default() -> Self {
        Self::new()
    }
}

/// Rule operation types for access control
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOperation {
    List,
    View,
    Create,
    Update,
    Delete,
}

impl RuleOperation {
    /// Get the rule for this operation from collection rules
    pub fn get_rule<'a>(&self, rules: &'a CollectionRules) -> Option<&'a String> {
        match self {
            RuleOperation::List => rules.list_rule.as_ref(),
            RuleOperation::View => rules.view_rule.as_ref(),
            RuleOperation::Create => rules.create_rule.as_ref(),
            RuleOperation::Update => rules.update_rule.as_ref(),
            RuleOperation::Delete => rules.delete_rule.as_ref(),
        }
    }
}

impl std::fmt::Display for RuleOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleOperation::List => write!(f, "list"),
            RuleOperation::View => write!(f, "view"),
            RuleOperation::Create => write!(f, "create"),
            RuleOperation::Update => write!(f, "update"),
            RuleOperation::Delete => write!(f, "delete"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::evaluator::{User, UserRole};
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
    fn test_rule_engine_creation() {
        let engine = RuleEngine::new();
        assert_eq!(engine.cache_size(), 0);
    }

    #[test]
    fn test_validate_syntax() {
        let engine = RuleEngine::new();
        
        // Valid rules
        assert!(engine.validate_syntax("user.role == \"admin\"").is_ok());
        assert!(engine.validate_syntax("record.published == true").is_ok());
        assert!(engine.validate_syntax("user.role in [\"admin\", \"moderator\"]").is_ok());
        assert!(engine.validate_syntax("").is_ok()); // Empty rule is valid
        
        // Invalid rules
        assert!(engine.validate_syntax("user.role ==").is_err());
        assert!(engine.validate_syntax("== \"admin\"").is_err());
        assert!(engine.validate_syntax("user.role & \"admin\"").is_err());
    }

    #[test]
    fn test_evaluate_simple_rules() {
        let mut engine = RuleEngine::new();
        let user = create_admin_user();
        let context = EvaluationContext::new().with_user(user);
        
        // Simple equality check
        let result = engine.evaluate("user.role == \"admin\"", &context).unwrap();
        assert!(result);
        
        let result = engine.evaluate("user.role == \"user\"", &context).unwrap();
        assert!(!result);
        
        // Check cache
        assert_eq!(engine.cache_size(), 2);
    }

    #[test]
    fn test_evaluate_empty_rule() {
        let mut engine = RuleEngine::new();
        let context = EvaluationContext::new();
        
        // Empty rule should default to deny
        let result = engine.evaluate("", &context).unwrap();
        assert!(!result);
        
        let result = engine.evaluate("   ", &context).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_user_rule() {
        let mut engine = RuleEngine::new();
        let user = create_admin_user();
        
        let result = engine.evaluate_user_rule("user.role == \"admin\"", Some(&user)).unwrap();
        assert!(result);
        
        let result = engine.evaluate_user_rule("user.role == \"user\"", Some(&user)).unwrap();
        assert!(!result);
        
        // No user context
        let result = engine.evaluate_user_rule("user.role == \"admin\"", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_record_rule() {
        let mut engine = RuleEngine::new();
        let user = create_test_user();
        let record = json!({
            "id": "123",
            "owner_id": user.id.to_string(),
            "published": true
        });
        
        let result = engine.evaluate_record_rule(
            "record.owner_id == user.id",
            Some(&user),
            Some(&record),
        ).unwrap();
        assert!(result);
        
        let result = engine.evaluate_record_rule(
            "record.published == true",
            None,
            Some(&record),
        ).unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_multiple_rules() {
        let mut engine = RuleEngine::new();
        let user = create_admin_user();
        let context = EvaluationContext::new().with_user(user);
        
        let rules = vec!["user.role == \"user\"", "user.role == \"admin\""];
        
        // Any rule passes (OR logic)
        let result = engine.evaluate_any(&rules, &context).unwrap();
        assert!(result);
        
        // All rules must pass (AND logic)
        let result = engine.evaluate_all(&rules, &context).unwrap();
        assert!(!result);
        
        let rules = vec!["user.role == \"admin\"", "user.verified == false"];
        let result = engine.evaluate_all(&rules, &context).unwrap();
        assert!(result);
    }

    #[test]
    fn test_collection_rules_creation() {
        let rules = CollectionRules::new();
        assert!(rules.list_rule.is_none());
        assert!(rules.view_rule.is_none());
        
        let rules = CollectionRules::admin_only();
        assert_eq!(rules.list_rule, Some("user.role == \"admin\"".to_string()));
        
        let rules = CollectionRules::blog_post_rules();
        assert!(rules.list_rule.is_some());
        assert!(rules.view_rule.is_some());
        assert!(rules.create_rule.is_some());
        assert!(rules.update_rule.is_some());
        assert!(rules.delete_rule.is_some());
    }

    #[test]
    fn test_collection_rules_validation() {
        let engine = RuleEngine::new();
        
        let rules = CollectionRules::blog_post_rules();
        assert!(rules.validate(&engine).is_ok());
        
        let mut invalid_rules = CollectionRules::new();
        invalid_rules.list_rule = Some("invalid syntax ==".to_string());
        assert!(invalid_rules.validate(&engine).is_err());
    }

    #[test]
    fn test_rule_operation() {
        let rules = CollectionRules::blog_post_rules();
        
        assert!(RuleOperation::List.get_rule(&rules).is_some());
        assert!(RuleOperation::View.get_rule(&rules).is_some());
        assert!(RuleOperation::Create.get_rule(&rules).is_some());
        assert!(RuleOperation::Update.get_rule(&rules).is_some());
        assert!(RuleOperation::Delete.get_rule(&rules).is_some());
        
        assert_eq!(RuleOperation::List.to_string(), "list");
        assert_eq!(RuleOperation::Create.to_string(), "create");
    }

    #[test]
    fn test_cache_management() {
        let mut engine = RuleEngine::new();
        let context = EvaluationContext::new();
        
        // Evaluate some rules to populate cache
        let _ = engine.evaluate("true", &context);
        let _ = engine.evaluate("false", &context);
        let _ = engine.evaluate("42 > 10", &context);
        
        assert_eq!(engine.cache_size(), 3);
        
        engine.clear_cache();
        assert_eq!(engine.cache_size(), 0);
    }

    #[test]
    fn test_rule_validation_and_integration() {
        let engine = RuleEngine::new();
        
        // Test rule validation
        let rules = vec![
            ("valid_rule", "user.role == \"admin\""),
            ("invalid_rule", "user.role =="),
            ("another_valid", "record.published == true"),
        ];
        
        let results = engine.validate_rules(&rules);
        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_ok());
        assert!(results[1].1.is_err());
        assert!(results[2].1.is_ok());
        
        // Test collection rule evaluation
        let mut engine = RuleEngine::new();
        let rules = CollectionRules::user_owned();
        let user = create_test_user();
        let record = json!({
            "id": "record-1",
            "owner_id": user.id.to_string(),
            "title": "Test Record"
        });
        
        let context = EvaluationContext::new()
            .with_user(user)
            .with_record(record);
        
        // Test view operation (should pass - user owns record)
        let result = engine.evaluate_collection_rule(&rules, RuleOperation::View, &context).unwrap();
        assert!(result);
        
        // Test delete operation (should pass - user owns record)
        let result = engine.evaluate_collection_rule(&rules, RuleOperation::Delete, &context).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_collection_rules_patterns() {
        let engine = RuleEngine::new();
        
        // Test public read rules
        let public_rules = CollectionRules::public_read();
        assert!(public_rules.list_rule.is_some());
        assert!(public_rules.view_rule.is_some());
        assert!(public_rules.create_rule.is_none());
        
        // Test user owned rules
        let user_rules = CollectionRules::user_owned();
        assert!(user_rules.has_rules());
        assert_eq!(user_rules.get_all_rules().len(), 5);
        
        // Test validation
        assert!(public_rules.validate(&engine).is_ok());
        assert!(user_rules.validate(&engine).is_ok());
        
        // Test detailed validation
        let results = user_rules.validate_detailed(&engine);
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|(_, result)| result.is_ok()));
    }
    
    #[test]
    fn test_access_control_helpers() {
        let mut engine = RuleEngine::new();
        let context = EvaluationContext::new();
        
        // Test check_access with no rule (should deny)
        let result = engine.check_access(None, &context).unwrap();
        assert!(!result);
        
        // Test check_access with always true rule
        let result = engine.check_access(Some("true"), &context).unwrap();
        assert!(result);
        
        // Test check_access with always false rule
        let result = engine.check_access(Some("false"), &context).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_engine_with_prevalidated_rules() {
        // Test creating engine with valid rules
        let valid_rules = vec!["user.role == \"admin\"", "record.published == true"];
        let engine = RuleEngine::with_rules(&valid_rules);
        assert!(engine.is_ok());
        
        // Test creating engine with invalid rules
        let invalid_rules = vec!["user.role == \"admin\"", "invalid syntax =="];
        let engine = RuleEngine::with_rules(&invalid_rules);
        assert!(engine.is_err());
    }

    #[test]
    fn test_edge_cases_and_error_handling() {
        let mut engine = RuleEngine::new();
        let context = EvaluationContext::new();
        
        // Test empty rule evaluation
        let result = engine.evaluate("", &context).unwrap();
        assert!(!result); // Empty rule should deny
        
        // Test whitespace-only rule
        let result = engine.evaluate("   \t\n  ", &context).unwrap();
        assert!(!result); // Whitespace-only rule should deny
        
        // Test invalid syntax
        let result = engine.evaluate("invalid syntax ==", &context);
        assert!(result.is_err());
        
        // Test rule with missing context
        let result = engine.evaluate("user.role == \"admin\"", &context);
        assert!(result.is_err()); // Should fail because no user in context
        
        // Test complex nested expressions
        let user = create_admin_user();
        let context = EvaluationContext::new().with_user(user);
        
        let complex_rule = "(user.role == \"admin\" || user.role == \"moderator\") && user.verified == false";
        let result = engine.evaluate(complex_rule, &context).unwrap();
        assert!(result); // Admin user with verified=false should pass
        
        // Test function calls with edge cases
        let record = json!({
            "tags": [],
            "title": "",
            "content": null
        });
        let context = EvaluationContext::new().with_record(record);
        
        let result = engine.evaluate("size(record.tags) == 0", &context).unwrap();
        assert!(result);
        
        let result = engine.evaluate("size(record.title) == 0", &context).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_rule_caching_behavior() {
        let mut engine = RuleEngine::new();
        let context = EvaluationContext::new();
        
        // Test that rules are cached
        assert_eq!(engine.cache_size(), 0);
        
        let _ = engine.evaluate("true", &context);
        assert_eq!(engine.cache_size(), 1);
        
        let _ = engine.evaluate("false", &context);
        assert_eq!(engine.cache_size(), 2);
        
        // Same rule should not increase cache size
        let _ = engine.evaluate("true", &context);
        assert_eq!(engine.cache_size(), 2);
        
        // Clear cache
        engine.clear_cache();
        assert_eq!(engine.cache_size(), 0);
    }
    
    #[test]
    fn test_various_rule_syntaxes() {
        let engine = RuleEngine::new();
        
        // Test various valid syntaxes
        let valid_rules = vec![
            "true",
            "false",
            "user.role == \"admin\"",
            "record.published == true",
            "user.role in [\"admin\", \"moderator\"]",
            "record.score > 10 && record.score < 100",
            "startsWith(record.title, \"Important\")",
            "contains(record.tags, \"urgent\")",
            "size(record.comments) > 0",
            "!record.deleted",
            "record.created_at > \"2023-01-01\"",
            "@request.method == \"GET\"",
            "(user.role == \"admin\" || record.owner_id == user.id) && record.published == true",
        ];
        
        for rule in valid_rules {
            assert!(engine.validate_syntax(rule).is_ok(), "Rule should be valid: {}", rule);
        }
        
        // Test various invalid syntaxes
        let invalid_rules = vec![
            "user.role ==",
            "== \"admin\"",
            "user.role & \"admin\"",
            "user.role in",
            "size(record.tags",
            "user.role == \"admin\" &&",
            "|| user.role == \"admin\"",
            "user.role === \"admin\"", // Triple equals not supported
        ];
        
        for rule in invalid_rules {
            assert!(engine.validate_syntax(rule).is_err(), "Rule should be invalid: {}", rule);
        }
    }

    #[test]
    fn test_complex_blog_scenario() {
        let mut engine = RuleEngine::new();
        let admin = create_admin_user();
        let user = create_test_user();
        
        let published_post = json!({
            "id": "post-1",
            "title": "Published Post",
            "published": true,
            "owner_id": user.id.to_string()
        });
        
        let draft_post = json!({
            "id": "post-2",
            "title": "Draft Post",
            "published": false,
            "owner_id": user.id.to_string()
        });
        
        let rules = CollectionRules::blog_post_rules();
        
        // Test list rule: published posts or admin
        let list_rule = rules.list_rule.as_ref().unwrap();
        
        // Regular user can see published posts
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(published_post.clone());
        assert!(engine.evaluate(list_rule, &context).unwrap());
        
        // Regular user cannot see draft posts
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(draft_post.clone());
        assert!(!engine.evaluate(list_rule, &context).unwrap());
        
        // Admin can see all posts
        let context = EvaluationContext::new()
            .with_user(admin.clone())
            .with_record(draft_post.clone());
        assert!(engine.evaluate(list_rule, &context).unwrap());
        
        // Test update rule: owner or admin
        let update_rule = rules.update_rule.as_ref().unwrap();
        
        // Owner can update their own posts
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(published_post.clone());
        assert!(engine.evaluate(update_rule, &context).unwrap());
        
        // Admin can update any posts
        let context = EvaluationContext::new()
            .with_user(admin.clone())
            .with_record(published_post.clone());
        assert!(engine.evaluate(update_rule, &context).unwrap());
        
        // Test delete rule: admin only
        let delete_rule = rules.delete_rule.as_ref().unwrap();
        
        // Owner cannot delete their own posts
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(published_post.clone());
        assert!(!engine.evaluate(delete_rule, &context).unwrap());
        
        // Admin can delete any posts
        let context = EvaluationContext::new()
            .with_user(admin.clone())
            .with_record(published_post.clone());
        assert!(engine.evaluate(delete_rule, &context).unwrap());
    }
}
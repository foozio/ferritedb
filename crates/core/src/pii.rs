use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Configuration for PII redaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiRedactionConfig {
    /// Fields that should always be redacted
    pub sensitive_fields: HashSet<String>,
    /// Patterns to detect and redact PII in text
    pub pii_patterns: Vec<PiiPattern>,
    /// Replacement text for redacted content
    pub redaction_text: String,
    /// Whether to enable PII detection in field values
    pub detect_pii_in_values: bool,
    /// Whether to redact entire field values or just the PII parts
    pub redact_entire_field: bool,
}

impl Default for PiiRedactionConfig {
    fn default() -> Self {
        let mut sensitive_fields = HashSet::new();
        sensitive_fields.insert("password".to_string());
        sensitive_fields.insert("password_hash".to_string());
        sensitive_fields.insert("secret".to_string());
        sensitive_fields.insert("token".to_string());
        sensitive_fields.insert("api_key".to_string());
        sensitive_fields.insert("private_key".to_string());
        sensitive_fields.insert("ssn".to_string());
        sensitive_fields.insert("social_security_number".to_string());
        sensitive_fields.insert("credit_card".to_string());
        sensitive_fields.insert("credit_card_number".to_string());
        sensitive_fields.insert("bank_account".to_string());
        sensitive_fields.insert("routing_number".to_string());

        Self {
            sensitive_fields,
            pii_patterns: Self::default_pii_patterns(),
            redaction_text: "[REDACTED]".to_string(),
            detect_pii_in_values: true,
            redact_entire_field: false,
        }
    }
}

impl PiiRedactionConfig {
    fn default_pii_patterns() -> Vec<PiiPattern> {
        vec![
            // Email addresses
            PiiPattern {
                name: "email".to_string(),
                regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
                description: "Email addresses".to_string(),
            },
            // Phone numbers (US format)
            PiiPattern {
                name: "phone_us".to_string(),
                regex: r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b".to_string(),
                description: "US phone numbers".to_string(),
            },
            // Social Security Numbers (simplified pattern)
            PiiPattern {
                name: "ssn".to_string(),
                regex: r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b".to_string(),
                description: "Social Security Numbers".to_string(),
            },
            // Credit card numbers (simplified pattern)
            PiiPattern {
                name: "credit_card".to_string(),
                regex: r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b".to_string(),
                description: "Credit card numbers".to_string(),
            },
            // IP addresses
            PiiPattern {
                name: "ip_address".to_string(),
                regex: r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b".to_string(),
                description: "IP addresses".to_string(),
            },
            // MAC addresses
            PiiPattern {
                name: "mac_address".to_string(),
                regex: r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b".to_string(),
                description: "MAC addresses".to_string(),
            },
            // URLs with potential sensitive info
            PiiPattern {
                name: "url_with_token".to_string(),
                regex: r"https?://[^\s]*[?&](?:token|key|secret|password)=[^\s&]*".to_string(),
                description: "URLs containing tokens or secrets".to_string(),
            },
        ]
    }
}

/// Pattern for detecting PII in text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiPattern {
    pub name: String,
    pub regex: String,
    pub description: String,
}

/// PII redaction service
#[derive(Debug)]
pub struct PiiRedactor {
    config: PiiRedactionConfig,
    compiled_patterns: Vec<(String, Regex)>,
}

impl PiiRedactor {
    /// Create a new PII redactor with the given configuration
    pub fn new(config: PiiRedactionConfig) -> Result<Self, regex::Error> {
        let mut compiled_patterns = Vec::new();
        
        for pattern in &config.pii_patterns {
            let regex = Regex::new(&pattern.regex)?;
            compiled_patterns.push((pattern.name.clone(), regex));
        }
        
        Ok(Self {
            config,
            compiled_patterns,
        })
    }

    /// Redact PII from a JSON value
    pub fn redact_json(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                self.redact_json_object(map);
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_json(item);
                }
            }
            Value::String(s) => {
                if self.config.detect_pii_in_values {
                    *s = self.redact_text(s);
                }
            }
            _ => {} // Numbers, booleans, null don't need redaction
        }
    }

    /// Redact PII from a JSON object
    fn redact_json_object(&self, map: &mut Map<String, Value>) {
        for (key, value) in map.iter_mut() {
            // Check if field name is in sensitive fields list
            if self.is_sensitive_field(key) {
                *value = Value::String(self.config.redaction_text.clone());
                continue;
            }

            // Recursively process nested objects and arrays
            match value {
                Value::Object(_) | Value::Array(_) => {
                    self.redact_json(value);
                }
                Value::String(s) => {
                    if self.config.detect_pii_in_values {
                        let redacted = self.redact_text(s);
                        if redacted != *s {
                            if self.config.redact_entire_field {
                                *value = Value::String(self.config.redaction_text.clone());
                            } else {
                                *s = redacted;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Check if a field name is considered sensitive
    fn is_sensitive_field(&self, field_name: &str) -> bool {
        let field_lower = field_name.to_lowercase();
        
        // Check exact matches
        if self.config.sensitive_fields.contains(&field_lower) {
            return true;
        }
        
        // Check if field name contains sensitive keywords
        for sensitive_field in &self.config.sensitive_fields {
            if field_lower.contains(sensitive_field) {
                return true;
            }
        }
        
        false
    }

    /// Redact PII patterns from text
    pub fn redact_text(&self, text: &str) -> String {
        let mut result = text.to_string();
        
        for (pattern_name, regex) in &self.compiled_patterns {
            if regex.is_match(&result) {
                debug!("Found PII pattern '{}' in text", pattern_name);
                result = regex.replace_all(&result, &self.config.redaction_text).to_string();
            }
        }
        
        result
    }

    /// Redact PII from a HashMap (useful for request/response data)
    pub fn redact_hashmap(&self, map: &mut HashMap<String, String>) {
        for (key, value) in map.iter_mut() {
            if self.is_sensitive_field(key) {
                *value = self.config.redaction_text.clone();
            } else if self.config.detect_pii_in_values {
                let redacted = self.redact_text(value);
                if redacted != *value {
                    if self.config.redact_entire_field {
                        *value = self.config.redaction_text.clone();
                    } else {
                        *value = redacted;
                    }
                }
            }
        }
    }

    /// Create a redacted copy of a string (for logging)
    pub fn redact_for_logging(&self, text: &str) -> String {
        self.redact_text(text)
    }

    /// Check if text contains PII without redacting
    pub fn contains_pii(&self, text: &str) -> bool {
        for (_, regex) in &self.compiled_patterns {
            if regex.is_match(text) {
                return true;
            }
        }
        false
    }

    /// Get statistics about PII detection
    pub fn analyze_text(&self, text: &str) -> PiiAnalysis {
        let mut detected_patterns = Vec::new();
        let mut total_matches = 0;
        
        for (pattern_name, regex) in &self.compiled_patterns {
            let matches: Vec<_> = regex.find_iter(text).collect();
            if !matches.is_empty() {
                total_matches += matches.len();
                detected_patterns.push(PiiDetection {
                    pattern_name: pattern_name.clone(),
                    match_count: matches.len(),
                    positions: matches.iter().map(|m| (m.start(), m.end())).collect(),
                });
            }
        }
        
        PiiAnalysis {
            contains_pii: total_matches > 0,
            total_matches,
            detected_patterns,
        }
    }
}

/// Result of PII analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiAnalysis {
    pub contains_pii: bool,
    pub total_matches: usize,
    pub detected_patterns: Vec<PiiDetection>,
}

/// Information about detected PII pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetection {
    pub pattern_name: String,
    pub match_count: usize,
    pub positions: Vec<(usize, usize)>,
}

/// Utility functions for common PII redaction scenarios
pub struct PiiUtils;

impl PiiUtils {
    /// Redact email addresses, keeping domain for debugging
    pub fn redact_email_partial(email: &str) -> String {
        if let Some(at_pos) = email.find('@') {
            let (local, domain) = email.split_at(at_pos);
            if local.len() > 2 {
                format!("{}***{}", &local[..2], domain)
            } else {
                format!("***{}", domain)
            }
        } else {
            "[REDACTED_EMAIL]".to_string()
        }
    }

    /// Redact phone numbers, keeping last 4 digits
    pub fn redact_phone_partial(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 4 {
            format!("***-***-{}", &digits[digits.len()-4..])
        } else {
            "[REDACTED_PHONE]".to_string()
        }
    }

    /// Redact credit card numbers, keeping last 4 digits
    pub fn redact_credit_card_partial(card: &str) -> String {
        let digits: String = card.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 4 {
            format!("****-****-****-{}", &digits[digits.len()-4..])
        } else {
            "[REDACTED_CARD]".to_string()
        }
    }

    /// Redact IP addresses, keeping first octet
    pub fn redact_ip_partial(ip: &str) -> String {
        if let Some(first_dot) = ip.find('.') {
            format!("{}.***.***.***", &ip[..first_dot])
        } else {
            "[REDACTED_IP]".to_string()
        }
    }
}

/// Middleware helper for redacting request/response data
pub fn redact_request_data(
    redactor: &PiiRedactor,
    data: &mut serde_json::Value,
) {
    redactor.redact_json(data);
}

/// Helper for redacting log messages
pub fn redact_log_message(redactor: &PiiRedactor, message: &str) -> String {
    redactor.redact_for_logging(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_pii_redactor_creation() {
        let config = PiiRedactionConfig::default();
        let redactor = PiiRedactor::new(config).unwrap();
        assert!(!redactor.compiled_patterns.is_empty());
    }

    #[test]
    fn test_sensitive_field_detection() {
        let config = PiiRedactionConfig::default();
        let redactor = PiiRedactor::new(config).unwrap();
        
        assert!(redactor.is_sensitive_field("password"));
        assert!(redactor.is_sensitive_field("user_password"));
        assert!(redactor.is_sensitive_field("PASSWORD"));
        assert!(!redactor.is_sensitive_field("username"));
    }

    #[test]
    fn test_json_redaction() {
        let config = PiiRedactionConfig::default();
        let redactor = PiiRedactor::new(config).unwrap();
        
        let mut data = json!({
            "username": "john_doe",
            "password": "secret123",
            "email": "john@example.com",
            "phone": "555-123-4567",
            "nested": {
                "api_key": "abc123",
                "public_info": "safe data"
            }
        });
        
        redactor.redact_json(&mut data);
        
        // Password should be redacted (sensitive field)
        assert_eq!(data["password"], "[REDACTED]");
        assert_eq!(data["nested"]["api_key"], "[REDACTED]");
        
        // Email and phone should be redacted (PII patterns)
        assert_ne!(data["email"], "john@example.com");
        assert_ne!(data["phone"], "555-123-4567");
        
        // Username and public info should remain
        assert_eq!(data["username"], "john_doe");
        assert_eq!(data["nested"]["public_info"], "safe data");
    }

    #[test]
    fn test_text_redaction() {
        let config = PiiRedactionConfig::default();
        let redactor = PiiRedactor::new(config).unwrap();
        
        let text = "Contact me at john@example.com or call 555-123-4567";
        let redacted = redactor.redact_text(text);
        
        assert!(!redacted.contains("john@example.com"));
        assert!(!redacted.contains("555-123-4567"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_pii_analysis() {
        let config = PiiRedactionConfig::default();
        let redactor = PiiRedactor::new(config).unwrap();
        
        let text = "Email: john@example.com, Phone: 555-123-4567";
        let analysis = redactor.analyze_text(text);
        
        assert!(analysis.contains_pii);
        assert_eq!(analysis.total_matches, 2);
        assert_eq!(analysis.detected_patterns.len(), 2);
    }

    #[test]
    fn test_partial_redaction_utils() {
        assert_eq!(PiiUtils::redact_email_partial("john@example.com"), "jo***@example.com");
        assert_eq!(PiiUtils::redact_phone_partial("555-123-4567"), "***-***-4567");
        assert_eq!(PiiUtils::redact_credit_card_partial("4111-1111-1111-1111"), "****-****-****-1111");
        assert_eq!(PiiUtils::redact_ip_partial("192.168.1.1"), "192.***.***.***");
    }

    #[test]
    fn test_contains_pii() {
        let config = PiiRedactionConfig::default();
        let redactor = PiiRedactor::new(config).unwrap();
        
        assert!(redactor.contains_pii("My email is john@example.com"));
        assert!(redactor.contains_pii("Call me at 555-123-4567"));
        assert!(!redactor.contains_pii("This is just normal text"));
    }
}
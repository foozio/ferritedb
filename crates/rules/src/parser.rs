use pest::Parser;
use pest_derive::Parser;

use crate::error::{RuleError, RuleResult};

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct RuleParser;

/// Abstract Syntax Tree node for rule expressions
#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    // Literals
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Array(Vec<AstNode>),

    // Identifiers and member access
    Identifier(String),
    MemberAccess {
        object: Box<AstNode>,
        property: String,
    },

    // Binary operations
    BinaryOp {
        left: Box<AstNode>,
        operator: BinaryOperator,
        right: Box<AstNode>,
    },

    // Unary operations
    UnaryOp {
        operator: UnaryOperator,
        operand: Box<AstNode>,
    },

    // Function calls
    FunctionCall {
        name: String,
        args: Vec<AstNode>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryOperator {
    // Logical
    And,
    Or,

    // Equality
    Equal,
    NotEqual,

    // Relational
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,

    // Arithmetic
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,

    // Membership
    In,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnaryOperator {
    Not,
    Negate,
}

impl RuleParser {
    /// Parse a rule expression string into an AST
    pub fn parse_rule(input: &str) -> RuleResult<AstNode> {
        let pairs = Self::parse(Rule::expression, input)
            .map_err(|e| RuleError::Parse(format!("Parse error: {}", e)))?;

        let pair = pairs
            .into_iter()
            .next()
            .ok_or_else(|| RuleError::Parse("Empty expression".to_string()))?;

        Self::build_ast(pair)
    }

    /// Validate rule syntax without building full AST
    pub fn validate_syntax(input: &str) -> RuleResult<()> {
        Self::parse(Rule::expression, input)
            .map_err(|e| RuleError::Parse(format!("Syntax error: {}", e)))?;
        Ok(())
    }

    fn build_ast(pair: pest::iterators::Pair<Rule>) -> RuleResult<AstNode> {
        match pair.as_rule() {
            Rule::expression => {
                let inner = pair.into_inner().next().unwrap();
                Self::build_ast(inner)
            }

            Rule::or_expr => Self::build_binary_expr_generic(pair),

            Rule::and_expr => Self::build_binary_expr_generic(pair),

            Rule::in_expr => Self::build_binary_expr_generic(pair),

            Rule::equality_expr => Self::build_binary_expr_generic(pair),

            Rule::relational_expr => Self::build_binary_expr_generic(pair),

            Rule::additive_expr => Self::build_binary_expr_generic(pair),

            Rule::multiplicative_expr => Self::build_binary_expr_generic(pair),

            Rule::unary_expr => {
                let mut inner = pair.into_inner();
                let first = inner.next().unwrap();

                match first.as_rule() {
                    Rule::primary_expr => Self::build_ast(first),
                    Rule::unary_op => {
                        let operator = match first.as_str() {
                            "!" => UnaryOperator::Not,
                            "-" => UnaryOperator::Negate,
                            _ => {
                                return Err(RuleError::Parse(format!(
                                    "Unknown unary operator: {}",
                                    first.as_str()
                                )))
                            }
                        };
                        let operand = Self::build_ast(inner.next().unwrap())?;
                        Ok(AstNode::UnaryOp {
                            operator,
                            operand: Box::new(operand),
                        })
                    }
                    _ => Err(RuleError::Parse(format!(
                        "Unexpected rule in unary_expr: {:?}",
                        first.as_rule()
                    ))),
                }
            }

            Rule::primary_expr => {
                let inner = pair.into_inner().next().unwrap();
                Self::build_ast(inner)
            }

            Rule::member_access => {
                let mut inner = pair.into_inner();
                let mut object = Self::build_ast(inner.next().unwrap())?;

                for property_pair in inner {
                    let property = property_pair.as_str().to_string();
                    object = AstNode::MemberAccess {
                        object: Box::new(object),
                        property,
                    };
                }

                Ok(object)
            }

            Rule::request_context => Ok(AstNode::Identifier("@request".to_string())),

            Rule::function_call => {
                let mut inner = pair.into_inner();
                let name = inner.next().unwrap().as_str().to_string();
                let mut args = Vec::new();

                for arg_pair in inner {
                    args.push(Self::build_ast(arg_pair)?);
                }

                Ok(AstNode::FunctionCall { name, args })
            }

            Rule::array_literal => {
                let mut elements = Vec::new();
                for element_pair in pair.into_inner() {
                    elements.push(Self::build_ast(element_pair)?);
                }
                Ok(AstNode::Array(elements))
            }

            Rule::literal => {
                let inner = pair.into_inner().next().unwrap();
                Self::build_ast(inner)
            }

            Rule::string_literal => {
                let inner = pair.into_inner().next().unwrap();
                let content = inner.as_str();
                // Unescape string content
                let unescaped = content
                    .replace("\\\"", "\"")
                    .replace("\\'", "'")
                    .replace("\\\\", "\\")
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\t", "\t");
                Ok(AstNode::String(unescaped))
            }

            Rule::number_literal => {
                let value = pair
                    .as_str()
                    .parse::<f64>()
                    .map_err(|e| RuleError::Parse(format!("Invalid number: {}", e)))?;
                Ok(AstNode::Number(value))
            }

            Rule::boolean_literal => {
                let value = pair.as_str() == "true";
                Ok(AstNode::Boolean(value))
            }

            Rule::null_literal => Ok(AstNode::Null),

            Rule::identifier => Ok(AstNode::Identifier(pair.as_str().to_string())),

            // Operator rules - these should be handled by their parent expressions
            Rule::or_op
            | Rule::and_op
            | Rule::in_op
            | Rule::eq_op
            | Rule::rel_op
            | Rule::add_op
            | Rule::mul_op
            | Rule::unary_op => Err(RuleError::Parse(format!(
                "Operator rule should not be parsed directly: {:?}",
                pair.as_rule()
            ))),

            _ => Err(RuleError::Parse(format!(
                "Unexpected rule: {:?}",
                pair.as_rule()
            ))),
        }
    }

    fn build_binary_expr_generic(pair: pest::iterators::Pair<Rule>) -> RuleResult<AstNode> {
        let mut inner = pair.into_inner();
        let mut left = Self::build_ast(inner.next().unwrap())?;

        while let Some(op_pair) = inner.next() {
            let operator = Self::parse_binary_operator(&op_pair)?;
            let right = Self::build_ast(inner.next().unwrap())?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_binary_operator(pair: &pest::iterators::Pair<Rule>) -> RuleResult<BinaryOperator> {
        match pair.as_str() {
            "==" => Ok(BinaryOperator::Equal),
            "!=" => Ok(BinaryOperator::NotEqual),
            "<" => Ok(BinaryOperator::LessThan),
            "<=" => Ok(BinaryOperator::LessThanOrEqual),
            ">" => Ok(BinaryOperator::GreaterThan),
            ">=" => Ok(BinaryOperator::GreaterThanOrEqual),
            "+" => Ok(BinaryOperator::Add),
            "-" => Ok(BinaryOperator::Subtract),
            "*" => Ok(BinaryOperator::Multiply),
            "/" => Ok(BinaryOperator::Divide),
            "%" => Ok(BinaryOperator::Modulo),
            "||" => Ok(BinaryOperator::Or),
            "&&" => Ok(BinaryOperator::And),
            "in" => Ok(BinaryOperator::In),
            _ => Err(RuleError::Parse(format!(
                "Unknown operator: {}",
                pair.as_str()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_literal() {
        let ast = RuleParser::parse_rule("true").unwrap();
        assert_eq!(ast, AstNode::Boolean(true));

        let ast = RuleParser::parse_rule("42").unwrap();
        assert_eq!(ast, AstNode::Number(42.0));

        let ast = RuleParser::parse_rule("\"hello\"").unwrap();
        assert_eq!(ast, AstNode::String("hello".to_string()));
    }

    #[test]
    fn test_parse_identifier() {
        let ast = RuleParser::parse_rule("user").unwrap();
        assert_eq!(ast, AstNode::Identifier("user".to_string()));
    }

    #[test]
    fn test_parse_member_access() {
        let ast = RuleParser::parse_rule("user.role").unwrap();
        assert_eq!(
            ast,
            AstNode::MemberAccess {
                object: Box::new(AstNode::Identifier("user".to_string())),
                property: "role".to_string(),
            }
        );

        let ast = RuleParser::parse_rule("record.owner.id").unwrap();
        assert_eq!(
            ast,
            AstNode::MemberAccess {
                object: Box::new(AstNode::MemberAccess {
                    object: Box::new(AstNode::Identifier("record".to_string())),
                    property: "owner".to_string(),
                }),
                property: "id".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_binary_operations() {
        let ast = RuleParser::parse_rule("user.role == \"admin\"").unwrap();
        assert_eq!(
            ast,
            AstNode::BinaryOp {
                left: Box::new(AstNode::MemberAccess {
                    object: Box::new(AstNode::Identifier("user".to_string())),
                    property: "role".to_string(),
                }),
                operator: BinaryOperator::Equal,
                right: Box::new(AstNode::String("admin".to_string())),
            }
        );
    }

    #[test]
    fn test_parse_logical_operations() {
        let ast =
            RuleParser::parse_rule("user.role == \"admin\" && record.published == true").unwrap();

        if let AstNode::BinaryOp { operator, .. } = ast {
            assert_eq!(operator, BinaryOperator::And);
        } else {
            panic!("Expected binary operation");
        }
    }

    #[test]
    fn test_parse_unary_operations() {
        let ast = RuleParser::parse_rule("!user.verified").unwrap();
        assert_eq!(
            ast,
            AstNode::UnaryOp {
                operator: UnaryOperator::Not,
                operand: Box::new(AstNode::MemberAccess {
                    object: Box::new(AstNode::Identifier("user".to_string())),
                    property: "verified".to_string(),
                }),
            }
        );
    }

    #[test]
    fn test_parse_array_literal() {
        let ast = RuleParser::parse_rule("[\"admin\", \"moderator\"]").unwrap();
        assert_eq!(
            ast,
            AstNode::Array(vec![
                AstNode::String("admin".to_string()),
                AstNode::String("moderator".to_string()),
            ])
        );
    }

    #[test]
    fn test_parse_function_call() {
        let ast = RuleParser::parse_rule("contains(record.tags, \"important\")").unwrap();
        assert_eq!(
            ast,
            AstNode::FunctionCall {
                name: "contains".to_string(),
                args: vec![
                    AstNode::MemberAccess {
                        object: Box::new(AstNode::Identifier("record".to_string())),
                        property: "tags".to_string(),
                    },
                    AstNode::String("important".to_string()),
                ],
            }
        );
    }

    #[test]
    fn test_parse_complex_expression() {
        let rule =
            "record.published == true || (user.role == \"admin\" && record.owner == user.id)";
        let ast = RuleParser::parse_rule(rule).unwrap();

        if let AstNode::BinaryOp { operator, .. } = ast {
            assert_eq!(operator, BinaryOperator::Or);
        } else {
            panic!("Expected binary operation");
        }
    }

    #[test]
    fn test_validate_syntax() {
        assert!(RuleParser::validate_syntax("user.role == \"admin\"").is_ok());
        assert!(RuleParser::validate_syntax("record.published == true").is_ok());
        assert!(RuleParser::validate_syntax("user.role in [\"admin\", \"moderator\"]").is_ok());

        // Invalid syntax
        assert!(RuleParser::validate_syntax("user.role ==").is_err());
        assert!(RuleParser::validate_syntax("== \"admin\"").is_err());
        assert!(RuleParser::validate_syntax("user.role & \"admin\"").is_err());
    }

    #[test]
    fn test_parse_request_context() {
        let ast = RuleParser::parse_rule("@request.method == \"GET\"").unwrap();
        assert_eq!(
            ast,
            AstNode::BinaryOp {
                left: Box::new(AstNode::MemberAccess {
                    object: Box::new(AstNode::Identifier("@request".to_string())),
                    property: "method".to_string(),
                }),
                operator: BinaryOperator::Equal,
                right: Box::new(AstNode::String("GET".to_string())),
            }
        );
    }
}

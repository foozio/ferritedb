# Filter Expression Parameterization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Support multi-condition filters with `AND`/`OR` while ensuring all user values are parameterized and validated.

**Architecture:** Introduce a small tokenizer that splits filters into simple condition strings and logical operators outside of quotes, parse each condition with the existing single-condition logic, and build SQL with `QueryBuilder` using bound parameters. The filter expression is represented as a flat list of conditions and operators.

**Tech Stack:** Rust, SQLx `QueryBuilder`, `serde_json`, `chrono`, `uuid`.

### Task 1: Add failing tests for multi-condition filters

**Files:**
- Modify: `crates/core/src/records.rs#L1400` (tests module)

**Step 1: Write the failing test**

Add tests near existing filter tests:

```rust
    #[tokio::test]
    async fn test_filter_expression_with_and_or_conditions() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        let record_a = json!({
            "title": "Hello",
            "content": "First",
            "score": 10.0,
            "published": true
        });
        let record_b = json!({
            "title": "Hello",
            "content": "Second",
            "score": 20.0,
            "published": false
        });
        let record_c = json!({
            "title": "Goodbye",
            "content": "Third",
            "score": 30.0,
            "published": true
        });

        record_service
            .create_record("test_posts", record_a)
            .await
            .unwrap();
        record_service
            .create_record("test_posts", record_b)
            .await
            .unwrap();
        record_service
            .create_record("test_posts", record_c)
            .await
            .unwrap();

        let results = record_service
            .list_records_with_query(
                "test_posts",
                10,
                0,
                Some("title = 'Hello' AND published = true OR score >= 30"),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        let titles: Vec<&str> = results
            .iter()
            .map(|r| r.data.get("title").and_then(|v| v.as_str()).unwrap())
            .collect();
        assert!(titles.contains(&"Hello"));
        assert!(titles.contains(&"Goodbye"));

        db.close().await;
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ferritedb-core records::tests::test_filter_expression_with_and_or_conditions`
Expected: FAIL with a validation error about the filter expression.

**Step 3: Commit**

```bash
git add crates/core/src/records.rs
git commit -m "test: cover multi-condition filters"
```

### Task 2: Add tokenizer and filter expression parsing

**Files:**
- Modify: `crates/core/src/records.rs#L430-520`

**Step 1: Write the failing test**

Add a parser-focused test to catch malformed sequences:

```rust
    #[tokio::test]
    async fn test_filter_expression_rejects_invalid_operator_sequence() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        let result = record_service
            .list_records_with_query("test_posts", 10, 0, Some("title = 'Hello' AND"), None, None)
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid filter expression"));

        db.close().await;
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p ferritedb-core records::tests::test_filter_expression_rejects_invalid_operator_sequence`
Expected: FAIL with current behavior accepting single condition only.

**Step 3: Write minimal implementation**

Add new types and helpers near existing filter parsing code:

```rust
#[derive(Clone)]
enum LogicalOp {
    And,
    Or,
}

#[derive(Clone)]
struct FilterExpression {
    conditions: Vec<FilterCondition>,
    operators: Vec<LogicalOp>,
}

fn tokenize_filter_expression(filter: &str) -> CoreResult<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = filter.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(ch);
            }
            _ if !in_single && !in_double => {
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }

    if in_single || in_double {
        return Err(CoreError::ValidationError(
            "Invalid filter expression".to_string(),
        ));
    }

    let mut buf = String::new();
    let mut i = 0;
    let chars: Vec<char> = current.chars().collect();
    while i < chars.len() {
        if chars[i].is_whitespace() {
            buf.push(chars[i]);
            i += 1;
            continue;
        }

        if i + 3 <= chars.len() {
            let slice: String = chars[i..i + 3].iter().collect();
            if slice.eq_ignore_ascii_case("and")
                && (i == 0 || chars[i - 1].is_whitespace())
                && (i + 3 == chars.len() || chars[i + 3].is_whitespace())
            {
                tokens.push(buf.trim().to_string());
                tokens.push("AND".to_string());
                buf.clear();
                i += 3;
                continue;
            }
        }

        if i + 2 <= chars.len() {
            let slice: String = chars[i..i + 2].iter().collect();
            if slice.eq_ignore_ascii_case("or")
                && (i == 0 || chars[i - 1].is_whitespace())
                && (i + 2 == chars.len() || chars[i + 2].is_whitespace())
            {
                tokens.push(buf.trim().to_string());
                tokens.push("OR".to_string());
                buf.clear();
                i += 2;
                continue;
            }
        }

        buf.push(chars[i]);
        i += 1;
    }

    if !buf.trim().is_empty() {
        tokens.push(buf.trim().to_string());
    }

    Ok(tokens)
}

fn parse_filter_expression(&self, filter: &str, collection: &Collection) -> CoreResult<FilterExpression> {
    let tokens = tokenize_filter_expression(filter)?;
    if tokens.is_empty() {
        return Err(CoreError::ValidationError("Invalid filter expression".to_string()));
    }

    let mut conditions = Vec::new();
    let mut operators = Vec::new();
    let mut expect_condition = true;

    for token in tokens {
        if expect_condition {
            if token.eq_ignore_ascii_case("AND") || token.eq_ignore_ascii_case("OR") || token.is_empty() {
                return Err(CoreError::ValidationError("Invalid filter expression".to_string()));
            }
            conditions.push(self.parse_filter_condition(&token, collection)?);
            expect_condition = false;
        } else {
            match token.to_uppercase().as_str() {
                "AND" => operators.push(LogicalOp::And),
                "OR" => operators.push(LogicalOp::Or),
                _ => {
                    return Err(CoreError::ValidationError("Invalid filter expression".to_string()));
                }
            }
            expect_condition = true;
        }
    }

    if expect_condition {
        return Err(CoreError::ValidationError("Invalid filter expression".to_string()));
    }

    if conditions.len() != operators.len() + 1 {
        return Err(CoreError::ValidationError("Invalid filter expression".to_string()));
    }

    Ok(FilterExpression { conditions, operators })
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p ferritedb-core records::tests::test_filter_expression_rejects_invalid_operator_sequence`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/core/src/records.rs
git commit -m "feat: parse filter expressions with logical operators"
```

### Task 3: Apply filter expressions in query builder

**Files:**
- Modify: `crates/core/src/records.rs#L250-330`

**Step 1: Write the failing test**

Re-run the earlier multi-condition test to confirm failure before SQL changes (it should still fail to match correct results). No code changes in this step.

**Step 2: Run test to verify it fails**

Run: `cargo test -p ferritedb-core records::tests::test_filter_expression_with_and_or_conditions`
Expected: FAIL (incorrect count or validation error).

**Step 3: Write minimal implementation**

Update list/query methods to use the new `FilterExpression`:

```rust
        let filter_expression = match filter {
            Some(filter_expr) => Some(self.parse_filter_expression(filter_expr, &collection)?),
            None => None,
        };

        if let Some(expression) = filter_expression.as_ref() {
            query_builder.push(" WHERE ");
            for (idx, condition) in expression.conditions.iter().enumerate() {
                if idx > 0 {
                    match expression.operators[idx - 1] {
                        LogicalOp::And => query_builder.push(" AND "),
                        LogicalOp::Or => query_builder.push(" OR "),
                    };
                }
                query_builder.push("(");
                self.apply_filter_condition(&mut query_builder, condition);
                query_builder.push(")");
            }
        }
```

Apply the same change in `count_records_with_filter`.

**Step 4: Run test to verify it passes**

Run: `cargo test -p ferritedb-core records::tests::test_filter_expression_with_and_or_conditions`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/core/src/records.rs
git commit -m "feat: parameterize multi-condition filters"
```

### Task 4: Full core tests

**Files:**
- None

**Step 1: Run core tests**

Run: `cargo test -p ferritedb-core`
Expected: PASS

**Step 2: Commit (if needed)**

No commit unless tests required adjustments.

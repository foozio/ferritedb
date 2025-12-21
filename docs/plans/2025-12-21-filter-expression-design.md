# Filter Expression Parameterization Design

## Context
`RecordService::list_records_with_query` builds SQL filters from user input. The current parser accepts only a single condition and does not support compound expressions. The backlog item requires parameterized SQL to prevent injection and expanding filter syntax to support multiple conditions.

## Goals
- Parse filter strings with multiple conditions joined by `AND` and `OR` (case-insensitive).
- Ensure all user-supplied values are bound parameters in SQLx.
- Preserve existing field/type validation and `IS NULL` / `IS NOT NULL` handling.
- Return clear `CoreError::ValidationError` on malformed filters.

## Non-Goals
- No parentheses or nested grouping in this pass.
- No changes to sorting or field projection behavior.
- No new comparison operators beyond those already supported.

## Proposed Approach
1. **Tokenizer**: Scan the filter string left-to-right, splitting on `AND`/`OR` tokens only when they appear outside of quoted string literals. The tokenizer emits a sequence of `Condition(String)` and `Op(LogicalOp)` tokens.
2. **Parser**: Convert tokens into a `FilterExpression`:
   - `conditions: Vec<FilterCondition>`
   - `operators: Vec<LogicalOp>` (length = conditions length - 1)
   - Reject malformed sequences (leading/trailing operator, empty condition).
3. **Condition Parsing**: Reuse the existing single-condition logic (currently in `parse_filter_condition`) for each condition string. This preserves field resolution and type validation.
4. **SQL Builder**: Emit SQL with explicit parentheses per condition: `(cond1) AND (cond2) OR (cond3)`. Values are always added via `QueryBuilder::push_bind` and column names are validated against schema and quoted.

## Error Handling
- Any malformed expression yields `CoreError::ValidationError("Invalid filter expression")` or the current field/type-specific validation errors.
- Unknown fields or invalid literals reuse existing validation messages.

## Testing Plan
- Add tests for `AND` and `OR` combinations with mixed types (text/number/bool).
- Add a test ensuring injection attempts remain inert when combined with other conditions.
- Keep existing single-condition tests intact.

## Migration/Rollout
- No schema changes.
- No API version bump; behavior is additive for filters with `AND`/`OR`.

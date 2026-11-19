use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::{CoreError, Result};
use crate::security::valid_column_name;

pub const MAX_FILTERS: usize = 64;
pub const MAX_SELECT_COLS: usize = 256;
pub const MAX_GROUPS: usize = 10_000;
pub const MAX_OUTPUT_ROWS: usize = 10_000;
pub const MAX_INPUT_ROWS: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub column: String,
    pub op: FilterOp,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregateOp {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSpec {
    pub op: AggregateOp,
    #[serde(default)]
    pub column: Option<String>,
    #[serde(default = "default_alias")]
    pub alias: String,
}

fn default_alias() -> String {
    "value".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Query {
    #[serde(default, rename = "where")]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub select: Option<Vec<String>>,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default)]
    pub aggregate: Option<AggregateSpec>,
}

pub fn validate_query(query: &Query) -> Result<()> {
    if query.filters.len() > MAX_FILTERS {
        return Err(CoreError::Invalid(format!(
            "too many filters (max {MAX_FILTERS})"
        )));
    }
    for f in &query.filters {
        if !valid_column_name(&f.column) {
            return Err(CoreError::Invalid(format!(
                "invalid filter column: {}",
                f.column
            )));
        }
    }
    if let Some(cols) = &query.select {
        if cols.len() > MAX_SELECT_COLS {
            return Err(CoreError::Invalid(format!(
                "too many select columns (max {MAX_SELECT_COLS})"
            )));
        }
        for c in cols {
            if !valid_column_name(c) {
                return Err(CoreError::Invalid(format!("invalid select column: {c}")));
            }
        }
    }
    if let Some(group_col) = &query.group_by {
        if !valid_column_name(group_col) {
            return Err(CoreError::Invalid(format!(
                "invalid group_by column: {group_col}"
            )));
        }
    }
    if let Some(agg) = &query.aggregate {
        if !valid_column_name(&agg.alias) {
            return Err(CoreError::Invalid(format!(
                "invalid aggregate alias: {}",
                agg.alias
            )));
        }
        if let Some(col) = &agg.column {
            if !valid_column_name(col) {
                return Err(CoreError::Invalid(format!(
                    "invalid aggregate column: {col}"
                )));
            }
        }
    }
    Ok(())
}

pub fn run_query(rows: &[Value], query: &Query) -> Result<Vec<Value>> {
    run_query_bounded(rows, query, MAX_OUTPUT_ROWS)
}

pub fn run_query_bounded(rows: &[Value], query: &Query, limit: usize) -> Result<Vec<Value>> {
    validate_query(query)?;
    if rows.len() > MAX_INPUT_ROWS {
        return Err(CoreError::Invalid(format!(
            "input rows exceed maximum ({MAX_INPUT_ROWS})"
        )));
    }
    let filtered: Vec<&Value> = rows
        .iter()
        .filter(|row| matches_all(row, &query.filters))
        .collect();
    if let Some(group_col) = &query.group_by {
        let agg = query
            .aggregate
            .as_ref()
            .ok_or_else(|| CoreError::Invalid("group_by requires aggregate".into()))?;
        let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
        for row in filtered {
            let key = group_key(row, group_col);
            if !groups.contains_key(&key) && groups.len() >= MAX_GROUPS {
                return Err(CoreError::Invalid(format!(
                    "too many distinct groups (max {MAX_GROUPS})"
                )));
            }
            groups.entry(key).or_default().push(row);
        }
        let cap = limit.clamp(1, MAX_OUTPUT_ROWS);
        let mut out = Vec::new();
        for (key, group) in groups {
            let mut obj = Map::new();
            obj.insert(group_col.clone(), Value::String(key));
            obj.insert(agg.alias.clone(), aggregate(&group, agg)?);
            out.push(Value::Object(obj));
            if out.len() >= cap {
                break;
            }
        }
        return Ok(out);
    }
    if let Some(agg) = &query.aggregate {
        let mut obj = Map::new();
        obj.insert(agg.alias.clone(), aggregate(&filtered, agg)?);
        return Ok(vec![Value::Object(obj)]);
    }
    let cap = limit.clamp(1, MAX_OUTPUT_ROWS);
    Ok(filtered
        .into_iter()
        .take(cap)
        .map(|row| project(row, query.select.as_deref()))
        .collect())
}

fn matches_all(row: &Value, filters: &[Filter]) -> bool {
    filters.iter().all(|f| matches_filter(row, f))
}

fn matches_filter(row: &Value, filter: &Filter) -> bool {
    let Some(actual) = row.get(&filter.column) else {
        return false;
    };
    match filter.op {
        FilterOp::Eq => actual == &filter.value,
        FilterOp::Ne => actual != &filter.value,
        FilterOp::Gt => cmp(actual, &filter.value).is_some_and(|o| o == Ordering::Greater),
        FilterOp::Lt => cmp(actual, &filter.value).is_some_and(|o| o == Ordering::Less),
        FilterOp::Gte => cmp(actual, &filter.value)
            .is_some_and(|o| o == Ordering::Greater || o == Ordering::Equal),
        FilterOp::Lte => {
            cmp(actual, &filter.value).is_some_and(|o| o == Ordering::Less || o == Ordering::Equal)
        }
        FilterOp::Contains => contains(actual, &filter.value),
    }
}

fn cmp(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let xf = x.as_f64().filter(|v| v.is_finite())?;
            let yf = y.as_f64().filter(|v| v.is_finite())?;
            xf.partial_cmp(&yf)
        }
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn contains(actual: &Value, needle: &Value) -> bool {
    match (actual, needle) {
        (Value::String(h), Value::String(n)) => h.contains(n),
        (Value::Array(arr), v) => arr.iter().any(|x| x == v),
        _ => false,
    }
}

fn group_key(row: &Value, column: &str) -> String {
    match row.get(column) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "null".into(),
    }
}

fn finite_number(v: f64) -> Result<Value> {
    if !v.is_finite() {
        return Err(CoreError::Invalid(
            "numeric aggregate produced non-finite value".into(),
        ));
    }
    Number::from_f64(v)
        .map(Value::Number)
        .ok_or_else(|| CoreError::Invalid("numeric aggregate out of JSON range".into()))
}

fn aggregate(rows: &[&Value], agg: &AggregateSpec) -> Result<Value> {
    match agg.op {
        AggregateOp::Count => Ok(Value::Number((rows.len() as u64).into())),
        AggregateOp::Sum | AggregateOp::Avg | AggregateOp::Min | AggregateOp::Max => {
            let col = agg
                .column
                .as_ref()
                .ok_or_else(|| CoreError::Invalid("numeric aggregate requires column".into()))?;
            let mut values = Vec::new();
            for r in rows {
                if let Some(raw) = r.get(col) {
                    if let Some(v) = raw.as_f64() {
                        if !v.is_finite() {
                            return Err(CoreError::Invalid(
                                "non-finite number in aggregated column".into(),
                            ));
                        }
                        values.push(v);
                    }
                }
            }
            if values.is_empty() {
                return Ok(Value::Null);
            }
            match agg.op {
                AggregateOp::Sum => finite_number(values.iter().sum()),
                AggregateOp::Avg => finite_number(values.iter().sum::<f64>() / values.len() as f64),
                AggregateOp::Min => finite_number(values.into_iter().fold(f64::INFINITY, f64::min)),
                AggregateOp::Max => {
                    finite_number(values.into_iter().fold(f64::NEG_INFINITY, f64::max))
                }
                AggregateOp::Count => unreachable!(),
            }
        }
    }
}

fn project(row: &Value, select: Option<&[String]>) -> Value {
    let Some(cols) = select else {
        return row.clone();
    };
    let mut obj = Map::new();
    for col in cols {
        if let Some(v) = row.get(col) {
            obj.insert(col.clone(), v.clone());
        }
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn group_by_sum_and_count() {
        let rows = vec![
            json!({"region":"eu","amount":10,"name":"alpha"}),
            json!({"region":"eu","amount":20,"name":"beta"}),
            json!({"region":"us","amount":7,"name":"gamma"}),
            json!({"region":"us","amount":3,"name":"alphabet"}),
        ];
        let q = Query {
            filters: vec![Filter {
                column: "name".into(),
                op: FilterOp::Contains,
                value: json!("a"),
            }],
            group_by: Some("region".into()),
            aggregate: Some(AggregateSpec {
                op: AggregateOp::Sum,
                column: Some("amount".into()),
                alias: "total".into(),
            }),
            select: None,
        };
        let out = run_query(&rows, &q).unwrap();
        assert_eq!(
            out,
            vec![
                json!({"region":"eu","total":30.0}),
                json!({"region":"us","total":10.0})
            ]
        );
    }

    #[test]
    fn filters_and_avg() {
        let rows = vec![
            json!({"kind":"a","v":1}),
            json!({"kind":"a","v":3}),
            json!({"kind":"b","v":99}),
        ];
        let q = Query {
            filters: vec![Filter {
                column: "kind".into(),
                op: FilterOp::Eq,
                value: json!("a"),
            }],
            aggregate: Some(AggregateSpec {
                op: AggregateOp::Avg,
                column: Some("v".into()),
                alias: "avg_v".into(),
            }),
            ..Default::default()
        };
        assert_eq!(run_query(&rows, &q).unwrap(), vec![json!({"avg_v":2.0})]);
    }

    #[test]
    fn rejects_invalid_identifiers_and_numeric_overflow() {
        let rows = vec![json!({"region": "eu", "amount": 1e308})];
        let bad_col = Query {
            filters: vec![Filter {
                column: "region; DROP TABLE users;--".into(),
                op: FilterOp::Eq,
                value: json!("eu"),
            }],
            ..Default::default()
        };
        assert!(run_query(&rows, &bad_col).is_err());

        let bad_alias = Query {
            aggregate: Some(AggregateSpec {
                op: AggregateOp::Count,
                column: None,
                alias: "bad alias!".into(),
            }),
            ..Default::default()
        };
        assert!(run_query(&rows, &bad_alias).is_err());

        let overflow_rows = vec![json!({"amount": 1e308}), json!({"amount": 1e308})];
        let sum_overflow = Query {
            aggregate: Some(AggregateSpec {
                op: AggregateOp::Sum,
                column: Some("amount".into()),
                alias: "total".into(),
            }),
            ..Default::default()
        };
        assert!(run_query(&overflow_rows, &sum_overflow).is_err());

        let too_many_filters = Query {
            filters: vec![
                Filter {
                    column: "region".into(),
                    op: FilterOp::Eq,
                    value: json!("eu"),
                };
                MAX_FILTERS + 1
            ],
            ..Default::default()
        };
        assert!(run_query(&rows, &too_many_filters).is_err());
    }
}

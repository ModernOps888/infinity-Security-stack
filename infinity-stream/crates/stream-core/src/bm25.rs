use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::error::{CoreError, Result};

pub const MAX_QUERY_BYTES: usize = 512;
pub const MAX_QUERY_TOKENS: usize = 64;
pub const MAX_TOKEN_BYTES: usize = 128;
pub const MAX_DOC_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_DOC_TOKENS: usize = 8_192;
pub const MAX_DOC_DEPTH: usize = 32;
pub const MAX_DOCS_PER_INDEX: usize = 100_000;
pub const MAX_TOP_K: usize = 100;
pub const MAX_SEARCH_OFFSET: usize = 1_000;

#[derive(Debug, Clone, Default)]
pub struct Bm25Index {
    docs: HashMap<String, HashMap<String, Value>>,
    postings: HashMap<String, HashMap<String, u32>>,
    doc_lengths: HashMap<String, usize>,
    doc_terms: HashMap<String, Vec<String>>,
    total_doc_len: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScoredDoc {
    pub doc_id: String,
    pub score: f64,
}

#[derive(Debug, Clone)]
pub struct PreparedDoc {
    pub doc_id: String,
    fields: HashMap<String, Value>,
    tf: HashMap<String, u32>,
    len: usize,
}

fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut i = max;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

impl Bm25Index {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn doc_count(&self) -> usize {
        self.docs.len()
    }

    pub fn prepare_doc(
        doc_id: impl Into<String>,
        fields: HashMap<String, Value>,
    ) -> Result<PreparedDoc> {
        let doc_id = doc_id.into();
        let text = fields_to_text_bounded(&fields)?;
        let tokens = tokenize_bounded(&text, MAX_DOC_TEXT_BYTES, MAX_DOC_TOKENS);
        let len = tokens.len().max(1);
        let mut tf: HashMap<String, u32> = HashMap::new();
        for t in tokens {
            let entry = tf.entry(t).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        Ok(PreparedDoc {
            doc_id,
            fields,
            tf,
            len,
        })
    }

    pub fn check_batch_capacity(&self, batch: &[PreparedDoc]) -> Result<()> {
        let mut new_ids: HashSet<&str> = HashSet::new();
        for item in batch {
            if !self.docs.contains_key(&item.doc_id) {
                new_ids.insert(item.doc_id.as_str());
            }
        }
        if self.docs.len().saturating_add(new_ids.len()) > MAX_DOCS_PER_INDEX {
            return Err(CoreError::Invalid(format!(
                "index document limit ({MAX_DOCS_PER_INDEX}) exceeded"
            )));
        }
        Ok(())
    }

    pub fn commit_prepared(&mut self, prepared: PreparedDoc) {
        let doc_id = prepared.doc_id;
        if self.docs.contains_key(&doc_id) {
            self.remove(&doc_id);
        }
        let mut terms_for_doc = Vec::with_capacity(prepared.tf.len());
        for (term, count) in prepared.tf {
            terms_for_doc.push(term.clone());
            self.postings
                .entry(term)
                .or_default()
                .insert(doc_id.clone(), count);
        }
        self.doc_terms.insert(doc_id.clone(), terms_for_doc);
        self.doc_lengths.insert(doc_id.clone(), prepared.len);
        self.total_doc_len = self.total_doc_len.saturating_add(prepared.len);
        self.docs.insert(doc_id, prepared.fields);
    }

    pub fn try_index(
        &mut self,
        doc_id: impl Into<String>,
        fields: HashMap<String, Value>,
    ) -> Result<()> {
        let prepared = Self::prepare_doc(doc_id, fields)?;
        self.check_batch_capacity(std::slice::from_ref(&prepared))?;
        self.commit_prepared(prepared);
        Ok(())
    }

    pub fn index(&mut self, doc_id: impl Into<String>, fields: HashMap<String, Value>) {
        let _ = self.try_index(doc_id, fields);
    }

    pub fn remove(&mut self, doc_id: &str) {
        if self.docs.remove(doc_id).is_some() {
            if let Some(len) = self.doc_lengths.remove(doc_id) {
                self.total_doc_len = self.total_doc_len.saturating_sub(len);
            }
            if let Some(terms) = self.doc_terms.remove(doc_id) {
                for term in terms {
                    if let Some(p) = self.postings.get_mut(&term) {
                        p.remove(doc_id);
                        if p.is_empty() {
                            self.postings.remove(&term);
                        }
                    }
                }
            }
        }
    }

    pub fn search_with_offset(
        &self,
        query: &str,
        k: usize,
        offset: usize,
    ) -> Result<Vec<ScoredDoc>> {
        if query.len() > MAX_QUERY_BYTES {
            return Err(CoreError::Invalid(format!(
                "query exceeds maximum length of {MAX_QUERY_BYTES} bytes"
            )));
        }
        if k > MAX_TOP_K {
            return Err(CoreError::Invalid(format!(
                "k exceeds maximum of {MAX_TOP_K}"
            )));
        }
        if offset > MAX_SEARCH_OFFSET {
            return Err(CoreError::Invalid(format!(
                "offset exceeds maximum of {MAX_SEARCH_OFFSET}"
            )));
        }
        let tokens = tokenize_bounded(query, MAX_QUERY_BYTES, MAX_QUERY_TOKENS + 1);
        if tokens.len() > MAX_QUERY_TOKENS {
            return Err(CoreError::Invalid(format!(
                "query exceeds maximum token count of {MAX_QUERY_TOKENS}"
            )));
        }
        Ok(self.score_tokens(tokens, k, offset))
    }

    pub fn search(&self, query: &str, k: usize) -> Vec<ScoredDoc> {
        let bounded_k = k.min(MAX_TOP_K);
        if bounded_k == 0 || self.docs.is_empty() {
            return vec![];
        }
        let tokens = tokenize_bounded(query, MAX_QUERY_BYTES, MAX_QUERY_TOKENS);
        self.score_tokens(tokens, bounded_k, 0)
    }

    fn score_tokens(&self, q_terms: Vec<String>, k: usize, offset: usize) -> Vec<ScoredDoc> {
        if q_terms.is_empty() || self.docs.is_empty() || k == 0 {
            return vec![];
        }
        let n = self.docs.len() as f64;
        if !n.is_finite() || n <= 0.0 {
            return vec![];
        }
        let raw_avgdl = self.total_doc_len as f64 / n;
        let avgdl = if raw_avgdl.is_finite() && raw_avgdl >= 1.0 {
            raw_avgdl
        } else {
            1.0
        };
        let k1 = 1.2;
        let b = 0.75;
        let mut scores: HashMap<String, f64> = HashMap::new();
        let unique: HashSet<String> = q_terms.into_iter().take(MAX_QUERY_TOKENS).collect();
        for term in unique {
            let Some(posting) = self.postings.get(&term) else {
                continue;
            };
            let df = posting.len() as f64;
            let num = (n - df + 0.5).max(0.0);
            let raw_idf = (num / (df + 0.5) + 1.0).ln();
            if !raw_idf.is_finite() || raw_idf <= 0.0 {
                continue;
            }
            for (doc, tf) in posting {
                let freq = *tf as f64;
                if !freq.is_finite() || freq <= 0.0 {
                    continue;
                }
                let dl = (*self.doc_lengths.get(doc).unwrap_or(&1)).max(1) as f64;
                let denom = freq + k1 * (1.0 - b + b * dl / avgdl);
                if denom > 0.0 && denom.is_finite() {
                    let contrib = raw_idf * (freq * (k1 + 1.0)) / denom;
                    if contrib.is_finite() {
                        let total = scores.entry(doc.clone()).or_insert(0.0);
                        let next = *total + contrib;
                        if next.is_finite() {
                            *total = next;
                        }
                    }
                }
            }
        }
        let mut ranked: Vec<ScoredDoc> = scores
            .into_iter()
            .filter(|(_, score)| score.is_finite())
            .map(|(doc_id, score)| ScoredDoc { doc_id, score })
            .collect();
        ranked.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.doc_id.cmp(&b.doc_id))
        });
        if offset >= ranked.len() {
            return vec![];
        }
        ranked.into_iter().skip(offset).take(k).collect()
    }
}

pub fn tokenize(input: &str) -> Vec<String> {
    tokenize_bounded(input, MAX_DOC_TEXT_BYTES, MAX_DOC_TOKENS)
}

pub fn tokenize_bounded(input: &str, max_bytes: usize, max_tokens: usize) -> Vec<String> {
    let end = floor_char_boundary(input, max_bytes);
    input[..end]
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty() && s.len() <= MAX_TOKEN_BYTES && !STOPWORDS.contains(s))
        .take(max_tokens)
        .map(ToOwned::to_owned)
        .collect()
}

fn fields_to_text_bounded(fields: &HashMap<String, Value>) -> Result<String> {
    let mut out = String::new();
    let mut stack: Vec<(usize, &Value)> = Vec::new();
    for (k, v) in fields {
        if out.len() >= MAX_DOC_TEXT_BYTES {
            break;
        }
        out.push(' ');
        out.push_str(k);
        stack.push((1, v));
        while let Some((depth, cur)) = stack.pop() {
            if depth > MAX_DOC_DEPTH {
                return Err(CoreError::Invalid(format!(
                    "document nesting exceeds maximum depth of {MAX_DOC_DEPTH}"
                )));
            }
            if out.len() >= MAX_DOC_TEXT_BYTES {
                break;
            }
            match cur {
                Value::String(s) => {
                    let rem = MAX_DOC_TEXT_BYTES.saturating_sub(out.len());
                    let take = floor_char_boundary(s, rem);
                    out.push(' ');
                    out.push_str(&s[..take]);
                }
                Value::Number(n) => {
                    out.push(' ');
                    out.push_str(&n.to_string());
                }
                Value::Bool(b) => {
                    out.push(' ');
                    out.push_str(if *b { "true" } else { "false" });
                }
                Value::Array(arr) => {
                    for item in arr.iter().rev() {
                        stack.push((depth + 1, item));
                    }
                }
                Value::Object(obj) => {
                    for val in obj.values() {
                        stack.push((depth + 1, val));
                    }
                }
                Value::Null => {}
            }
        }
    }
    Ok(out)
}

const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "he", "in", "is", "it",
    "its", "of", "on", "that", "the", "to", "was", "were", "will", "with", "or", "this", "these",
    "those",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(title: &str, body: &str) -> HashMap<String, Value> {
        HashMap::from([("title".into(), json!(title)), ("body".into(), json!(body))])
    }

    #[test]
    fn tokenizes_and_removes_stopwords() {
        assert_eq!(
            tokenize("The Quick, brown fox!"),
            vec!["quick", "brown", "fox"]
        );
    }

    #[test]
    fn relevant_docs_rank_above_irrelevant() {
        let mut idx = Bm25Index::new();
        idx.index(
            "rust",
            doc("Rust streaming", "append only logs and fast search"),
        );
        idx.index("cake", doc("Cake recipe", "flour sugar butter"));
        idx.index(
            "logs",
            doc("Streaming logs", "durable commit logs search search"),
        );
        let hits = idx.search("streaming commit logs", 3);
        assert_eq!(hits[0].doc_id, "logs");
        assert!(
            hits.iter().position(|h| h.doc_id == "logs").unwrap()
                < hits
                    .iter()
                    .position(|h| h.doc_id == "cake")
                    .unwrap_or(usize::MAX)
        );
    }

    #[test]
    fn enforces_query_token_k_and_offset_bounds() {
        let mut idx = Bm25Index::new();
        idx.index("d1", doc("alpha", "beta gamma"));
        idx.index("d2", doc("alpha", "delta"));

        let too_long = "a".repeat(MAX_QUERY_BYTES + 1);
        assert!(idx.search_with_offset(&too_long, 10, 0).is_err());

        let many_terms = (0..=MAX_QUERY_TOKENS)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(idx.search_with_offset(&many_terms, 10, 0).is_err());

        assert!(idx.search_with_offset("alpha", MAX_TOP_K + 1, 0).is_err());
        assert!(idx
            .search_with_offset("alpha", 10, MAX_SEARCH_OFFSET + 1)
            .is_err());

        let page2 = idx.search_with_offset("alpha", 1, 1).unwrap();
        assert_eq!(page2.len(), 1);
    }

    #[test]
    fn rejects_deeply_nested_documents_and_produces_finite_scores() {
        let mut idx = Bm25Index::new();
        let mut val = json!("leaf");
        for _ in 0..=MAX_DOC_DEPTH {
            val = json!({"n": val});
        }
        assert!(idx
            .try_index("deep", HashMap::from([("nested".into(), val)]))
            .is_err());

        // Single-doc index + empty-text doc: scores must always remain finite.
        idx.try_index("empty", HashMap::from([("empty".into(), json!("the a"))]))
            .unwrap();
        let hits = idx.search("empty", 10);
        for h in hits {
            assert!(h.score.is_finite());
        }
    }
}

use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::path::Path;

use crate::error::{CoreError, Result};
use crate::model::Metric;

pub const MAX_DIM: usize = 4096;
pub const MAX_M: usize = 128;
pub const MAX_EF_CONSTRUCTION: usize = 2048;
pub const MAX_EF_SEARCH: usize = 4096;
pub const MAX_TOP_K: usize = 1000;
pub const MAX_POINTS: usize = 100_000;
pub const MAX_POINT_ID_LEN: usize = 128;

#[derive(Debug, Clone)]
struct DistNode {
    dist: f32,
    id: String,
}

impl PartialEq for DistNode {
    fn eq(&self, other: &Self) -> bool {
        self.dist.to_bits() == other.dist.to_bits() && self.id == other.id
    }
}

impl Eq for DistNode {}

impl Ord for DistNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.dist
            .total_cmp(&other.dist)
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for DistNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn validate_vector(vector: &[f32], expected_dim: usize, label: &str) -> Result<()> {
    if vector.len() != expected_dim {
        return Err(CoreError::Invalid(format!(
            "{label} dimension {} does not match collection dimension {expected_dim}",
            vector.len()
        )));
    }
    if vector.iter().any(|v| !v.is_finite()) {
        return Err(CoreError::Invalid(format!(
            "{label} must contain only finite numbers"
        )));
    }
    Ok(())
}

fn validate_point_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_POINT_ID_LEN || id.chars().any(char::is_control) {
        return Err(CoreError::Invalid(
            "point id must be 1-128 non-control characters".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub id: String,
    pub vector: Vec<f32>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub distance: f32,
    pub score: f32,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Node {
    id: String,
    vector: Vec<f32>,
    metadata: Option<Value>,
    level: usize,
    neighbors: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HnswIndex {
    dim: usize,
    metric: Metric,
    m: usize,
    ef_construction: usize,
    max_level: usize,
    entry_point: Option<String>,
    nodes: HashMap<String, Node>,
}

impl HnswIndex {
    pub fn new(dim: usize, metric: Metric, m: usize, ef_construction: usize) -> Result<Self> {
        if dim == 0 || dim > MAX_DIM {
            return Err(CoreError::Invalid(format!(
                "dimension must be between 1 and {MAX_DIM}"
            )));
        }
        let m = m.clamp(2, MAX_M);
        let ef_construction = ef_construction.clamp(m, MAX_EF_CONSTRUCTION);
        Ok(Self {
            dim,
            metric,
            m,
            ef_construction,
            max_level: 0,
            entry_point: None,
            nodes: HashMap::new(),
        })
    }

    pub fn dim(&self) -> usize {
        self.dim
    }
    pub fn metric(&self) -> Metric {
        self.metric
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    pub fn point(&self, id: &str) -> Option<Point> {
        self.nodes.get(id).map(|n| Point {
            id: n.id.clone(),
            vector: n.vector.clone(),
            metadata: n.metadata.clone(),
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let index: Self = serde_json::from_slice(&bytes)?;
        index.validate_loaded()?;
        Ok(index)
    }

    fn validate_loaded(&self) -> Result<()> {
        if self.dim == 0 || self.dim > MAX_DIM {
            return Err(CoreError::Invalid("invalid loaded index dimension".into()));
        }
        if self.m < 2 || self.m > MAX_M {
            return Err(CoreError::Invalid("invalid loaded index m".into()));
        }
        if self.nodes.len() > MAX_POINTS {
            return Err(CoreError::Invalid("loaded index exceeds point cap".into()));
        }
        if self.nodes.is_empty() != self.entry_point.is_none() {
            return Err(CoreError::Invalid("corrupted index entry point".into()));
        }
        if let Some(ep) = &self.entry_point {
            if !self.nodes.contains_key(ep) {
                return Err(CoreError::Invalid("missing entry point node".into()));
            }
        }
        for (key, node) in &self.nodes {
            validate_point_id(&node.id)?;
            if key != &node.id {
                return Err(CoreError::Invalid("mismatched node key".into()));
            }
            validate_vector(&node.vector, self.dim, "node vector")?;
            if node.level > 32 || node.neighbors.len() != node.level + 1 {
                return Err(CoreError::Invalid("invalid node layer structure".into()));
            }
        }
        Ok(())
    }

    pub fn insert(&mut self, point: Point) -> Result<()> {
        validate_point_id(&point.id)?;
        validate_vector(&point.vector, self.dim, "vector")?;
        if !self.nodes.contains_key(&point.id) && self.nodes.len() >= MAX_POINTS {
            return Err(CoreError::Invalid(format!(
                "collection exceeds maximum vector capacity ({MAX_POINTS})"
            )));
        }
        if self.nodes.contains_key(&point.id) {
            self.delete(&point.id);
        }

        let level = self.random_level();
        let id = point.id.clone();
        let node = Node {
            id: id.clone(),
            vector: point.vector.clone(),
            metadata: point.metadata.clone(),
            level,
            neighbors: vec![Vec::new(); level + 1],
        };

        let Some(mut entry) = self.entry_point.clone() else {
            self.max_level = level;
            self.entry_point = Some(id.clone());
            self.nodes.insert(id, node);
            return Ok(());
        };

        for layer in ((level + 1)..=self.max_level).rev() {
            entry = self.greedy_closest(&point.vector, &entry, layer);
        }

        self.nodes.insert(id.clone(), node);
        let upto = level.min(self.max_level);
        for layer in (0..=upto).rev() {
            let found = self.search_layer(&point.vector, &entry, self.ef_construction, layer);
            let selected = self.select_neighbors(found, self.m);
            for neighbor in selected {
                self.link(&id, &neighbor, layer);
            }
            if let Some(best) = self
                .nodes
                .get(&id)
                .and_then(|n| n.neighbors.get(layer))
                .and_then(|v| v.first())
                .cloned()
            {
                entry = best;
            }
        }

        if level > self.max_level {
            self.max_level = level;
            self.entry_point = Some(id);
        }
        Ok(())
    }

    pub fn upsert_many(&mut self, points: Vec<Point>) -> Result<()> {
        for p in points {
            self.insert(p)?;
        }
        Ok(())
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let existed = self.nodes.remove(id).is_some();
        if !existed {
            return false;
        }
        for node in self.nodes.values_mut() {
            for layer in &mut node.neighbors {
                layer.retain(|n| n != id);
            }
        }
        if self.entry_point.as_deref() == Some(id) {
            let next = self
                .nodes
                .values()
                .max_by_key(|n| n.level)
                .map(|n| (n.id.clone(), n.level));
            match next {
                Some((ep, lvl)) => {
                    self.entry_point = Some(ep);
                    self.max_level = lvl;
                }
                None => {
                    self.entry_point = None;
                    self.max_level = 0;
                }
            }
        }
        existed
    }

    pub fn search(&self, query: &[f32], k: usize, ef: usize) -> Result<Vec<SearchHit>> {
        validate_vector(query, self.dim, "query")?;
        if k > MAX_TOP_K {
            return Err(CoreError::Invalid(format!("k must be <= {MAX_TOP_K}")));
        }
        if ef > MAX_EF_SEARCH {
            return Err(CoreError::Invalid(format!("ef must be <= {MAX_EF_SEARCH}")));
        }
        if k == 0 || self.nodes.is_empty() {
            return Ok(Vec::new());
        }
        let Some(mut entry) = self.entry_point.clone() else {
            return Ok(Vec::new());
        };
        for layer in (1..=self.max_level).rev() {
            entry = self.greedy_closest(query, &entry, layer);
        }
        let ef = ef.max(k).min(self.nodes.len().max(k)).min(MAX_EF_SEARCH);
        let candidates = self.search_layer(query, &entry, ef, 0);
        let mut hits: Vec<_> = candidates
            .into_iter()
            .take(k)
            .filter_map(|(distance, id)| {
                self.nodes.get(&id).map(|n| SearchHit {
                    id: id.clone(),
                    distance,
                    score: self.metric.score(query, &n.vector),
                    metadata: n.metadata.clone(),
                })
            })
            .collect();
        hits.sort_by(|a, b| a.distance.total_cmp(&b.distance));
        Ok(hits)
    }

    pub fn brute_force_search(&self, query: &[f32], k: usize) -> Result<Vec<SearchHit>> {
        validate_vector(query, self.dim, "query")?;
        if k > MAX_TOP_K {
            return Err(CoreError::Invalid(format!("k must be <= {MAX_TOP_K}")));
        }
        if k == 0 || self.nodes.is_empty() {
            return Ok(Vec::new());
        }
        let mut hits: Vec<_> = self
            .nodes
            .values()
            .map(|n| {
                let distance = self.metric.distance(query, &n.vector);
                SearchHit {
                    id: n.id.clone(),
                    distance,
                    score: self.metric.score(query, &n.vector),
                    metadata: n.metadata.clone(),
                }
            })
            .collect();
        hits.sort_by(|a, b| a.distance.total_cmp(&b.distance));
        hits.truncate(k);
        Ok(hits)
    }

    fn random_level(&self) -> usize {
        let mut rng = rand::thread_rng();
        let p = 1.0 / (self.m as f64).ln().max(1.0);
        let mut level = 0;
        while rng.gen::<f64>() < p && level < 32 {
            level += 1;
        }
        level
    }

    fn dist(&self, query: &[f32], id: &str) -> f32 {
        self.nodes
            .get(id)
            .map(|n| self.metric.distance(query, &n.vector))
            .unwrap_or(f32::MAX)
    }

    fn greedy_closest(&self, query: &[f32], entry: &str, layer: usize) -> String {
        let mut current = entry.to_string();
        let mut current_dist = self.dist(query, &current);
        loop {
            let mut changed = false;
            if let Some(node) = self.nodes.get(&current) {
                if let Some(neighbors) = node.neighbors.get(layer) {
                    for nb in neighbors {
                        let d = self.dist(query, nb);
                        if d < current_dist {
                            current_dist = d;
                            current = nb.clone();
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        current
    }

    fn search_layer(
        &self,
        query: &[f32],
        entry: &str,
        ef: usize,
        layer: usize,
    ) -> Vec<(f32, String)> {
        let mut visited = HashSet::new();
        let start_dist = self.dist(query, entry);
        let mut candidates: BinaryHeap<Reverse<DistNode>> = BinaryHeap::new();
        let mut results: BinaryHeap<DistNode> = BinaryHeap::new();
        let start = DistNode {
            dist: start_dist,
            id: entry.to_string(),
        };
        candidates.push(Reverse(start.clone()));
        results.push(start);
        visited.insert(entry.to_string());

        while let Some(Reverse(DistNode {
            dist: cand_dist,
            id: cand_id,
        })) = candidates.pop()
        {
            let worst = results.peek().map(|x| x.dist).unwrap_or(f32::MAX);
            if results.len() >= ef && cand_dist > worst {
                break;
            }
            let neighbors = self
                .nodes
                .get(&cand_id)
                .and_then(|n| n.neighbors.get(layer))
                .cloned()
                .unwrap_or_default();
            for nb in neighbors {
                if !visited.insert(nb.clone()) {
                    continue;
                }
                let d = self.dist(query, &nb);
                let worst = results.peek().map(|x| x.dist).unwrap_or(f32::MAX);
                if results.len() < ef || d < worst {
                    let item = DistNode { dist: d, id: nb };
                    candidates.push(Reverse(item.clone()));
                    results.push(item);
                    if results.len() > ef {
                        results.pop();
                    }
                }
            }
        }
        let mut out: Vec<(f32, String)> = results.into_iter().map(|x| (x.dist, x.id)).collect();
        out.sort_by(|a, b| a.0.total_cmp(&b.0));
        out
    }

    fn select_neighbors(&self, mut candidates: Vec<(f32, String)>, m: usize) -> Vec<String> {
        candidates.sort_by(|a, b| a.0.total_cmp(&b.0));
        candidates.into_iter().take(m).map(|(_, id)| id).collect()
    }

    fn link(&mut self, a: &str, b: &str, layer: usize) {
        if a == b {
            return;
        }
        if let Some(an) = self.nodes.get_mut(a) {
            if layer < an.neighbors.len() && !an.neighbors[layer].iter().any(|x| x == b) {
                an.neighbors[layer].push(b.to_string());
            }
        }
        if let Some(bn) = self.nodes.get_mut(b) {
            if layer < bn.neighbors.len() && !bn.neighbors[layer].iter().any(|x| x == a) {
                bn.neighbors[layer].push(a.to_string());
            }
        }
        self.prune_neighbors(a, layer);
        self.prune_neighbors(b, layer);
    }

    fn prune_neighbors(&mut self, id: &str, layer: usize) {
        let Some(center) = self.nodes.get(id).map(|n| n.vector.clone()) else {
            return;
        };
        let Some(mut neighbors) = self
            .nodes
            .get(id)
            .and_then(|n| n.neighbors.get(layer))
            .cloned()
        else {
            return;
        };
        let metric = self.metric;
        neighbors.sort_by(|x, y| {
            let dx = self
                .nodes
                .get(x)
                .map(|n| metric.distance(&center, &n.vector))
                .unwrap_or(f32::MAX);
            let dy = self
                .nodes
                .get(y)
                .map(|n| metric.distance(&center, &n.vector))
                .unwrap_or(f32::MAX);
            dx.total_cmp(&dy)
        });
        if neighbors.len() > self.m {
            neighbors.truncate(self.m);
        }
        if let Some(node) = self.nodes.get_mut(id) {
            if layer < node.neighbors.len() {
                node.neighbors[layer] = neighbors;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_vec(rng: &mut StdRng, dim: usize) -> Vec<f32> {
        (0..dim).map(|_| rng.gen_range(-1.0..1.0)).collect()
    }

    #[test]
    fn hnsw_recall_vs_bruteforce_is_high() {
        let mut rng = StdRng::seed_from_u64(42);
        let dim = 32;
        let mut index = HnswIndex::new(dim, Metric::Cosine, 16, 128).unwrap();
        for i in 0..2500 {
            index
                .insert(Point {
                    id: format!("p{i}"),
                    vector: rand_vec(&mut rng, dim),
                    metadata: None,
                })
                .unwrap();
        }
        let mut recall_sum = 0.0;
        let queries = 20;
        for _ in 0..queries {
            let q = rand_vec(&mut rng, dim);
            let exact: HashSet<_> = index
                .brute_force_search(&q, 10)
                .unwrap()
                .into_iter()
                .map(|h| h.id)
                .collect();
            let approx: HashSet<_> = index
                .search(&q, 10, 512)
                .unwrap()
                .into_iter()
                .map(|h| h.id)
                .collect();
            let overlap = exact.intersection(&approx).count();
            recall_sum += overlap as f32 / 10.0;
        }
        let recall = recall_sum / queries as f32;
        eprintln!("HNSW recall@10={recall:.3}");
        assert!(recall > 0.90, "recall@10 too low: {recall}");
    }

    #[test]
    fn persists_roundtrip() {
        let mut index = HnswIndex::new(3, Metric::L2, 8, 32).unwrap();
        index
            .insert(Point {
                id: "a".into(),
                vector: vec![0.0, 1.0, 2.0],
                metadata: Some(serde_json::json!({"kind":"x"})),
            })
            .unwrap();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("hnsw_test.idx");
        index.save(&path).unwrap();
        let loaded = HnswIndex::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.search(&[0.0, 1.0, 2.0], 1, 10).unwrap()[0].id, "a");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_non_finite_and_out_of_bounds_vectors_and_limits() {
        assert!(HnswIndex::new(0, Metric::Cosine, 8, 32).is_err());
        assert!(HnswIndex::new(MAX_DIM + 1, Metric::Cosine, 8, 32).is_err());

        let mut index = HnswIndex::new(3, Metric::Cosine, 8, 32).unwrap();
        assert!(index
            .insert(Point {
                id: "bad-nan".into(),
                vector: vec![1.0, f32::NAN, 0.0],
                metadata: None,
            })
            .is_err());
        assert!(index
            .insert(Point {
                id: "bad-inf".into(),
                vector: vec![1.0, f32::INFINITY, 0.0],
                metadata: None,
            })
            .is_err());
        assert!(index
            .insert(Point {
                id: "bad-neginf".into(),
                vector: vec![1.0, f32::NEG_INFINITY, 0.0],
                metadata: None,
            })
            .is_err());
        assert!(index
            .insert(Point {
                id: "".into(),
                vector: vec![1.0, 0.0, 0.0],
                metadata: None,
            })
            .is_err());
        assert!(index
            .insert(Point {
                id: "ok".into(),
                vector: vec![1.0, 0.0, 0.0],
                metadata: None,
            })
            .is_ok());

        // Query validation still runs even on non-empty or k=0 queries.
        assert!(index.search(&[f32::NAN, 0.0, 0.0], 1, 10).is_err());
        assert!(index.search(&[f32::INFINITY, 0.0, 0.0], 0, 10).is_err());
        assert!(index.brute_force_search(&[f32::NAN, 0.0, 0.0], 1).is_err());
        assert!(index.search(&[1.0, 0.0, 0.0], MAX_TOP_K + 1, 10).is_err());
        assert!(index
            .search(&[1.0, 0.0, 0.0], 1, MAX_EF_SEARCH + 1)
            .is_err());
        assert!(index
            .brute_force_search(&[1.0, 0.0, 0.0], MAX_TOP_K + 1)
            .is_err());
    }
}

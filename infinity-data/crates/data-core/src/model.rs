use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Metric {
    Cosine,
    L2,
    Dot,
}

impl Metric {
    pub fn distance(self, a: &[f32], b: &[f32]) -> f32 {
        if a.is_empty()
            || a.len() != b.len()
            || a.iter().any(|v| !v.is_finite())
            || b.iter().any(|v| !v.is_finite())
        {
            return f32::MAX;
        }
        match self {
            Metric::Cosine => {
                // Accumulate in f64 so squaring large finite f32s cannot overflow to Inf/NaN.
                let mut dot = 0.0f64;
                let mut na = 0.0f64;
                let mut nb = 0.0f64;
                for (&x, &y) in a.iter().zip(b) {
                    let xf = f64::from(x);
                    let yf = f64::from(y);
                    dot += xf * yf;
                    na += xf * xf;
                    nb += yf * yf;
                }
                if na == 0.0 || nb == 0.0 {
                    1.0
                } else {
                    let denom = na.sqrt() * nb.sqrt();
                    if !denom.is_finite() || denom == 0.0 {
                        1.0
                    } else {
                        let sim = (dot / denom).clamp(-1.0, 1.0);
                        (1.0 - sim) as f32
                    }
                }
            }
            Metric::L2 => {
                let sum: f64 = a
                    .iter()
                    .zip(b)
                    .map(|(&x, &y)| {
                        let d = f64::from(x) - f64::from(y);
                        d * d
                    })
                    .sum();
                sum.sqrt().min(f64::from(f32::MAX)) as f32
            }
            Metric::Dot => {
                let dot: f64 = a
                    .iter()
                    .zip(b)
                    .map(|(&x, &y)| f64::from(x) * f64::from(y))
                    .sum();
                (-dot).clamp(f64::from(-f32::MAX), f64::from(f32::MAX)) as f32
            }
        }
    }

    pub fn score(self, a: &[f32], b: &[f32]) -> f32 {
        let d = self.distance(a, b);
        if !d.is_finite() {
            return -f32::MAX;
        }
        match self {
            Metric::Cosine => 1.0 - d,
            Metric::L2 | Metric::Dot => -d,
        }
    }
}

impl FromStr for Metric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "cosine" => Ok(Metric::Cosine),
            "l2" | "euclidean" => Ok(Metric::L2),
            "dot" | "inner" => Ok(Metric::Dot),
            _ => Err(format!("unsupported metric: {s}")),
        }
    }
}

impl fmt::Display for Metric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Metric::Cosine => "cosine",
            Metric::L2 => "l2",
            Metric::Dot => "dot",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionInfo {
    pub name: String,
    pub dim: usize,
    pub metric: Metric,
    pub count: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<TableColumn>,
    pub row_count: usize,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_distance_handles_extreme_values_and_invalid_inputs() {
        // Large finite values must not overflow squaring into Inf/NaN.
        let big = [1e25_f32, 1e25_f32];
        let d_cos = Metric::Cosine.distance(&big, &big);
        assert!(d_cos.is_finite() && d_cos.abs() < 1e-5, "d_cos={d_cos}");

        let d_l2 = Metric::L2.distance(&big, &big);
        assert!(d_l2.is_finite() && d_l2 == 0.0);

        // Zero vector cosine distance stays 1.0.
        assert_eq!(Metric::Cosine.distance(&[0.0, 0.0], &[1.0, 0.0]), 1.0);

        // Non-finite or mismatched lengths never produce NaN.
        assert!(!Metric::Cosine
            .distance(&[f32::NAN, 1.0], &[1.0, 1.0])
            .is_nan());
        assert!(!Metric::L2.distance(&[f32::INFINITY], &[1.0]).is_nan());
        assert_eq!(Metric::Dot.distance(&[1.0], &[1.0, 2.0]), f32::MAX);
    }
}

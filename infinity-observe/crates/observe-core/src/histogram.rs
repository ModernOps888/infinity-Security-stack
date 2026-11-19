//! Exponential base-2 histogram for compact value distributions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

pub const MAX_BUCKETS: usize = 4_096;
const MIN_EXP_IDX: i32 = -1_022;
const MAX_EXP_IDX: i32 = 1_022;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramBucket {
    pub lower: f64,
    pub upper: f64,
    pub count: u64,
}

impl HistogramBucket {
    pub fn validate(&self) -> Result<()> {
        if !self.lower.is_finite() || !self.upper.is_finite() {
            return Err(CoreError::Invalid(
                "histogram bucket bounds must be finite".into(),
            ));
        }
        if self.lower < 0.0 || self.upper < 0.0 {
            return Err(CoreError::Invalid(
                "histogram bucket bounds must be non-negative".into(),
            ));
        }
        if self.lower == 0.0 {
            if self.upper != 0.0 {
                return Err(CoreError::Invalid(
                    "zero bucket must have upper == 0.0".into(),
                ));
            }
            return Ok(());
        }
        if self.upper <= self.lower {
            return Err(CoreError::Invalid(
                "histogram bucket upper must exceed lower".into(),
            ));
        }
        let exp = self.lower.log2();
        if !exp.is_finite()
            || exp.fract().abs() > 1e-9
            || (self.upper / self.lower - 2.0).abs() > 1e-9
        {
            return Err(CoreError::Invalid(
                "malformed exponential histogram bucket bounds".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exp2Histogram {
    zero_count: u64,
    buckets: BTreeMap<i32, u64>,
}

impl Exp2Histogram {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_record(&mut self, value: f64) -> Result<()> {
        if !value.is_finite() || value < 0.0 {
            return Err(CoreError::Invalid(
                "histogram value must be finite and non-negative".into(),
            ));
        }
        if value == 0.0 {
            self.zero_count = self.zero_count.saturating_add(1);
            return Ok(());
        }
        let idx = (value.log2().floor() as i32).clamp(MIN_EXP_IDX, MAX_EXP_IDX);
        if value >= 2f64.powi(MAX_EXP_IDX + 1) {
            return Err(CoreError::Invalid(
                "histogram value exceeds representable bucket range".into(),
            ));
        }
        if !self.buckets.contains_key(&idx) && self.buckets.len() >= MAX_BUCKETS {
            return Err(CoreError::Invalid("histogram bucket limit exceeded".into()));
        }
        let entry = self.buckets.entry(idx).or_insert(0);
        *entry = entry.saturating_add(1);
        Ok(())
    }

    pub fn record(&mut self, value: f64) {
        let _ = self.try_record(value);
    }

    pub fn from_buckets(buckets: &[HistogramBucket]) -> Result<Self> {
        if buckets.len() > MAX_BUCKETS {
            return Err(CoreError::Invalid("too many histogram buckets".into()));
        }
        let mut h = Self::new();
        for b in buckets {
            b.validate()?;
            if b.lower == 0.0 {
                h.zero_count = h.zero_count.saturating_add(b.count);
            } else {
                let idx = b.lower.log2().round() as i32;
                if !(MIN_EXP_IDX..=MAX_EXP_IDX).contains(&idx) {
                    return Err(CoreError::Invalid(
                        "histogram bucket exponent out of range".into(),
                    ));
                }
                let entry = h.buckets.entry(idx).or_insert(0);
                *entry = entry.saturating_add(b.count);
            }
        }
        Ok(h)
    }

    pub fn total_count(&self) -> u64 {
        self.buckets
            .values()
            .fold(self.zero_count, |acc, &c| acc.saturating_add(c))
    }

    pub fn buckets(&self) -> Vec<HistogramBucket> {
        let mut out = Vec::new();
        if self.zero_count > 0 {
            out.push(HistogramBucket {
                lower: 0.0,
                upper: 0.0,
                count: self.zero_count,
            });
        }
        out.extend(self.buckets.iter().map(|(idx, count)| HistogramBucket {
            lower: 2f64.powi(*idx),
            upper: 2f64.powi(*idx + 1),
            count: *count,
        }));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_values_by_powers_of_two() {
        let mut h = Exp2Histogram::new();
        for v in [0.0, 0.25, 0.5, 1.0, 1.9, 2.0, 3.99, 4.0, 8.0, 9.0] {
            h.record(v);
        }
        assert_eq!(h.total_count(), 10);
        let buckets = h.buckets();
        assert!(buckets
            .iter()
            .any(|b| b.lower == 0.0 && b.upper == 0.0 && b.count == 1));
        assert!(buckets
            .iter()
            .any(|b| b.lower == 1.0 && b.upper == 2.0 && b.count == 2));
        assert!(buckets
            .iter()
            .any(|b| b.lower == 2.0 && b.upper == 4.0 && b.count == 2));
        assert!(buckets
            .iter()
            .any(|b| b.lower == 8.0 && b.upper == 16.0 && b.count == 2));
    }

    #[test]
    fn rejects_invalid_values_and_malformed_buckets() {
        let mut h = Exp2Histogram::new();
        assert!(h.try_record(f64::NAN).is_err());
        assert!(h.try_record(f64::INFINITY).is_err());
        assert!(h.try_record(-1.0).is_err());
        assert!(h.try_record(f64::MAX).is_err());
        assert_eq!(h.total_count(), 0);

        assert!(Exp2Histogram::from_buckets(&[HistogramBucket {
            lower: 1.0,
            upper: 0.5,
            count: 1,
        }])
        .is_err());
        assert!(Exp2Histogram::from_buckets(&[HistogramBucket {
            lower: 0.0,
            upper: 1.0,
            count: 1,
        }])
        .is_err());
        assert!(Exp2Histogram::from_buckets(&[HistogramBucket {
            lower: f64::NAN,
            upper: 2.0,
            count: 1,
        }])
        .is_err());
        assert!(Exp2Histogram::from_buckets(&[HistogramBucket {
            lower: 1.0,
            upper: 3.0,
            count: 1,
        }])
        .is_err());
    }
}

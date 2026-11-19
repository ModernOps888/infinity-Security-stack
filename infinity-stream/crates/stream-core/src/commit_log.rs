use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{LogRecord, NewRecord};
use crate::security::validate_resource_name;

pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = MAX_RECORD_BYTES + 32;
pub const MAX_READ_RECORDS: usize = 1_000;

#[derive(Debug, Clone)]
struct OffsetPos {
    segment: PathBuf,
    pos: u64,
}

#[derive(Debug, Default)]
struct PartitionLog {
    next_offset: u64,
    current_base: u64,
    current_size: u64,
    index: HashMap<u64, OffsetPos>,
}

#[derive(Debug)]
pub struct CommitLog {
    root: PathBuf,
    segment_max_bytes: u64,
    partitions: HashMap<(String, u32), PartitionLog>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRecord {
    offset: u64,
    key: Option<String>,
    value: serde_json::Value,
    timestamp: String,
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn read_bounded_frame<R: BufRead>(reader: &mut R, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let max_read = (limit as u64).saturating_add(1);
    reader.take(max_read).read_until(b'\n', &mut buf)?;
    if buf.is_empty() {
        return Ok(None);
    }
    if buf.len() > limit {
        return Err(CoreError::Invalid(
            "segment frame exceeds maximum allowed size".into(),
        ));
    }
    Ok(Some(buf))
}

fn parse_frame(raw: &[u8], path: &Path) -> Result<StoredRecord> {
    if !raw.ends_with(b"\n") {
        return Err(CoreError::Invalid(format!(
            "truncated frame in segment {}",
            path.display()
        )));
    }
    let trimmed = std::str::from_utf8(raw)
        .map_err(|_| CoreError::Invalid(format!("non-utf8 frame in segment {}", path.display())))?
        .trim_end_matches(['\r', '\n']);
    let Some((crc_hex, json_part)) = trimmed.split_once(':') else {
        return Err(CoreError::Invalid(format!(
            "missing frame checksum in segment {}",
            path.display()
        )));
    };
    if crc_hex.len() != 8 {
        return Err(CoreError::Invalid(format!(
            "malformed frame checksum in segment {}",
            path.display()
        )));
    }
    let expected_crc = u32::from_str_radix(crc_hex, 16).map_err(|_| {
        CoreError::Invalid(format!(
            "invalid checksum hex in segment {}",
            path.display()
        ))
    })?;
    let actual_crc = crc32(json_part.as_bytes());
    if expected_crc != actual_crc {
        return Err(CoreError::Invalid(format!(
            "corrupt CRC in segment {}",
            path.display()
        )));
    }
    serde_json::from_str(json_part)
        .map_err(|e| CoreError::Invalid(format!("corrupt segment payload {}: {e}", path.display())))
}

impl CommitLog {
    /// Reject topic names that could escape the log root or hit reserved
    /// Windows device paths (defense-in-depth at the FS sink).
    fn ensure_safe_topic(topic: &str) -> Result<()> {
        validate_resource_name(topic)
    }

    fn ensure_contained_in(root: &Path, target: &Path) -> Result<()> {
        let rel = target
            .strip_prefix(root)
            .map_err(|_| CoreError::Invalid("path escapes commit log root".into()))?;
        let mut cur = root.to_path_buf();
        for comp in rel.components() {
            match comp {
                Component::Normal(part) => {
                    cur.push(part);
                    if let Ok(meta) = fs::symlink_metadata(&cur) {
                        if meta.file_type().is_symlink() {
                            return Err(CoreError::Invalid(
                                "symlinks are not permitted inside commit log".into(),
                            ));
                        }
                        let canon = fs::canonicalize(&cur)?;
                        if !canon.starts_with(root) {
                            return Err(CoreError::Invalid(
                                "canonical path escapes commit log root".into(),
                            ));
                        }
                    }
                }
                _ => {
                    return Err(CoreError::Invalid(
                        "disallowed path component inside commit log".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn ensure_contained(&self, target: &Path) -> Result<()> {
        Self::ensure_contained_in(&self.root, target)
    }

    pub fn open(data_dir: impl AsRef<Path>, segment_max_bytes: u64) -> Result<Self> {
        let root_raw = data_dir.as_ref().join("logs");
        fs::create_dir_all(&root_raw)?;
        if fs::symlink_metadata(&root_raw)?.file_type().is_symlink() {
            return Err(CoreError::Invalid(
                "commit log root must not be a symlink".into(),
            ));
        }
        let root = fs::canonicalize(&root_raw)?;
        let mut me = Self {
            root,
            segment_max_bytes: segment_max_bytes.max(256),
            partitions: HashMap::new(),
        };
        me.recover()?;
        Ok(me)
    }

    pub fn create_partition(&mut self, topic: &str, partition: u32) -> Result<()> {
        Self::ensure_safe_topic(topic)?;
        let dir = self.partition_dir(topic, partition);
        self.ensure_contained(&dir)?;
        fs::create_dir_all(&dir)?;
        self.ensure_contained(&dir)?;
        self.partitions
            .entry((topic.to_string(), partition))
            .or_default();
        Ok(())
    }

    pub fn delete_topic(&mut self, topic: &str) -> Result<()> {
        Self::ensure_safe_topic(topic)?;
        let dir = self.root.join(topic);
        self.ensure_contained(&dir)?;
        if let Ok(meta) = fs::symlink_metadata(&dir) {
            if meta.file_type().is_symlink() {
                return Err(CoreError::Invalid(
                    "refusing to remove symlink topic directory".into(),
                ));
            }
            if meta.is_dir() {
                fs::remove_dir_all(&dir)?;
            }
        }
        self.partitions.retain(|(t, _), _| t != topic);
        Ok(())
    }

    pub fn append(
        &mut self,
        topic: &str,
        partition: u32,
        records: Vec<NewRecord>,
    ) -> Result<Vec<LogRecord>> {
        let items = records.into_iter().map(|r| (partition, r)).collect();
        self.append_partitioned(topic, items)
    }

    /// Atomically validates, serializes, and CRC-frames an entire multi-partition
    /// batch before writing any frame to disk so oversized records or offset
    /// overflows never leave partial writes on disk.
    pub fn append_partitioned(
        &mut self,
        topic: &str,
        items: Vec<(u32, NewRecord)>,
    ) -> Result<Vec<LogRecord>> {
        Self::ensure_safe_topic(topic)?;
        let mut simulated_offsets: HashMap<u32, u64> = HashMap::new();
        for (partition, _) in &items {
            self.create_partition(topic, *partition)?;
            let dir = self.partition_dir(topic, *partition);
            self.ensure_contained(&dir)?;
            simulated_offsets.entry(*partition).or_insert_with(|| {
                self.partitions
                    .get(&(topic.to_string(), *partition))
                    .expect("partition initialized")
                    .next_offset
            });
        }

        let mut prepared = Vec::with_capacity(items.len());
        for (partition, rec) in items {
            let offset_ref = simulated_offsets
                .get_mut(&partition)
                .expect("partition offset tracked");
            let offset = *offset_ref;
            let next = offset
                .checked_add(1)
                .ok_or_else(|| CoreError::Invalid("partition offset overflow".into()))?;
            let stored = StoredRecord {
                offset,
                key: rec.key,
                value: rec.value,
                timestamp: Utc::now().to_rfc3339(),
            };
            let json_bytes = serde_json::to_vec(&stored)?;
            if json_bytes.len() > MAX_RECORD_BYTES {
                return Err(CoreError::Invalid(format!(
                    "record exceeds maximum size of {MAX_RECORD_BYTES} bytes"
                )));
            }
            let crc = crc32(&json_bytes);
            let mut frame = Vec::with_capacity(json_bytes.len() + 10);
            frame.extend_from_slice(format!("{crc:08x}:").as_bytes());
            frame.extend_from_slice(&json_bytes);
            frame.push(b'\n');
            prepared.push((partition, stored, frame));
            *offset_ref = next;
        }

        let root_path = self.root.clone();
        let mut out = Vec::with_capacity(prepared.len());
        for (partition, stored, frame) in prepared {
            let dir = self.partition_dir(topic, partition);
            let key = (topic.to_string(), partition);
            let part = self.partitions.get_mut(&key).expect("created");
            let needed = u64::try_from(frame.len())
                .map_err(|_| CoreError::Invalid("frame length overflow".into()))?;
            if part.current_size > 0
                && part.current_size.saturating_add(needed) > self.segment_max_bytes
            {
                part.current_base = stored.offset;
                part.current_size = 0;
            }
            let path = dir.join(format!("{:020}.log", part.current_base));
            Self::ensure_contained_in(&root_path, &path)?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&path)?;
            let pos = file.seek(SeekFrom::End(0))?;
            file.write_all(&frame)?;
            file.flush()?;
            part.index
                .insert(stored.offset, OffsetPos { segment: path, pos });
            part.current_size = part.current_size.saturating_add(needed);
            part.next_offset = stored
                .offset
                .checked_add(1)
                .ok_or_else(|| CoreError::Invalid("partition offset overflow".into()))?;
            out.push(LogRecord {
                topic: topic.to_string(),
                partition,
                offset: stored.offset,
                key: stored.key,
                value: stored.value,
                timestamp: stored.timestamp,
            });
        }
        Ok(out)
    }

    pub fn read_from(
        &self,
        topic: &str,
        partition: u32,
        offset: u64,
        max: usize,
    ) -> Result<Vec<LogRecord>> {
        Self::ensure_safe_topic(topic)?;
        let capped_max = max.min(MAX_READ_RECORDS);
        if capped_max == 0 {
            return Ok(vec![]);
        }
        let Some(part) = self.partitions.get(&(topic.to_string(), partition)) else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        let mut cur = offset;
        while out.len() < capped_max {
            let Some(pos) = part.index.get(&cur) else {
                break;
            };
            self.ensure_contained(&pos.segment)?;
            let file = File::open(&pos.segment)?;
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(pos.pos))?;
            let Some(frame) = read_bounded_frame(&mut reader, MAX_FRAME_BYTES)? else {
                return Err(CoreError::Invalid(format!(
                    "truncated frame at offset {cur} in {}",
                    pos.segment.display()
                )));
            };
            let stored = parse_frame(&frame, &pos.segment)?;
            if stored.offset != cur {
                return Err(CoreError::Invalid(format!(
                    "offset mismatch in segment {}: expected {cur}, found {}",
                    pos.segment.display(),
                    stored.offset
                )));
            }
            out.push(LogRecord {
                topic: topic.to_string(),
                partition,
                offset: stored.offset,
                key: stored.key,
                value: stored.value,
                timestamp: stored.timestamp,
            });
            let Some(next) = cur.checked_add(1) else {
                break;
            };
            cur = next;
        }
        Ok(out)
    }

    pub fn next_offset(&self, topic: &str, partition: u32) -> u64 {
        self.partitions
            .get(&(topic.to_string(), partition))
            .map(|p| p.next_offset)
            .unwrap_or(0)
    }

    pub fn total_records(&self) -> u64 {
        self.partitions
            .values()
            .fold(0u64, |acc, p| acc.saturating_add(p.next_offset))
    }

    fn recover(&mut self) -> Result<()> {
        if !self.root.exists() {
            return Ok(());
        }
        for topic_entry in fs::read_dir(&self.root)? {
            let topic_entry = topic_entry?;
            let ft = topic_entry.file_type()?;
            if ft.is_symlink() {
                return Err(CoreError::Invalid(
                    "symlink discovered inside commit log root".into(),
                ));
            }
            if !ft.is_dir() {
                continue;
            }
            let topic = topic_entry.file_name().to_string_lossy().to_string();
            Self::ensure_safe_topic(&topic)?;
            self.ensure_contained(&topic_entry.path())?;
            for part_entry in fs::read_dir(topic_entry.path())? {
                let part_entry = part_entry?;
                let pft = part_entry.file_type()?;
                if pft.is_symlink() {
                    return Err(CoreError::Invalid(
                        "symlink discovered inside topic directory".into(),
                    ));
                }
                if !pft.is_dir() {
                    continue;
                }
                let part_name = part_entry.file_name().to_string_lossy().to_string();
                let partition: u32 = part_name.parse().map_err(|_| {
                    CoreError::Invalid(format!("invalid partition directory name: {part_name:?}"))
                })?;
                self.recover_partition(&topic, partition, &part_entry.path())?;
            }
        }
        Ok(())
    }

    fn recover_partition(&mut self, topic: &str, partition: u32, dir: &Path) -> Result<()> {
        self.ensure_contained(dir)?;
        let mut files: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("log"))
            .collect();
        files.sort();
        let mut part = PartitionLog::default();
        for path in files {
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(CoreError::Invalid(format!(
                    "symlink segment rejected: {}",
                    path.display()
                )));
            }
            self.ensure_contained(&path)?;
            let base = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| {
                    CoreError::Invalid(format!("invalid segment filename: {}", path.display()))
                })?;
            let mut reader = BufReader::new(File::open(&path)?);
            let mut pos = 0u64;
            while let Some(frame) = read_bounded_frame(&mut reader, MAX_FRAME_BYTES)? {
                let bytes = u64::try_from(frame.len())
                    .map_err(|_| CoreError::Invalid("frame size overflow".into()))?;
                if !frame.iter().all(|b| b.is_ascii_whitespace()) {
                    let stored = parse_frame(&frame, &path)?;
                    let next = stored.offset.checked_add(1).ok_or_else(|| {
                        CoreError::Invalid(format!("offset overflow in {}", path.display()))
                    })?;
                    part.index.insert(
                        stored.offset,
                        OffsetPos {
                            segment: path.clone(),
                            pos,
                        },
                    );
                    part.next_offset = part.next_offset.max(next);
                    part.current_base = base;
                }
                pos = pos
                    .checked_add(bytes)
                    .ok_or_else(|| CoreError::Invalid("segment position overflow".into()))?;
            }
            part.current_size = fs::metadata(&path)?.len();
        }
        self.partitions.insert((topic.to_string(), partition), part);
        Ok(())
    }

    fn partition_dir(&self, topic: &str, partition: u32) -> PathBuf {
        self.root.join(topic).join(partition.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(name: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join("stream-core-tests")
            .join(format!("{name}-{n}"))
    }

    #[test]
    fn append_and_read() {
        let dir = test_dir("append");
        let mut log = CommitLog::open(&dir, 1024).unwrap();
        let written = log
            .append(
                "orders",
                0,
                vec![NewRecord {
                    key: Some("k".into()),
                    value: json!({"n":1}),
                }],
            )
            .unwrap();
        assert_eq!(written[0].offset, 0);
        let read = log.read_from("orders", 0, 0, 10).unwrap();
        assert_eq!(read, written);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn segment_rolls() {
        let dir = test_dir("roll");
        let mut log = CommitLog::open(&dir, 180).unwrap();
        for i in 0..10 {
            log.append(
                "t",
                0,
                vec![NewRecord {
                    key: None,
                    value: json!({"payload":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "i": i}),
                }],
            )
            .unwrap();
        }
        let seg_dir = dir.join("logs").join("t").join("0");
        let files = fs::read_dir(seg_dir).unwrap().count();
        assert!(files > 1, "expected multiple segments");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_rebuilds_offsets() {
        let dir = test_dir("recovery");
        {
            let mut log = CommitLog::open(&dir, 256).unwrap();
            log.append(
                "events",
                1,
                vec![
                    NewRecord {
                        key: None,
                        value: json!("a"),
                    },
                    NewRecord {
                        key: None,
                        value: json!("b"),
                    },
                ],
            )
            .unwrap();
        }
        let mut recovered = CommitLog::open(&dir, 256).unwrap();
        assert_eq!(recovered.next_offset("events", 1), 2);
        let read = recovered.read_from("events", 1, 1, 1).unwrap();
        assert_eq!(read[0].value, json!("b"));
        let appended = recovered
            .append(
                "events",
                1,
                vec![NewRecord {
                    key: None,
                    value: json!("c"),
                }],
            )
            .unwrap();
        assert_eq!(appended[0].offset, 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_traversal_and_windows_reserved_topics() {
        let dir = test_dir("unsafe-topic");
        let mut log = CommitLog::open(&dir, 1024).unwrap();
        for bad in [
            "../escape",
            "..",
            "a/b",
            "a\\b",
            "a\0b",
            "CON",
            "nul",
            "COM1",
            "LPT9",
        ] {
            assert!(
                log.create_partition(bad, 0).is_err(),
                "expected error for {bad}"
            );
            assert!(log.read_from(bad, 0, 0, 10).is_err());
            assert!(log.delete_topic(bad).is_err());
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_corrupt_crc_and_truncated_frames_without_panic() {
        let dir = test_dir("corrupt");
        {
            let mut log = CommitLog::open(&dir, 1024).unwrap();
            log.append(
                "orders",
                0,
                vec![NewRecord {
                    key: Some("k1".into()),
                    value: json!({"ok": true}),
                }],
            )
            .unwrap();
        }
        let seg_path = dir
            .join("logs")
            .join("orders")
            .join("0")
            .join("00000000000000000000.log");
        let orig = fs::read_to_string(&seg_path).unwrap();

        // Tamper payload without updating CRC -> rejected cleanly on open and read_from.
        let tampered = orig.replace("true", "false");
        fs::write(&seg_path, &tampered).unwrap();
        assert!(CommitLog::open(&dir, 1024).is_err());

        // Restore valid frame and append truncated frame lacking newline.
        let mut truncated = orig.clone();
        truncated.push_str("deadbeef:{\"offset\":1");
        fs::write(&seg_path, &truncated).unwrap();
        assert!(CommitLog::open(&dir, 1024).is_err());

        // Overflow offset in segment file -> rejected cleanly without panic.
        let payload = format!(
            "{{\"offset\":{},\"key\":null,\"value\":1,\"timestamp\":\"2026-01-01T00:00:00Z\"}}",
            u64::MAX
        );
        let frame = format!("{:08x}:{payload}\n", crc32(payload.as_bytes()));
        fs::write(&seg_path, frame).unwrap();
        assert!(CommitLog::open(&dir, 1024).is_err());

        let _ = fs::remove_dir_all(dir);
    }
}

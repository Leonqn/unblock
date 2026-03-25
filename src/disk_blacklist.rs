use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use memmap2::Mmap;
use tempfile::NamedTempFile;

/// A disk-based blacklist that stores domain hashes in a sorted mmap'd file.
/// Lookups use binary search over sorted u64 hashes — O(log n), ~0 MB RSS.
pub struct DiskBlacklist {
    mmap: Mmap,
    len: usize,
    /// If set, the file at this path is deleted when the blacklist is dropped.
    /// Used for temp files so they don't accumulate on disk.
    owned_path: Option<PathBuf>,
}

impl Drop for DiskBlacklist {
    fn drop(&mut self) {
        if let Some(path) = self.owned_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl DiskBlacklist {
    fn open_owned(path: PathBuf) -> Result<Self> {
        let file = File::open(&path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let len = mmap.len() / std::mem::size_of::<u64>();
        Ok(Self {
            mmap,
            len,
            owned_path: Some(path),
        })
    }

    /// Check if an exact domain is in the blacklist.
    pub fn contains(&self, domain: &str) -> bool {
        if self.len == 0 {
            return false;
        }
        let hash = hash_domain(domain);
        let hashes = self.as_slice();
        hashes.binary_search(&hash).is_ok()
    }

    /// Check if a domain or any of its parent domains is in the blacklist.
    /// E.g., for "sub.example.com", checks: "sub.example.com", "example.com", "com".
    pub fn contains_domain(&self, domain: &str) -> bool {
        if self.len == 0 {
            return false;
        }
        let mut remaining = domain;
        loop {
            if self.contains(remaining) {
                return true;
            }
            match remaining.find('.') {
                Some(pos) => remaining = &remaining[pos + 1..],
                None => return false,
            }
        }
    }

    fn as_slice(&self) -> &[u64] {
        if self.len == 0 {
            return &[];
        }
        let ptr = self.mmap.as_ptr() as *const u64;
        unsafe { std::slice::from_raw_parts(ptr, self.len) }
    }
}

// Unsafe impl is needed because Mmap doesn't implement Send/Sync by default,
// but our usage is read-only after construction.
unsafe impl Send for DiskBlacklist {}
unsafe impl Sync for DiskBlacklist {}

/// Builder that collects domain hashes and writes them sorted to a temp file.
/// Uses a NamedTempFile so it never conflicts with a mmap held by a previous DiskBlacklist.
pub struct DiskBlacklistBuilder {
    writer: BufWriter<NamedTempFile>,
    count: usize,
}

impl DiskBlacklistBuilder {
    /// Create a new builder. `dir` is the directory where the temp file will be created.
    pub fn new(dir: &Path) -> Result<Self> {
        let temp = NamedTempFile::new_in(dir)?;
        let writer = BufWriter::new(temp);
        Ok(Self { writer, count: 0 })
    }

    /// Add a domain hash to the file (unsorted at this point).
    pub fn add(&mut self, domain: &str) -> Result<()> {
        let hash = hash_domain(domain);
        self.writer.write_all(&hash.to_le_bytes())?;
        self.count += 1;
        Ok(())
    }

    /// Finish building: flush, sort in-place via mmap, return DiskBlacklist.
    pub fn finish(self) -> Result<DiskBlacklist> {
        let temp = self.writer.into_inner()?; // flush and get NamedTempFile back

        if self.count == 0 {
            let (_, path) = temp.keep()?;
            return DiskBlacklist::open_owned(path);
        }

        let temp_path = temp.path().to_path_buf();

        // Sort hashes in-place using mmap, then deduplicate
        let deduped_len;
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temp_path)?;
            let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
            let ptr = mmap.as_mut_ptr() as *mut u64;
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, self.count) };
            slice.sort_unstable();
            deduped_len = dedup_sorted(slice);
            mmap.flush()?;
        }
        {
            let file = std::fs::OpenOptions::new().write(true).open(&temp_path)?;
            file.set_len((deduped_len * std::mem::size_of::<u64>()) as u64)?;
        }

        // Persist the temp file (prevent auto-deletion) and open as owned DiskBlacklist.
        let (_, path) = temp.keep()?;
        DiskBlacklist::open_owned(path)
    }
}

/// Deduplicate a sorted slice in-place, returning the new length.
fn dedup_sorted(slice: &mut [u64]) -> usize {
    if slice.is_empty() {
        return 0;
    }
    let mut write = 1;
    for read in 1..slice.len() {
        if slice[read] != slice[write - 1] {
            slice[write] = slice[read];
            write += 1;
        }
    }
    write
}

fn hash_domain(domain: &str) -> u64 {
    let normalized = domain.to_ascii_lowercase();
    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_blacklist_basic() -> Result<()> {
        let dir = tempfile::tempdir()?;

        let mut builder = DiskBlacklistBuilder::new(dir.path())?;
        builder.add("example.com")?;
        builder.add("blocked.org")?;
        builder.add("test.net")?;
        let bl = builder.finish()?;

        assert!(bl.contains("example.com"));
        assert!(bl.contains("blocked.org"));
        assert!(bl.contains("test.net"));
        assert!(!bl.contains("allowed.com"));
        assert!(!bl.contains("google.com"));

        Ok(())
    }

    #[test]
    fn test_disk_blacklist_case_insensitive() -> Result<()> {
        let dir = tempfile::tempdir()?;

        let mut builder = DiskBlacklistBuilder::new(dir.path())?;
        builder.add("Example.COM")?;
        let bl = builder.finish()?;

        assert!(bl.contains("example.com"));
        assert!(bl.contains("EXAMPLE.COM"));
        assert!(bl.contains("Example.Com"));

        Ok(())
    }

    #[test]
    fn test_disk_blacklist_empty() -> Result<()> {
        let dir = tempfile::tempdir()?;

        let builder = DiskBlacklistBuilder::new(dir.path())?;
        let bl = builder.finish()?;

        assert!(!bl.contains("anything"));

        Ok(())
    }

    #[test]
    fn test_disk_blacklist_duplicates() -> Result<()> {
        let dir = tempfile::tempdir()?;

        let mut builder = DiskBlacklistBuilder::new(dir.path())?;
        builder.add("example.com")?;
        builder.add("example.com")?;
        builder.add("example.com")?;
        let bl = builder.finish()?;

        assert!(bl.contains("example.com"));
        assert_eq!(bl.len, 1); // single entry after dedup

        Ok(())
    }
}

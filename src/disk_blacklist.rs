use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use memmap2::Mmap;

/// A disk-based blacklist that stores domain hashes in a sorted mmap'd file.
/// Lookups use binary search over sorted u64 hashes — O(log n), ~0 MB RSS.
pub struct DiskBlacklist {
    mmap: Mmap,
    len: usize,
}

impl DiskBlacklist {
    /// Open an existing disk blacklist file.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let len = mmap.len() / std::mem::size_of::<u64>();
        Ok(Self { mmap, len })
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

/// Builder that collects domain hashes and writes them sorted to a file.
pub struct DiskBlacklistBuilder {
    path: PathBuf,
    writer: BufWriter<File>,
    count: usize,
}

impl DiskBlacklistBuilder {
    pub fn new(path: PathBuf) -> Result<Self> {
        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        Ok(Self {
            path,
            writer,
            count: 0,
        })
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
        drop(self.writer); // flush and close

        if self.count == 0 {
            // Create empty blacklist
            return DiskBlacklist::open(&self.path);
        }

        // Sort hashes in-place using mmap, then deduplicate
        let deduped_len;
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)?;
            let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
            let ptr = mmap.as_mut_ptr() as *mut u64;
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, self.count) };
            slice.sort_unstable();
            deduped_len = dedup_sorted(slice);
            mmap.flush()?;
            // Drop mmap and file before truncating — on Windows, set_len fails
            // with OS error 1224 if the file still has a mapped section.
        }
        {
            let file = std::fs::OpenOptions::new().write(true).open(&self.path)?;
            file.set_len((deduped_len * std::mem::size_of::<u64>()) as u64)?;
        }

        DiskBlacklist::open(&self.path)
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
        let path = dir.path().join("test.bl");

        let mut builder = DiskBlacklistBuilder::new(path.clone())?;
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
        let path = dir.path().join("test.bl");

        let mut builder = DiskBlacklistBuilder::new(path.clone())?;
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
        let path = dir.path().join("test.bl");

        let builder = DiskBlacklistBuilder::new(path.clone())?;
        let bl = builder.finish()?;

        assert!(!bl.contains("anything"));

        Ok(())
    }

    #[test]
    fn test_disk_blacklist_duplicates() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.bl");

        let mut builder = DiskBlacklistBuilder::new(path.clone())?;
        builder.add("example.com")?;
        builder.add("example.com")?;
        builder.add("example.com")?;
        let bl = builder.finish()?;

        assert!(bl.contains("example.com"));
        // File should be smaller due to dedup
        let meta = std::fs::metadata(&path)?;
        assert_eq!(meta.len(), 8); // single u64

        Ok(())
    }
}

use std::{borrow::Borrow, cmp::Ordering, hash::Hash, time::Instant};

use priority_queue::PriorityQueue;

#[derive(Debug)]
struct Cache<K: Hash + Eq, V> {
    cache: PriorityQueue<K, ExpiresAt<V>>,
    get_time: fn() -> Instant,
}

impl<K: Hash + Eq, V> Cache<K, V> {
    pub fn new(get_time: fn() -> Instant) -> Self {
        Self {
            cache: PriorityQueue::new(),
            get_time,
        }
    }

    pub fn insert(&mut self, k: K, v: V, expires_at: Instant) {
        self.cache.push(
            k,
            ExpiresAt {
                expires_at,
                value: v,
            },
        );
    }

    pub fn remove_expired(&mut self, remove_count: usize) -> usize {
        let current_time = (self.get_time)();
        let mut removed = 0;
        while self
            .cache
            .peek()
            .filter(|(_, v)| v.expires_at < current_time && remove_count != removed)
            .is_some()
        {
            removed += 1;
            self.cache.pop();
        }
        removed
    }

    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.cache
            .get(k)
            .filter(|(_, v)| v.expires_at > (self.get_time)())
            .map(|(_, v)| &v.value)
    }
}

#[derive(Debug)]
struct ExpiresAt<T> {
    expires_at: Instant,
    value: T,
}

impl<T> Ord for ExpiresAt<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.expires_at.cmp(&self.expires_at)
    }
}

impl<T> PartialOrd for ExpiresAt<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.expires_at.partial_cmp(&self.expires_at)
    }
}

impl<T> Eq for ExpiresAt<T> {}

impl<T> PartialEq for ExpiresAt<T> {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at.eq(&other.expires_at)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::Cache;

    fn future() -> Instant {
        Instant::now() + Duration::from_secs(500)
    }

    fn past() -> Instant {
        Instant::now() - Duration::from_secs(500)
    }

    #[test]
    fn should_remove_expired() {
        let mut cache = Cache::new(future);
        cache.insert(1, 2, Instant::now());

        let removed = cache.remove_expired(5);

        assert_eq!(removed, 1);
        assert!(cache.get(&1).is_none())
    }

    #[test]
    fn should_not_return_expired() {
        let mut cache = Cache::new(future);
        cache.insert(1, 2, Instant::now());

        let expired = cache.get(&1);

        assert!(expired.is_none())
    }

    #[test]
    fn should_return_not_expired() {
        let mut cache = Cache::new(past);
        cache.insert(1, 2, Instant::now());

        let not_expired = cache.get(&1);

        assert_eq!(not_expired, Some(&2))
    }

    #[test]
    fn should_not_remove_not_expired() {
        let mut cache = Cache::new(past);
        cache.insert(1, 2, Instant::now());

        let removed = cache.remove_expired(5);

        assert_eq!(removed, 0);
        assert_eq!(cache.get(&1), Some(&2))
    }

    #[test]
    fn should_remove_not_greater_than_expected() {
        let mut cache = Cache::new(future);
        cache.insert(1, 2, Instant::now());
        cache.insert(2, 2, Instant::now() + Duration::from_secs(1));
        cache.insert(3, 2, Instant::now() + Duration::from_secs(2));
        cache.insert(4, 4, Instant::now() + Duration::from_secs(3));

        let removed = cache.remove_expired(2);

        assert_eq!(removed, 2);
    }
}

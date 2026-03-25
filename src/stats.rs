use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{error, info};
use serde::{Deserialize, Serialize};

const MAX_RECENT_REQUESTS: usize = 10;

#[derive(Serialize, Deserialize, Clone)]
pub struct RecentRequest {
    pub domain: String,
    pub timestamp: u64,
    pub trace: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct IpStats {
    pub domain_counts: HashMap<String, u64>,
    pub recent_requests: VecDeque<RecentRequest>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct StatsData {
    pub per_ip: HashMap<IpAddr, IpStats>,
}

pub struct StatsCollector {
    data: Arc<Mutex<StatsData>>,
    file_path: PathBuf,
}

impl StatsCollector {
    pub async fn new(file_path: PathBuf) -> Self {
        let data = Self::load_from_disk(file_path.clone())
            .await
            .unwrap_or_default();
        if !data.per_ip.is_empty() {
            info!("Loaded stats for {} IPs from disk", data.per_ip.len());
        }
        Self {
            data: Arc::new(Mutex::new(data)),
            file_path,
        }
    }

    pub fn record(&self, ip: IpAddr, domain: String, trace: String) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut data = self.data.lock().unwrap();
        let stats = data.per_ip.entry(ip).or_default();
        *stats.domain_counts.entry(domain.clone()).or_default() += 1;
        stats.recent_requests.push_back(RecentRequest {
            domain,
            timestamp,
            trace,
        });
        if stats.recent_requests.len() > MAX_RECENT_REQUESTS {
            stats.recent_requests.pop_front();
        }
    }

    pub fn snapshot(&self) -> StatsData {
        self.data.lock().unwrap().clone()
    }

    pub async fn save_to_disk(&self) {
        let path = self.file_path.clone();
        let data = self.data.clone();

        if let Err(e) = tokio::task::spawn_blocking(move || {
            let data = data.lock().unwrap();
            let json = serde_json::to_vec(&*data).map_err(std::io::Error::other)?;
            drop(data);
            let tmp_path = path.with_extension("json.tmp");
            fs::write(&tmp_path, &json)?;
            fs::rename(&tmp_path, &path)
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)))
        {
            error!("Failed to save stats to disk: {}", e);
        }
    }

    async fn load_from_disk(path: PathBuf) -> Option<StatsData> {
        match tokio::task::spawn_blocking(move || {
            let bytes = fs::read(&path)?;
            serde_json::from_slice(&bytes).map_err(std::io::Error::other)
        })
        .await
        {
            Ok(Ok(data)) => Some(data),
            Ok(Err(e)) => {
                error!("Failed to load stats from disk: {}", e);
                None
            }
            Err(e) => {
                error!("Failed to spawn blocking task for stats load: {}", e);
                None
            }
        }
    }
}

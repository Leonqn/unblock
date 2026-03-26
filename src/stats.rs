use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::routers::KeeneticClient;

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

struct Inner {
    data: StatsData,
    date: String,
}

pub struct StatsCollector {
    inner: Arc<Mutex<Inner>>,
    stats_dir: PathBuf,
    devices: Arc<Mutex<HashMap<IpAddr, String>>>,
    router: Option<Arc<KeeneticClient>>,
}

fn today() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_date_from_secs(secs)
}

fn format_date_from_secs(secs: u64) -> String {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let mut days = (secs / 86400) as i64;
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

impl StatsCollector {
    pub async fn new(stats_dir: PathBuf, router: Option<Arc<KeeneticClient>>) -> Self {
        let date = today();
        let path = file_for_date(&stats_dir, &date);
        let data = load_from_file(path).await.unwrap_or_default();
        if !data.per_ip.is_empty() {
            info!(
                "Loaded stats for {} IPs for date {}",
                data.per_ip.len(),
                date
            );
        }
        Self {
            inner: Arc::new(Mutex::new(Inner { data, date })),
            stats_dir,
            devices: Arc::new(Mutex::new(HashMap::new())),
            router,
        }
    }

    pub async fn record(&self, ip: IpAddr, domain: String, trace: String) {
        let is_new_ip = {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let date = format_date_from_secs(timestamp);

            let mut inner = self.inner.lock().unwrap();
            if date != inner.date {
                let old_data = std::mem::take(&mut inner.data);
                let old_path = file_for_date(&self.stats_dir, &inner.date);
                inner.date = date;
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = write_file(&old_path, &old_data) {
                        error!("Failed to save stats for previous day: {}", e);
                    }
                });
            }
            let is_new = !inner.data.per_ip.contains_key(&ip);
            let stats = inner.data.per_ip.entry(ip).or_default();
            *stats.domain_counts.entry(domain.clone()).or_default() += 1;
            stats.recent_requests.push_back(RecentRequest {
                domain,
                timestamp,
                trace,
            });
            if stats.recent_requests.len() > MAX_RECENT_REQUESTS {
                stats.recent_requests.pop_front();
            }
            is_new
        };

        let unknown = is_new_ip && !self.devices.lock().unwrap().contains_key(&ip);
        if unknown {
            if let Some(router) = &self.router {
                match router.get_hotspot().await {
                    Ok(hosts) => {
                        *self.devices.lock().unwrap() = hosts;
                    }
                    Err(e) => {
                        warn!("Failed to fetch devices from router: {}", e);
                    }
                }
            }
        }
    }

    pub fn devices(&self) -> HashMap<IpAddr, String> {
        self.devices.lock().unwrap().clone()
    }

    pub fn snapshot(&self) -> StatsData {
        self.inner.lock().unwrap().data.clone()
    }

    pub async fn load_date(&self, date: &str) -> StatsData {
        let path = file_for_date(&self.stats_dir, date);
        load_from_file(path).await.unwrap_or_default()
    }

    pub async fn available_dates(&self) -> Vec<String> {
        let dir = self.stats_dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut dates: Vec<String> = fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    name.strip_suffix(".json").map(|s| s.to_owned())
                })
                .collect();
            dates.sort();
            dates.reverse();
            dates
        })
        .await
        .unwrap_or_default()
    }

    pub fn current_date(&self) -> String {
        self.inner.lock().unwrap().date.clone()
    }

    pub async fn save_to_disk(&self) {
        let (data, path) = {
            let inner = self.inner.lock().unwrap();
            (
                inner.data.clone(),
                file_for_date(&self.stats_dir, &inner.date),
            )
        };

        if let Err(e) = tokio::task::spawn_blocking(move || write_file(&path, &data))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e)))
        {
            error!("Failed to save stats to disk: {}", e);
        }
    }
}

fn file_for_date(stats_dir: &Path, date: &str) -> PathBuf {
    stats_dir.join(format!("{}.json", date))
}

fn write_file(path: &Path, data: &StatsData) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(data).map_err(std::io::Error::other)?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, &json)?;
    fs::rename(&tmp_path, path)
}

async fn load_from_file(path: PathBuf) -> Option<StatsData> {
    match tokio::task::spawn_blocking(move || {
        let bytes = fs::read(&path)?;
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)
    })
    .await
    {
        Ok(Ok(data)) => Some(data),
        Ok(Err(e)) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                error!("Failed to load stats from disk: {}", e);
            }
            None
        }
        Err(e) => {
            error!("Failed to spawn blocking task for stats load: {}", e);
            None
        }
    }
}

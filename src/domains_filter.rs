use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    path::PathBuf,
    time::Duration,
};

use crate::disk_blacklist::{DiskBlacklist, DiskBlacklistBuilder};
use crate::files_stream::create_files_stream;
use anyhow::Result;
use futures_util::stream::Stream;
use log::{error, warn};
use once_cell::sync::OnceCell;
use regex::Regex;
use url::Url;
use tokio_stream::StreamExt;

#[derive(Debug, PartialEq, Eq)]
pub struct MatchResult<'a> {
    pub rule: &'a str,
    pub is_allowed: bool,
}

pub fn filters_stream(
    filter_url: Url,
    update_interval: Duration,
    manual_rules: Vec<String>,
    data_dir: Option<PathBuf>,
) -> Result<impl Stream<Item = DomainsFilter>> {
    Ok(
        create_files_stream(filter_url, update_interval)?.filter_map(move |filter| {
            let manual_rules = manual_rules.join("\n");
            let domains_filter = std::str::from_utf8(filter.as_ref())
                .map_err(anyhow::Error::from)
                .and_then(|rules| DomainsFilter::new(&(manual_rules + rules), data_dir.as_deref()));
            match domains_filter {
                Ok(filter) => Some(filter),
                Err(err) => {
                    error!("Failed to create filter. Err: {:#}", err);
                    None
                }
            }
        }),
    )
}

pub struct DomainsFilter {
    allow_matcher: RulesMatcher,
    block_matcher: RulesMatcher,
    /// Simple `||domain.com^` block rules stored on disk for memory efficiency.
    simple_block_disk: Option<DiskBlacklist>,
}

impl std::fmt::Debug for DomainsFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainsFilter")
            .field("allow_matcher", &self.allow_matcher)
            .field("block_matcher", &self.block_matcher)
            .field("simple_block_disk", &self.simple_block_disk.is_some())
            .finish()
    }
}

impl DomainsFilter {
    pub fn new(rules: &str, data_dir: Option<&std::path::Path>) -> Result<Self> {
        let all_rules: Vec<Rule> = rules
            .lines()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty() && !x.starts_with('!') && !x.contains('$'))
            .map(Rule::new)
            .collect::<Result<Vec<Rule>>>()?;

        let (allow, block): (Vec<_>, Vec<_>) = all_rules.into_iter().partition(|x| x.is_allow_rule);

        // Separate simple domain block rules from complex ones
        let (simple_domains, complex_block): (Vec<_>, Vec<_>) = block
            .into_iter()
            .partition(|rule| extract_simple_domain(&rule.rule).is_some());

        let simple_block_disk = if !simple_domains.is_empty() {
            if let Some(dir) = data_dir {
                let bl_path = dir.join("ads_block.bl");
                match build_simple_disk_blacklist(&simple_domains, &bl_path) {
                    Ok(bl) => {
                        log::info!(
                            "Moved {} simple block rules to disk, {} complex rules in memory",
                            simple_domains.len(),
                            complex_block.len()
                        );
                        Some(bl)
                    }
                    Err(err) => {
                        log::error!("Failed to build disk blacklist for ads: {:#}", err);
                        // Fall back to keeping everything in memory
                        let mut all_block = simple_domains;
                        all_block.extend(complex_block);
                        return Ok(Self {
                            allow_matcher: RulesMatcher::new(allow),
                            block_matcher: RulesMatcher::new(all_block),
                            simple_block_disk: None,
                        });
                    }
                }
            } else {
                // No data_dir: keep simple rules in memory too
                let mut all_block = simple_domains;
                all_block.extend(complex_block);
                return Ok(Self {
                    allow_matcher: RulesMatcher::new(allow),
                    block_matcher: RulesMatcher::new(all_block),
                    simple_block_disk: None,
                });
            }
        } else {
            None
        };

        let allow_matcher = RulesMatcher::new(allow);
        let block_matcher = RulesMatcher::new(complex_block);
        Ok(Self {
            allow_matcher,
            block_matcher,
            simple_block_disk,
        })
    }

    pub fn match_domain(&self, domain: &str) -> Option<MatchResult<'_>> {
        // Check allow rules first (always in memory, few rules)
        if let Some(rule) = self.allow_matcher.match_domain(domain) {
            return Some(MatchResult {
                rule: &rule.rule,
                is_allowed: true,
            });
        }
        // Check complex block rules in memory
        if let Some(rule) = self.block_matcher.match_domain(domain) {
            return Some(MatchResult {
                rule: &rule.rule,
                is_allowed: false,
            });
        }
        // Check simple block rules on disk
        if let Some(ref disk) = self.simple_block_disk {
            if disk.contains_domain(domain) {
                return Some(MatchResult {
                    rule: "disk-blocked",
                    is_allowed: false,
                });
            }
        }
        None
    }
}

/// Extract the domain from a simple `||domain.com^` rule.
/// Returns None for complex rules (regex, wildcards, etc.)
fn extract_simple_domain(rule: &str) -> Option<&str> {
    let rule = rule.strip_prefix("||")?;
    let domain = rule.strip_suffix('^')?;
    if domain.is_empty() {
        return None;
    }
    // Must be a simple domain: only alphanumeric, dots, hyphens
    if domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        Some(domain)
    } else {
        None
    }
}

fn build_simple_disk_blacklist(rules: &[Rule], bl_path: &std::path::Path) -> Result<DiskBlacklist> {
    let mut builder = DiskBlacklistBuilder::new(bl_path.to_path_buf())?;
    for rule in rules {
        if let Some(domain) = extract_simple_domain(&rule.rule) {
            builder.add(domain)?;
        }
    }
    builder.finish()
}

#[derive(Debug)]
struct RulesMatcher {
    substrs: HashMap<u64, Vec<usize>>,
    rules: Vec<Rule>,
}

impl RulesMatcher {
    pub fn new(rules: Vec<Rule>) -> Self {
        let substrs = rules
            .iter()
            .map(|rule| {
                rule.rule
                    .split(|c| c != '_' && c != '-' && c != '.' && !char::is_alphanumeric(c))
                    .max_by_key(|x| x.len())
                    .unwrap_or("")
                    .trim_matches('.')
            })
            .enumerate()
            .map(|(i, s)| (Self::hash(s), i))
            .fold(HashMap::<_, Vec<_>>::new(), |mut acc, (h, i)| {
                acc.entry(h).or_default().push(i);
                acc
            });
        Self { substrs, rules }
    }

    fn hash(s: &str) -> u64 {
        let mut h = DefaultHasher::new();
        s.hash(&mut h);
        h.finish()
    }

    fn match_domain(&self, domain: &str) -> Option<&Rule> {
        let dots = std::iter::once(0)
            .chain(
                domain
                    .char_indices()
                    .filter_map(|(i, c)| (c == '.').then_some(i)),
            )
            .chain(std::iter::once(domain.len()))
            .collect::<Vec<_>>();
        dots.iter()
            .enumerate()
            .flat_map(|(d_idx, &i)| {
                dots[d_idx + 1..]
                    .iter()
                    .map(move |&j| Self::hash(domain[i..j].trim_matches('.')))
            })
            .find_map(|h| {
                self.substrs.get(&h)?.iter().find_map(|idx| {
                    let rule = &self.rules[*idx];
                    rule.is_match(domain).then_some(rule)
                })
            })
    }
}

#[derive(Debug)]
struct Rule {
    regex: OnceCell<Result<Regex, regex::Error>>,
    rule: String,
    is_allow_rule: bool,
}

impl Rule {
    fn new(rule: &str) -> Result<Self> {
        if let Some(stripped) = rule.strip_prefix("@@") {
            Ok(Self {
                regex: OnceCell::new(),
                rule: stripped.to_owned(),
                is_allow_rule: true,
            })
        } else {
            Ok(Self {
                regex: OnceCell::new(),
                rule: rule.to_owned(),
                is_allow_rule: false,
            })
        }
    }

    fn is_match(&self, s: &str) -> bool {
        let regex = self
            .regex
            .get_or_init(|| Regex::new(&Self::create_regex_string(&self.rule)));
        match regex {
            Ok(regex) => regex.is_match(s),
            Err(err) => {
                warn!("Got bad regex {:?} from rule {}", err, self.rule);
                false
            }
        }
    }

    fn create_regex_string(rule: &str) -> String {
        if rule.starts_with('/') && rule.ends_with('/') {
            rule.trim_matches('/').replace(r"\/", r"/")
        } else {
            let mut regex = regex::escape(rule)
                .replace(r"\*", ".*")
                .replace(r"\^", "([^ a-zA-Z0-9.%_-]|$)")
                .replace("://", "");

            if let Some(stripped) = regex.strip_prefix(r"\|\|") {
                regex = String::from(r"([a-z0-9-_.]+\.|^)") + stripped;
            } else if let Some(stripped) = regex.strip_prefix(r"\|") {
                regex = String::from("^") + stripped;
            }
            if let Some(stripped) = regex.strip_suffix(r"\|") {
                regex = String::from(stripped) + "$";
            }
            regex
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainsFilter, MatchResult};

    #[test]
    fn checker_test() {
        let filter = r"
||sporedfryhum.com^
||rcdn.pro^$badfilter
/movie1168\.com\/storage\/go\/[0-9a-zA-Z]{0,40}\.gif/
/movie1168\.com/
.3.n.2.1.l50.js
||tercabilis.info^
||jwuqescfqa.xyz^
://mine.torrent.pw^
://*.anime-free.net^
||hostingcloud.*.wasm^
||play*.videos.vidto.me^
*ad.durasite.net^
@@||omniture.walmart.com^|
||ad.mail.ru^|
||ya.ru
@@||ya.ru
||ntent.com^

        ";
        let filter = DomainsFilter::new(filter, None).unwrap();

        assert_eq!(filter.match_domain("rcdn.pro"), None);
        assert_eq!(
            filter.match_domain("movie1168.com"),
            Some(MatchResult {
                is_allowed: false,
                rule: r"/movie1168\.com/",
            })
        );
        assert_eq!(
            filter.match_domain("anime-ura.anime-free.net"),
            Some(MatchResult {
                is_allowed: false,
                rule: r"://*.anime-free.net^",
            })
        );
        assert_eq!(
            filter.match_domain("dsa.omniture.walmart.com"),
            Some(MatchResult {
                is_allowed: true,
                rule: r"||omniture.walmart.com^|",
            })
        );
        assert_eq!(
            filter.match_domain("asdasdasd.....3.n.2.1.l50.js"),
            Some(MatchResult {
                is_allowed: false,
                rule: r".3.n.2.1.l50.js",
            })
        );
        assert_eq!(
            filter.match_domain("playvideododo.ddd.dddd.videos.vidto.me"),
            Some(MatchResult {
                is_allowed: false,
                rule: r"||play*.videos.vidto.me^",
            })
        );

        assert_eq!(
            filter.match_domain("ya.ru"),
            Some(MatchResult {
                is_allowed: true,
                rule: r"||ya.ru",
            })
        );
        assert_eq!(filter.match_domain("durasite.net^"), None);
        assert_eq!(filter.match_domain("play*.videos.vidto.me.asd"), None);
        assert_eq!(filter.match_domain("raw.githubusercontent.com"), None);
    }

    #[test]
    fn simple_rules_go_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let filter = r"
||simple-block.com^
||another-block.org^
://*.complex-rule.net^
@@||allowed.com^
        ";
        let filter = DomainsFilter::new(filter, Some(dir.path())).unwrap();

        // Simple block rules should match via disk
        assert_eq!(
            filter.match_domain("simple-block.com"),
            Some(MatchResult {
                is_allowed: false,
                rule: "disk-blocked",
            })
        );
        // Subdomain should also match
        assert_eq!(
            filter.match_domain("sub.simple-block.com"),
            Some(MatchResult {
                is_allowed: false,
                rule: "disk-blocked",
            })
        );
        // Complex rule still works
        assert_eq!(
            filter.match_domain("test.complex-rule.net"),
            Some(MatchResult {
                is_allowed: false,
                rule: r"://*.complex-rule.net^",
            })
        );
        // Allow rule works
        assert_eq!(
            filter.match_domain("allowed.com"),
            Some(MatchResult {
                is_allowed: true,
                rule: r"||allowed.com^",
            })
        );
        // Non-blocked domain
        assert_eq!(filter.match_domain("google.com"), None);
    }
}

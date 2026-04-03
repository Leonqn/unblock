use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    time::Duration,
};

use crate::files_stream::create_files_stream;
use anyhow::Result;
use futures_util::stream::Stream;
use log::{error, info, warn};
use regex::Regex;
use tokio_stream::StreamExt;
use url::Url;

#[derive(Debug, PartialEq, Eq)]
pub enum MatchResult<'a> {
    Allow(&'a str),
    Block(&'a str),
}

impl MatchResult<'_> {
    pub fn is_allowed(&self) -> bool {
        matches!(self, MatchResult::Allow(_))
    }

    pub fn rule(&self) -> &str {
        match self {
            MatchResult::Allow(rule) | MatchResult::Block(rule) => rule,
        }
    }
}

impl std::fmt::Display for MatchResult<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchResult::Allow(rule) => write!(f, "allowed by {rule}"),
            MatchResult::Block(rule) => write!(f, "blocked by {rule}"),
        }
    }
}

pub fn filters_stream(
    filter_url: Url,
    update_interval: Duration,
    manual_rules: Vec<String>,
) -> Result<impl Stream<Item = DomainsFilter>> {
    Ok(create_files_stream(filter_url, update_interval)?
        .then(move |filter| {
            let manual_rules = manual_rules.clone();
            async move {
                let result = tokio::task::spawn_blocking(move || {
                    let manual_rules = manual_rules.join("\n");
                    std::str::from_utf8(filter.as_ref())
                        .map_err(anyhow::Error::from)
                        .and_then(|rules| DomainsFilter::new(&(manual_rules + rules)))
                })
                .await;
                match result {
                    Ok(Ok(filter)) => Some(filter),
                    Ok(Err(err)) => {
                        error!("Failed to create filter. Err: {:#}", err);
                        None
                    }
                    Err(err) => {
                        error!("spawn_blocking panicked: {:#}", err);
                        None
                    }
                }
            }
        })
        .filter_map(|x| x))
}

pub struct DomainsFilter {
    allow_domains: HashMap<u64, String>,
    block_domains: HashMap<u64, String>,
    allow_rules: Vec<CompiledRule>,
    block_rules: Vec<CompiledRule>,
}

impl std::fmt::Debug for DomainsFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainsFilter")
            .field("allow_domains", &self.allow_domains.len())
            .field("block_domains", &self.block_domains.len())
            .field("allow_rules", &self.allow_rules.len())
            .field("block_rules", &self.block_rules.len())
            .finish()
    }
}

fn hash_domain(domain: &str) -> u64 {
    let normalized = domain.to_ascii_lowercase();
    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

fn domain_in_map<'a>(map: &'a HashMap<u64, String>, domain: &str) -> Option<&'a str> {
    let mut remaining = domain;
    loop {
        if let Some(rule) = map.get(&hash_domain(remaining)) {
            return Some(rule);
        }
        match remaining.find('.') {
            Some(pos) => remaining = &remaining[pos + 1..],
            None => return None,
        }
    }
}

impl DomainsFilter {
    pub fn new(rules: &str) -> Result<Self> {
        let mut allow_domains = HashMap::new();
        let mut block_domains = HashMap::new();
        let mut allow_rules = Vec::new();
        let mut block_rules = Vec::new();

        for line in rules.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('!') || line.contains('$') {
                continue;
            }

            let (is_allow, rule_text) = match line.strip_prefix("@@") {
                Some(stripped) => (true, stripped),
                None => (false, line),
            };

            let Some(parsed) = parse_adguard_rule(rule_text) else {
                continue;
            };

            match parsed {
                ParsedRule::Domain(domain) => {
                    let hash = hash_domain(&domain);
                    let original = line.to_owned();
                    if is_allow {
                        allow_domains.insert(hash, original);
                    } else {
                        block_domains.insert(hash, original);
                    }
                }
                ParsedRule::Compiled(compiled) => {
                    if is_allow {
                        allow_rules.push(compiled);
                    } else {
                        block_rules.push(compiled);
                    }
                }
            }
        }

        info!(
            "{} allow domains, {} block domains, {} allow rules, {} block rules",
            allow_domains.len(),
            block_domains.len(),
            allow_rules.len(),
            block_rules.len()
        );

        Ok(Self {
            allow_domains,
            block_domains,
            allow_rules,
            block_rules,
        })
    }

    pub fn match_domain(&self, domain: &str) -> Option<MatchResult<'_>> {
        if let Some(rule) = domain_in_map(&self.allow_domains, domain) {
            return Some(MatchResult::Allow(rule));
        }
        if let Some(rule) = self.allow_rules.iter().find(|r| r.is_match(domain)) {
            return Some(MatchResult::Allow(&rule.original));
        }
        if let Some(rule) = domain_in_map(&self.block_domains, domain) {
            return Some(MatchResult::Block(rule));
        }
        if let Some(rule) = self.block_rules.iter().find(|r| r.is_match(domain)) {
            return Some(MatchResult::Block(&rule.original));
        }
        None
    }
}

// --- Rule parsing ---

enum ParsedRule {
    Domain(String),
    Compiled(CompiledRule),
}

struct CompiledRule {
    original: String,
    matcher: RuleMatcher,
}

enum RuleMatcher {
    /// Domain contains this substring
    Contains(String),
    /// `||` anchor with wildcard: at domain boundary starts with prefix, domain ends with suffix
    DomainGlob { prefix: String, suffix: String },
    /// Real regex (only for `/regex/` rules and rare complex patterns)
    Regex(Regex),
}

impl CompiledRule {
    fn is_match(&self, domain: &str) -> bool {
        match &self.matcher {
            RuleMatcher::Contains(s) => domain.contains(s.as_str()),
            RuleMatcher::DomainGlob { prefix, suffix } => {
                if !domain.ends_with(suffix.as_str()) {
                    return false;
                }
                if domain.starts_with(prefix.as_str()) {
                    return true;
                }
                let mut remaining = domain;
                while let Some(pos) = remaining.find('.') {
                    remaining = &remaining[pos + 1..];
                    if remaining.starts_with(prefix.as_str()) {
                        return true;
                    }
                }
                false
            }
            RuleMatcher::Regex(re) => re.is_match(domain),
        }
    }
}

fn strip_tail(s: &str) -> &str {
    s.strip_suffix("^|")
        .or_else(|| s.strip_suffix('^'))
        .or_else(|| s.strip_suffix('|'))
        .unwrap_or(s)
}

fn is_domain_chars(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Parse an AdGuard rule into either a domain hash lookup or a compiled matcher.
/// Returns None for rules that fail to compile.
fn parse_adguard_rule(rule: &str) -> Option<ParsedRule> {
    // /regex/ → real regex
    if rule.starts_with('/') && rule.ends_with('/') && rule.len() > 1 {
        let pattern = rule[1..rule.len() - 1].replace(r"\/", "/");
        return match Regex::new(&pattern) {
            Ok(re) => Some(ParsedRule::Compiled(CompiledRule {
                original: rule.to_owned(),
                matcher: RuleMatcher::Regex(re),
            })),
            Err(err) => {
                warn!("Bad regex from rule {}: {:?}", rule, err);
                None
            }
        };
    }

    // ||domain or ||prefix*suffix → domain hash or glob
    if let Some(inner) = rule.strip_prefix("||") {
        let inner = strip_tail(inner);
        if !inner.contains('*') && is_domain_chars(inner) {
            return Some(ParsedRule::Domain(inner.to_owned()));
        }
        if let Some(pos) = inner.find('*') {
            let suffix = &inner[pos + 1..];
            if !suffix.contains('*') {
                return Some(ParsedRule::Compiled(CompiledRule {
                    original: rule.to_owned(),
                    matcher: RuleMatcher::DomainGlob {
                        prefix: inner[..pos].to_owned(),
                        suffix: suffix.to_owned(),
                    },
                }));
            }
        }
        return Some(ParsedRule::Compiled(compile_to_regex(rule)));
    }

    // ://domain^ or ://*.domain^ → domain hash
    if let Some(inner) = rule.strip_prefix("://") {
        let inner = inner.strip_prefix("*.").unwrap_or(inner);
        let inner = strip_tail(inner);
        if !inner.contains('*') && is_domain_chars(inner) {
            return Some(ParsedRule::Domain(inner.to_owned()));
        }
    }

    // *text^ or .text → substring contains
    let stripped = rule.strip_prefix('*').unwrap_or(rule);
    let stripped = strip_tail(stripped);
    if !stripped.contains('*') && !stripped.is_empty() {
        return Some(ParsedRule::Compiled(CompiledRule {
            original: rule.to_owned(),
            matcher: RuleMatcher::Contains(stripped.to_owned()),
        }));
    }

    // Fallback: regex
    Some(ParsedRule::Compiled(compile_to_regex(rule)))
}

fn compile_to_regex(rule: &str) -> CompiledRule {
    let regex_str = adguard_to_regex(rule);
    CompiledRule {
        original: rule.to_owned(),
        matcher: match Regex::new(&regex_str) {
            Ok(re) => RuleMatcher::Regex(re),
            Err(err) => {
                warn!("Bad regex {:?} from rule {}", err, rule);
                RuleMatcher::Contains("\x00".to_owned())
            }
        },
    }
}

fn adguard_to_regex(rule: &str) -> String {
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
        let filter = DomainsFilter::new(filter).unwrap();

        assert_eq!(filter.match_domain("rcdn.pro"), None);
        assert_eq!(
            filter.match_domain("movie1168.com"),
            Some(MatchResult::Block(r"/movie1168\.com/"))
        );
        assert_eq!(
            filter.match_domain("anime-ura.anime-free.net"),
            Some(MatchResult::Block("://*.anime-free.net^"))
        );
        assert_eq!(
            filter.match_domain("dsa.omniture.walmart.com"),
            Some(MatchResult::Allow("@@||omniture.walmart.com^|"))
        );
        assert_eq!(
            filter.match_domain("asdasdasd.....3.n.2.1.l50.js"),
            Some(MatchResult::Block(".3.n.2.1.l50.js"))
        );
        assert_eq!(
            filter.match_domain("playvideododo.ddd.dddd.videos.vidto.me"),
            Some(MatchResult::Block("||play*.videos.vidto.me^"))
        );
        assert_eq!(
            filter.match_domain("ya.ru"),
            Some(MatchResult::Allow("@@||ya.ru"))
        );
        assert_eq!(filter.match_domain("durasite.net^"), None);
        assert_eq!(filter.match_domain("play*.videos.vidto.me.asd"), None);
        assert_eq!(filter.match_domain("raw.githubusercontent.com"), None);
    }

    #[test]
    fn simple_rules_in_memory() {
        let filter = r"
||simple-block.com^
||another-block.org^
://*.complex-rule.net^
@@||allowed.com^
        ";
        let filter = DomainsFilter::new(filter).unwrap();

        assert_eq!(
            filter.match_domain("simple-block.com"),
            Some(MatchResult::Block("||simple-block.com^"))
        );
        assert_eq!(
            filter.match_domain("sub.simple-block.com"),
            Some(MatchResult::Block("||simple-block.com^"))
        );
        assert_eq!(
            filter.match_domain("test.complex-rule.net"),
            Some(MatchResult::Block("://*.complex-rule.net^"))
        );
        assert_eq!(
            filter.match_domain("allowed.com"),
            Some(MatchResult::Allow("@@||allowed.com^"))
        );
        assert_eq!(filter.match_domain("google.com"), None);
    }

    #[test]
    fn parse_domain_variants() {
        let filter = DomainsFilter::new(
            r"
||exact.com^
||with-end.com^|
||no-caret.org
://proto.net^
://*.wildcard-proto.info^
        ",
        )
        .unwrap();

        for domain in [
            "exact.com",
            "sub.exact.com",
            "with-end.com",
            "no-caret.org",
            "deep.sub.no-caret.org",
            "proto.net",
            "sub.proto.net",
            "wildcard-proto.info",
            "any.wildcard-proto.info",
        ] {
            assert!(
                matches!(filter.match_domain(domain), Some(MatchResult::Block(_))),
                "expected blocked for {domain}"
            );
        }

        // Should not match unrelated domains
        assert_eq!(filter.match_domain("notexact.com"), None);
        assert_eq!(filter.match_domain("other.org"), None);
    }

    #[test]
    fn contains_rules() {
        let filter = DomainsFilter::new(
            r"
.tracker.js
*ad.network.com^
        ",
        )
        .unwrap();

        assert_eq!(
            filter.match_domain("cdn.tracker.js"),
            Some(MatchResult::Block(".tracker.js"))
        );
        assert_eq!(filter.match_domain("tracker.other"), None);

        assert_eq!(
            filter.match_domain("bad.ad.network.com"),
            Some(MatchResult::Block("*ad.network.com^"))
        );
        assert_eq!(
            filter.match_domain("ad.network.com"),
            Some(MatchResult::Block("*ad.network.com^"))
        );
        assert_eq!(filter.match_domain("network.com"), None);
    }

    #[test]
    fn domain_glob_rules() {
        let filter = DomainsFilter::new(
            r"
||play*.vidto.me^
||cdn*.tracker.net^
        ",
        )
        .unwrap();

        assert_eq!(
            filter.match_domain("playfoo.vidto.me"),
            Some(MatchResult::Block("||play*.vidto.me^"))
        );
        assert_eq!(
            filter.match_domain("sub.playfoo.vidto.me"),
            Some(MatchResult::Block("||play*.vidto.me^"))
        );
        assert_eq!(filter.match_domain("notplay.vidto.me"), None);
        assert_eq!(filter.match_domain("playfoo.other.me"), None);

        assert_eq!(
            filter.match_domain("cdn123.tracker.net"),
            Some(MatchResult::Block("||cdn*.tracker.net^"))
        );
        assert_eq!(filter.match_domain("xcdn.tracker.net"), None);
    }

    #[test]
    fn regex_rules() {
        let filter = DomainsFilter::new(r"/tracker\d+\.example\.com/").unwrap();

        assert_eq!(
            filter.match_domain("tracker123.example.com"),
            Some(MatchResult::Block(r"/tracker\d+\.example\.com/"))
        );
        assert_eq!(filter.match_domain("tracker.example.com"), None);
    }

    #[test]
    fn allow_takes_precedence() {
        let filter = DomainsFilter::new(
            r"
||blocked.com^
@@||allowed.blocked.com^
||ads.net^
@@||ads.net^
        ",
        )
        .unwrap();

        assert_eq!(
            filter.match_domain("allowed.blocked.com"),
            Some(MatchResult::Allow("@@||allowed.blocked.com^"))
        );
        assert_eq!(
            filter.match_domain("other.blocked.com"),
            Some(MatchResult::Block("||blocked.com^"))
        );
        assert_eq!(
            filter.match_domain("ads.net"),
            Some(MatchResult::Allow("@@||ads.net^"))
        );
    }

    #[test]
    fn dollar_rules_are_skipped() {
        let filter = DomainsFilter::new("||example.com^$badfilter").unwrap();
        assert_eq!(filter.match_domain("example.com"), None);
    }
}

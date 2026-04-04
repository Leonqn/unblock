use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    time::Duration,
};

use anyhow::Result;
use futures_util::stream::Stream;
use log::{error, info, warn};
use regex::Regex;
use tokio_stream::StreamExt;
use url::Url;

use crate::files_stream::create_files_stream;

pub enum MatchResult<'a> {
    Allow(&'a Rule),
    Block(&'a Rule),
}

impl MatchResult<'_> {
    pub fn is_allowed(&self) -> bool {
        matches!(self, MatchResult::Allow(_))
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
    allow_matcher: RulesMatcher,
    block_matcher: RulesMatcher,
}

impl std::fmt::Debug for DomainsFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainsFilter")
            .field("allow_rules", &self.allow_matcher.rules.len())
            .field("block_rules", &self.block_matcher.rules.len())
            .finish()
    }
}

impl DomainsFilter {
    pub fn new(rules: &str) -> Result<Self> {
        let all_rules: Vec<Rule> = rules
            .lines()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty() && !x.starts_with('!') && !x.contains('$'))
            .map(|line| {
                let (is_allow_rule, rule_text) = match line.strip_prefix("@@") {
                    Some(stripped) => (true, stripped),
                    None => (false, line),
                };
                Rule {
                    matcher: parse_matcher(rule_text),
                    is_allow_rule,
                }
            })
            .collect();

        let (allow, block): (Vec<_>, Vec<_>) = all_rules.into_iter().partition(|r| r.is_allow_rule);

        let allow_matcher = RulesMatcher::new(allow);
        let block_matcher = RulesMatcher::new(block);

        info!(
            "Filter: {} allow rules, {} block rules",
            allow_matcher.rules.len(),
            block_matcher.rules.len()
        );

        Ok(Self {
            allow_matcher,
            block_matcher,
        })
    }

    pub fn match_domain(&self, domain: &str) -> Option<MatchResult<'_>> {
        if let Some(rule) = self.allow_matcher.match_domain(domain) {
            return Some(MatchResult::Allow(rule));
        }
        if let Some(rule) = self.block_matcher.match_domain(domain) {
            return Some(MatchResult::Block(rule));
        }
        None
    }
}

// --- Matching engine ---

struct RulesMatcher {
    substrs: HashMap<u64, Vec<usize>>,
    rules: Vec<Rule>,
}

impl RulesMatcher {
    fn new(rules: Vec<Rule>) -> Self {
        let substrs = rules
            .iter()
            .enumerate()
            .map(|(i, rule)| (Self::hash(rule.matcher.index_key()), i))
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

// --- Rule ---

pub struct Rule {
    matcher: RuleMatcher,
    is_allow_rule: bool,
}

/// Fast matcher that avoids regex when possible.
enum RuleMatcher {
    /// `||domain.com^` — exact domain or subdomain match
    Domain(String),
    /// `.substring` or `*substring^` — substring match
    Contains(String),
    /// `||prefix*.suffix^` — glob with single wildcard
    DomainGlob { prefix: String, suffix: String },
    /// `/regex/` or complex patterns — compiled regex (lazy)
    LazyRegex(std::sync::OnceLock<Result<Regex, regex::Error>>, String),
}

impl RuleMatcher {
    /// Returns the best substring for the index lookup.
    fn index_key(&self) -> &str {
        let s = match self {
            RuleMatcher::Domain(s) | RuleMatcher::Contains(s) => s.as_str(),
            RuleMatcher::DomainGlob { suffix, .. } => {
                // suffix may start with a partial label (e.g. "bar.baz.com"),
                // skip to after the first dot to get a full domain suffix
                suffix.find('.').map(|p| &suffix[p + 1..]).unwrap_or(suffix)
            }
            RuleMatcher::LazyRegex(_, pattern) => pattern.as_str(),
        };
        s.split(|c: char| c != '_' && c != '-' && c != '.' && !c.is_alphanumeric())
            .max_by_key(|x| x.len())
            .unwrap_or("")
            .trim_matches('.')
    }
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_allow_rule {
            write!(f, "@@")?;
        }
        match &self.matcher {
            RuleMatcher::Domain(d) => write!(f, "||{d}^"),
            RuleMatcher::Contains(s) => write!(f, "*{s}^"),
            RuleMatcher::DomainGlob { prefix, suffix } => write!(f, "||{prefix}*{suffix}^"),
            RuleMatcher::LazyRegex(_, pattern) => write!(f, "/{pattern}/"),
        }
    }
}

impl Rule {
    fn is_match(&self, domain: &str) -> bool {
        match &self.matcher {
            RuleMatcher::Domain(d) => {
                domain == d
                    || domain.ends_with(d.as_str())
                        && domain.as_bytes().get(domain.len() - d.len() - 1) == Some(&b'.')
            }
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
            RuleMatcher::LazyRegex(cell, pattern) => {
                let regex = cell.get_or_init(|| Regex::new(pattern));
                match regex {
                    Ok(re) => re.is_match(domain),
                    Err(err) => {
                        warn!("Bad regex {:?} from rule {}", err, pattern);
                        false
                    }
                }
            }
        }
    }
}

// --- Rule parsing ---

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

fn parse_matcher(rule: &str) -> RuleMatcher {
    // /regex/ → lazy regex with the inner pattern
    if rule.starts_with('/') && rule.ends_with('/') && rule.len() > 1 {
        let pattern = rule[1..rule.len() - 1].replace(r"\/", "/");
        return RuleMatcher::LazyRegex(std::sync::OnceLock::new(), pattern);
    }

    // || anchored
    if let Some(inner) = rule.strip_prefix("||") {
        let inner = strip_tail(inner);
        if !inner.contains('*') && is_domain_chars(inner) {
            return RuleMatcher::Domain(inner.to_ascii_lowercase());
        }
        if let Some(pos) = inner.find('*') {
            let suffix = &inner[pos + 1..];
            if !suffix.contains('*') {
                return RuleMatcher::DomainGlob {
                    prefix: inner[..pos].to_owned(),
                    suffix: suffix.to_owned(),
                };
            }
        }
        return RuleMatcher::LazyRegex(std::sync::OnceLock::new(), adguard_to_regex(rule));
    }

    // :// prefix → domain or lazy regex
    if let Some(inner) = rule.strip_prefix("://") {
        let inner = inner.strip_prefix("*.").unwrap_or(inner);
        let inner = strip_tail(inner);
        if !inner.contains('*') && is_domain_chars(inner) {
            return RuleMatcher::Domain(inner.to_ascii_lowercase());
        }
    }

    // *text^ or .text → substring contains
    let stripped = rule.strip_prefix('*').unwrap_or(rule);
    let stripped = strip_tail(stripped);
    if !stripped.contains('*') && !stripped.is_empty() {
        return RuleMatcher::Contains(stripped.to_owned());
    }

    // Fallback: lazy regex
    RuleMatcher::LazyRegex(std::sync::OnceLock::new(), adguard_to_regex(rule))
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
    use super::DomainsFilter;

    fn assert_blocked(filter: &DomainsFilter, domain: &str) {
        let r = filter.match_domain(domain);
        assert!(
            r.is_some() && !r.unwrap().is_allowed(),
            "expected blocked for {domain}"
        );
    }

    fn assert_allowed(filter: &DomainsFilter, domain: &str) {
        let r = filter.match_domain(domain);
        assert!(
            r.is_some() && r.unwrap().is_allowed(),
            "expected allowed for {domain}"
        );
    }

    fn assert_none(filter: &DomainsFilter, domain: &str) {
        assert!(
            filter.match_domain(domain).is_none(),
            "expected none for {domain}"
        );
    }

    #[test]
    fn checker_test() {
        let filter = DomainsFilter::new(
            r"
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
        ",
        )
        .unwrap();

        assert_none(&filter, "rcdn.pro");
        assert_blocked(&filter, "movie1168.com");
        assert_blocked(&filter, "anime-ura.anime-free.net");
        assert_allowed(&filter, "dsa.omniture.walmart.com");
        assert_blocked(&filter, "asdasdasd.....3.n.2.1.l50.js");
        assert_blocked(&filter, "playvideododo.ddd.dddd.videos.vidto.me");
        assert_allowed(&filter, "ya.ru");
        assert_none(&filter, "durasite.net^");
        assert_none(&filter, "play*.videos.vidto.me.asd");
        assert_none(&filter, "raw.githubusercontent.com");
    }

    #[test]
    fn simple_rules() {
        let filter = DomainsFilter::new(
            r"
||simple-block.com^
||another-block.org^
://*.complex-rule.net^
@@||allowed.com^
        ",
        )
        .unwrap();

        assert_blocked(&filter, "simple-block.com");
        assert_blocked(&filter, "sub.simple-block.com");
        assert_blocked(&filter, "test.complex-rule.net");
        assert_allowed(&filter, "allowed.com");
        assert_none(&filter, "google.com");
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
            assert_blocked(&filter, domain);
        }
        assert_none(&filter, "notexact.com");
        assert_none(&filter, "other.org");
    }

    #[test]
    fn contains_rules() {
        let filter = DomainsFilter::new(".tracker.js\n*ad.network.com^").unwrap();

        assert_blocked(&filter, "cdn.tracker.js");
        assert_none(&filter, "tracker.other");
        assert_blocked(&filter, "bad.ad.network.com");
        assert_blocked(&filter, "ad.network.com");
        assert_none(&filter, "network.com");
    }

    #[test]
    fn domain_glob_rules() {
        let filter = DomainsFilter::new("||play*.vidto.me^\n||cdn*.tracker.net^").unwrap();

        assert_blocked(&filter, "playfoo.vidto.me");
        assert_blocked(&filter, "sub.playfoo.vidto.me");
        assert_none(&filter, "notplay.vidto.me");
        assert_none(&filter, "playfoo.other.me");
        assert_blocked(&filter, "cdn123.tracker.net");
        assert_none(&filter, "xcdn.tracker.net");
    }

    #[test]
    fn regex_rules() {
        let filter = DomainsFilter::new(r"/tracker\d+\.example\.com/").unwrap();

        assert_blocked(&filter, "tracker123.example.com");
        assert_none(&filter, "tracker.example.com");
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

        assert_allowed(&filter, "allowed.blocked.com");
        assert_blocked(&filter, "other.blocked.com");
        assert_allowed(&filter, "ads.net");
    }

    #[test]
    fn dollar_rules_are_skipped() {
        let filter = DomainsFilter::new("||example.com^$badfilter").unwrap();
        assert_none(&filter, "example.com");
    }

    #[test]
    fn wildcard_matches_any_subdomain() {
        let filter = DomainsFilter::new("||play*.vidto.me^").unwrap();

        assert_blocked(&filter, "playfoo.vidto.me");
        assert_blocked(&filter, "sub.playfoo.vidto.me");
        assert_none(&filter, "notplay.vidto.me");
        assert_none(&filter, "playfoo.other.me");
    }

    #[test]
    fn display_rule() {
        let filter = DomainsFilter::new("||example.com^\n@@||allowed.com^").unwrap();
        let blocked = filter.match_domain("example.com").unwrap();
        assert_eq!(blocked.to_string(), "blocked by ||example.com^");
        let allowed = filter.match_domain("allowed.com").unwrap();
        assert_eq!(allowed.to_string(), "allowed by @@||allowed.com^");
    }
}

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

#[derive(Debug, PartialEq, Eq)]
pub enum MatchResult<'a> {
    Allow(&'a str),
    Block(&'a str),
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
            .map(Rule::new)
            .collect::<Result<Vec<Rule>>>()?;

        let (allow, block): (Vec<_>, Vec<_>) = all_rules.into_iter().partition(|x| x.is_allow_rule);

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
            return Some(MatchResult::Allow(&rule.rule));
        }
        if let Some(rule) = self.block_matcher.match_domain(domain) {
            return Some(MatchResult::Block(&rule.rule));
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

// --- Rule ---

struct Rule {
    matcher: RuleMatcher,
    rule: String,
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

impl Rule {
    fn new(rule: &str) -> Result<Self> {
        let (is_allow_rule, rule_text) = match rule.strip_prefix("@@") {
            Some(stripped) => (true, stripped),
            None => (false, rule),
        };

        let matcher = parse_matcher(rule_text);

        Ok(Self {
            matcher,
            rule: rule_text.to_owned(),
            is_allow_rule,
        })
    }

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

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("rule", &self.rule)
            .field("is_allow_rule", &self.is_allow_rule)
            .finish()
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
            Some(MatchResult::Allow("||omniture.walmart.com^|"))
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
            Some(MatchResult::Allow("||ya.ru"))
        );
        assert_eq!(filter.match_domain("durasite.net^"), None);
        assert_eq!(filter.match_domain("play*.videos.vidto.me.asd"), None);
        assert_eq!(filter.match_domain("raw.githubusercontent.com"), None);
    }

    #[test]
    fn simple_rules() {
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
            Some(MatchResult::Allow("||allowed.com^"))
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
            Some(MatchResult::Allow("||allowed.blocked.com^"))
        );
        assert_eq!(
            filter.match_domain("other.blocked.com"),
            Some(MatchResult::Block("||blocked.com^"))
        );
        assert_eq!(
            filter.match_domain("ads.net"),
            Some(MatchResult::Allow("||ads.net^"))
        );
    }

    #[test]
    fn dollar_rules_are_skipped() {
        let filter = DomainsFilter::new("||example.com^$badfilter").unwrap();
        assert_eq!(filter.match_domain("example.com"), None);
    }

    #[test]
    fn wildcard_matches_any_subdomain() {
        let filter = DomainsFilter::new("||play*.vidto.me^").unwrap();

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
    }
}

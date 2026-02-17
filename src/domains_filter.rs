use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    time::Duration,
};

use crate::files_stream::create_files_stream;
use anyhow::Result;
use futures_util::stream::Stream;
use log::{error, warn};
use once_cell::sync::OnceCell;
use regex::Regex;
use reqwest::Url;
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
) -> Result<impl Stream<Item = DomainsFilter>> {
    Ok(
        create_files_stream(filter_url, update_interval)?.filter_map(move |filter| {
            let manual_rules = manual_rules.join("\n");
            let domains_filter = std::str::from_utf8(filter.as_ref())
                .map_err(anyhow::Error::from)
                .and_then(|rules| DomainsFilter::new(&(manual_rules + rules)));
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

#[derive(Debug)]
pub struct DomainsFilter {
    allow_matcher: RulesMatcher,
    block_matcher: RulesMatcher,
}

impl DomainsFilter {
    pub fn new(rules: &str) -> Result<Self> {
        let (allow, block) = rules
            .lines()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty() && !x.starts_with('!') && !x.contains('$'))
            .map(Rule::new)
            .collect::<Result<Vec<Rule>>>()?
            .into_iter()
            .partition(|x| x.is_allow_rule);
        let allow_matcher = RulesMatcher::new(allow);
        let block_matcher = RulesMatcher::new(block);
        Ok(Self {
            allow_matcher,
            block_matcher,
        })
    }

    pub fn match_domain(&self, domain: &str) -> Option<MatchResult<'_>> {
        self.allow_matcher
            .match_domain(domain)
            .or_else(|| self.block_matcher.match_domain(domain))
            .map(|x| MatchResult {
                rule: &x.rule,
                is_allowed: x.is_allow_rule,
            })
    }
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
        let filter = DomainsFilter::new(filter).unwrap();

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
}

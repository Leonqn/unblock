use std::time::Duration;

use crate::files_stream::create_files_stream;
use aho_corasick::AhoCorasick;
use anyhow::Result;
use futures_util::stream::Stream;
use log::error;
use regex::Regex;
use reqwest::Url;
use tokio::stream::StreamExt;

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
            let domains_filter = tokio::task::block_in_place(|| {
                let manual_rules = manual_rules.join("\n");
                std::str::from_utf8(filter.as_ref())
                    .map_err(anyhow::Error::from)
                    .and_then(|rules| DomainsFilter::new(&(manual_rules + rules)))
            });
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

    pub fn match_domain(&self, domain: &str) -> Option<MatchResult> {
        self.allow_matcher
            .match_domain(domain)
            .or_else(|| self.block_matcher.match_domain(domain))
            .map(|x| MatchResult {
                rule: &x.original_rule,
                is_allowed: x.is_allow_rule,
            })
    }
}

#[derive(Debug)]
struct RulesMatcher {
    rules_substr: AhoCorasick,
    rules: Vec<Rule>,
}

impl RulesMatcher {
    pub fn new(rules: Vec<Rule>) -> Self {
        let substrs = rules
            .iter()
            .map(|rule| {
                rule.regex
                    .as_str()
                    .split(|c| !char::is_alphanumeric(c))
                    .max_by_key(|x| x.len())
                    .unwrap_or("")
            })
            .collect::<Vec<_>>();
        let rules_substr = AhoCorasick::new_auto_configured(&substrs);
        Self {
            rules_substr,
            rules,
        }
    }

    fn match_domain(&self, domain: &str) -> Option<&Rule> {
        self.rules_substr
            .find_overlapping_iter(domain)
            .find_map(move |match_res| {
                let rule = &self.rules[match_res.pattern()];
                if rule.regex.is_match(domain) {
                    Some(rule)
                } else {
                    None
                }
            })
    }
}

#[derive(Debug)]
struct Rule {
    regex: Regex,
    original_rule: String,
    is_allow_rule: bool,
}

impl Rule {
    fn new(rule: &str) -> Result<Self> {
        if let Some(stripped) = rule.strip_prefix("@@") {
            Ok(Self {
                regex: Regex::new(&Self::create_regex_string(&stripped))?,
                original_rule: rule.to_owned(),
                is_allow_rule: true,
            })
        } else {
            Ok(Self {
                regex: Regex::new(&Self::create_regex_string(&rule))?,
                original_rule: rule.to_owned(),
                is_allow_rule: false,
            })
        }
    }

    fn create_regex_string(rule: &str) -> String {
        if rule.starts_with('/') && rule.ends_with('/') {
            rule.trim_matches('/').replace(r"\/", r"/")
        } else {
            let mut regex = regex::escape(rule)
                .replace(r"\*", ".*")
                .replace(r"\^", "$")
                .replace("://", "");

            if let Some(stripped) = regex.strip_prefix(r"\|\|") {
                regex = String::from(r"([\w\d\-_\.]+\.)?") + stripped;
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
                rule: r"@@||omniture.walmart.com^|",
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
                rule: r"@@||ya.ru",
            })
        );
        assert_eq!(filter.match_domain("durasite.net^"), None);
        assert_eq!(filter.match_domain("play*.videos.vidto.me.asd"), None);
    }
}

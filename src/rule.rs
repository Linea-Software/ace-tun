//! Rule definition and evaluation engine.
//!
//! Ported from ProxyBridge's `match_rule` / `match_rule_inner` family. A
//! [`Rule`] pairs a set of match criteria (process names, destination hosts,
//! ports, domains) with an [`RuleAction`]. A [`RuleSet`] compiles the rules
//! once and evaluates a connection against them in order.
//!
//! Matching semantics (identical to the C original):
//! * Rules are evaluated top to bottom; the first specific match wins.
//! * A *fully wildcard* rule (`*` process, all hosts/ports/domains) is held back
//!   as a fallback and only applied if no other rule matched.
//! * If nothing matches at all the action is [`RuleAction::Direct`].
//! * Host / port / domain filters are AND-combined; an empty or `*` filter
//!   matches everything.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;

/// What to do with a matched connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Redirect the connection through the configured upstream proxy.
    Proxy,
    /// Let the connection through untouched.
    Direct,
    /// Drop the connection entirely.
    Block,
}

/// Which transport protocol a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProtocol {
    /// TCP only.
    Tcp,
    /// UDP only.
    Udp,
    /// Both TCP and UDP.
    Both,
}

impl RuleProtocol {
    fn matches(self, is_udp: bool) -> bool {
        match self {
            RuleProtocol::Both => true,
            RuleProtocol::Tcp => !is_udp,
            RuleProtocol::Udp => is_udp,
        }
    }
}

/// A single routing rule.
///
/// Construct with [`Rule::new`] and refine with the builder methods:
///
/// ```
/// use ace_tun::{Rule, RuleAction};
///
/// let rule = Rule::new("chrome.exe;firefox.exe")
///     .hosts("*")
///     .ports("80;443")
///     .action(RuleAction::Proxy);
/// ```
#[derive(Debug, Clone)]
pub struct Rule {
    process_names: String,
    hosts: String,
    ports: String,
    domains: String,
    except_hosts: Option<String>,
    protocol: RuleProtocol,
    action: RuleAction,
    proxy_config_id: u32,
}

impl Rule {
    /// Create a rule matching the given semicolon/comma-separated process list.
    /// `"*"` (or `"ANY"`) matches every process.
    pub fn new(process_names: impl Into<String>) -> Self {
        Self {
            process_names: process_names.into(),
            hosts: "*".to_string(),
            ports: "*".to_string(),
            domains: "*".to_string(),
            except_hosts: None,
            protocol: RuleProtocol::Both,
            action: RuleAction::Direct,
            proxy_config_id: 0,
        }
    }

    /// Restrict the rule to these destination hosts/IPs (semicolon separated).
    /// Supports exact IPs, octet wildcards (`192.168.*.*`), ranges (`a-b`) and
    /// IPv6 CIDR (`2001:db8::/32`). `"*"` matches all.
    pub fn hosts(mut self, hosts: impl Into<String>) -> Self {
        self.hosts = hosts.into();
        self
    }

    /// Restrict the rule to these destination ports (`"80;443;8000-9000"`).
    pub fn ports(mut self, ports: impl Into<String>) -> Self {
        self.ports = ports.into();
        self
    }

    /// Restrict the rule to these destination domains (glob patterns like
    /// `*.example.com`). Matching relies on DNS snooping of plaintext DNS.
    pub fn domains(mut self, domains: impl Into<String>) -> Self {
        self.domains = domains.into();
        self
    }

    /// Exclude these destination hosts/IPs from the rule: if the destination
    /// matches any pattern here the rule is skipped. Useful for carving
    /// loopback out of a catch-all.
    pub fn except(mut self, hosts: impl Into<String>) -> Self {
        self.except_hosts = Some(hosts.into());
        self
    }

    /// Restrict the rule to a transport protocol (default [`RuleProtocol::Both`]).
    pub fn protocol(mut self, protocol: RuleProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the action taken when this rule matches (default [`RuleAction::Direct`]).
    pub fn action(mut self, action: RuleAction) -> Self {
        self.action = action;
        self
    }

    /// Select which upstream proxy config this rule uses (0 = first available).
    /// Only meaningful for [`RuleAction::Proxy`].
    pub fn proxy_config(mut self, id: u32) -> Self {
        self.proxy_config_id = id;
        self
    }

    /// The action this rule yields on match.
    pub fn action_kind(&self) -> RuleAction {
        self.action
    }

    fn compile(&self) -> CompiledRule {
        CompiledRule {
            process_matchers: compile_process_list(&self.process_names),
            process_wildcard: is_match_all(&self.process_names),
            hosts: self.hosts.clone(),
            hosts_all: is_match_all(&self.hosts),
            ports: self.ports.clone(),
            ports_all: is_match_all(&self.ports),
            domain_matchers: compile_glob_list(&self.domains),
            domains_all: is_match_all(&self.domains),
            except_hosts: self.except_hosts.clone(),
            protocol: self.protocol,
            action: self.action,
            proxy_config_id: self.proxy_config_id,
        }
    }
}

/// A compiled, evaluation-ready collection of [`Rule`]s.
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    /// `true` if any rule carries a domain filter — gates the (relatively
    /// expensive) DNS cache lookup, mirroring `g_has_domain_rules`.
    has_domain_rules: bool,
}

/// Outcome of evaluating a connection against a [`RuleSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMatch {
    /// The action to take.
    pub action: RuleAction,
    /// The proxy config id to use (only relevant for [`RuleAction::Proxy`]).
    pub proxy_config_id: u32,
}

impl RuleSet {
    /// Compile a list of rules into an evaluation-ready set.
    pub fn new(rules: &[Rule]) -> Self {
        let compiled: Vec<CompiledRule> = rules.iter().map(Rule::compile).collect();
        let has_domain_rules = compiled.iter().any(|r| !r.domains_all);
        Self {
            rules: compiled,
            has_domain_rules,
        }
    }

    /// Whether any rule needs a resolved destination domain.
    pub fn needs_domain_resolution(&self) -> bool {
        self.has_domain_rules
    }

    /// Whether the set has any rules at all.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate a connection.
    ///
    /// `process_name` is the executable file name of the owning process,
    /// `dest` / `dest_port` the original destination, `is_udp` the protocol,
    /// and `domain` the destination hostname resolved from the DNS cache (if
    /// any).
    pub fn evaluate(
        &self,
        process_name: &str,
        dest: IpAddr,
        dest_port: u16,
        is_udp: bool,
        domain: Option<&str>,
    ) -> RuleMatch {
        let mut fallback: Option<&CompiledRule> = None;

        for rule in &self.rules {
            if !rule.protocol.matches(is_udp) {
                continue;
            }

            if rule.process_wildcard {
                let filtered = !rule.hosts_all
                    || !rule.ports_all
                    || !rule.domains_all
                    || rule.except_hosts.is_some();
                if filtered {
                    if rule.matches_target(dest, dest_port, domain) {
                        return rule.as_match();
                    }
                    continue;
                }
                // Fully wildcard rule: hold as fallback.
                if fallback.is_none() {
                    fallback = Some(rule);
                }
                continue;
            }

            if rule.matches_process(process_name) && rule.matches_target(dest, dest_port, domain) {
                return rule.as_match();
            }
        }

        if let Some(rule) = fallback {
            return rule.as_match();
        }

        RuleMatch {
            action: RuleAction::Direct,
            proxy_config_id: 0,
        }
    }
}

#[derive(Debug)]
struct CompiledRule {
    process_matchers: Vec<Regex>,
    process_wildcard: bool,
    hosts: String,
    hosts_all: bool,
    ports: String,
    ports_all: bool,
    domain_matchers: Vec<Regex>,
    domains_all: bool,
    except_hosts: Option<String>,
    protocol: RuleProtocol,
    action: RuleAction,
    proxy_config_id: u32,
}

impl CompiledRule {
    fn as_match(&self) -> RuleMatch {
        RuleMatch {
            action: self.action,
            proxy_config_id: self.proxy_config_id,
        }
    }

    fn matches_process(&self, process_name: &str) -> bool {
        if self.process_wildcard {
            return true;
        }
        // Rules are typically written against Windows names (`chrome.exe`) but
        // run against whatever the platform resolves (`chrome` on Linux);
        // compare both sides without the `.exe` suffix.
        let name = strip_exe_suffix(process_name);
        self.process_matchers
            .iter()
            .any(|m| m.is_match(name))
    }

    fn matches_target(&self, dest: IpAddr, dest_port: u16, domain: Option<&str>) -> bool {
        if let Some(except) = &self.except_hosts
            && match_ip_list(except, dest)
        {
            return false;
        }
        (self.hosts_all || match_ip_list(&self.hosts, dest))
            && (self.ports_all || match_port_list(&self.ports, dest_port))
            && (self.domains_all || self.matches_domain(domain))
    }

    fn matches_domain(&self, domain: Option<&str>) -> bool {
        match domain {
            Some(d) => self.domain_matchers.iter().any(|m| m.is_match(d)),
            None => false,
        }
    }
}

// ── Token-list helpers ────────────────────────────────────────────────

/// A list matches everything if it is empty or a single `*` / `ANY`.
fn is_match_all(list: &str) -> bool {
    let t = list.trim();
    t.is_empty() || t == "*" || t.eq_ignore_ascii_case("ANY")
}

fn split_list(list: &str) -> impl Iterator<Item = &str> {
    list.split([';', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn compile_glob_list(list: &str) -> Vec<Regex> {
    if is_match_all(list) {
        return Vec::new();
    }
    split_list(list).filter_map(compile_glob).collect()
}

/// Compile a process-name list, stripping Windows `.exe` suffixes first.
///
/// The engine configures rules with Windows names (`chrome.exe;brave.exe`);
/// on Linux the same processes resolve as `chrome`, `brave`. Normalizing both
/// sides (see [`CompiledRule::matches_process`]) keeps those rule strings
/// unchanged on every platform.
fn compile_process_list(list: &str) -> Vec<Regex> {
    if is_match_all(list) {
        return Vec::new();
    }
    split_list(list)
        .map(strip_exe_suffix)
        .filter_map(compile_glob)
        .collect()
}

/// Strip a trailing `.exe` (case-insensitively) from a process name or rule
/// token. Globs keep their special characters: `chrome*` is untouched, while
/// `chrome.exe` becomes `chrome`.
fn strip_exe_suffix(token: &str) -> &str {
    const SUFFIX: &str = ".exe";
    if token.len() >= SUFFIX.len()
        && token[token.len() - SUFFIX.len()..].eq_ignore_ascii_case(SUFFIX)
    {
        &token[..token.len() - SUFFIX.len()]
    } else {
        token
    }
}

/// Convert a case-insensitive glob (`*`, `?`) into an anchored [`Regex`].
fn compile_glob(glob: &str) -> Option<Regex> {
    let mut pattern = String::with_capacity(glob.len() + 8);
    pattern.push_str("(?i)^");
    for ch in glob.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            c => pattern.push_str(&regex::escape(&c.to_string())),
        }
    }
    pattern.push('$');
    Regex::new(&pattern).ok()
}

// ── IP / port matching ────────────────────────────────────────────────

fn match_ip_list(list: &str, ip: IpAddr) -> bool {
    if is_match_all(list) {
        return true;
    }
    split_list(list).any(|tok| match_ip_pattern(tok, ip))
}

fn match_ip_pattern(pattern: &str, ip: IpAddr) -> bool {
    if pattern == "*" {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => match_ipv4_pattern(pattern, v4),
        IpAddr::V6(v6) => match_ipv6_pattern(pattern, v6),
    }
}

fn match_ipv4_pattern(pattern: &str, ip: Ipv4Addr) -> bool {
    // IPv6-looking patterns never match IPv4.
    if pattern.contains(':') {
        return false;
    }
    let octets = ip.octets();

    // Range: "a.b.c.d-e.f.g.h"
    if let Some((start, end)) = pattern.split_once('-') {
        if let (Ok(s), Ok(e)) = (
            start.trim().parse::<Ipv4Addr>(),
            end.trim().parse::<Ipv4Addr>(),
        ) {
            let v = u32::from(ip);
            return v >= u32::from(s) && v <= u32::from(e);
        }
        return false;
    }

    // Octet wildcard: "192.168.*.*"
    let parts: Vec<&str> = pattern.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for (part, octet) in parts.iter().zip(octets.iter()) {
        if *part == "*" {
            continue;
        }
        match part.parse::<u8>() {
            Ok(v) if v == *octet => {}
            _ => return false,
        }
    }
    true
}

fn match_ipv6_pattern(pattern: &str, ip: Ipv6Addr) -> bool {
    if pattern == "*" {
        return true;
    }
    // IPv4-only patterns never match IPv6.
    if !pattern.contains(':') {
        return false;
    }

    // CIDR: "2001:db8::/32"
    if let Some((net, prefix)) = pattern.split_once('/') {
        let (Ok(network), Ok(prefix_len)) =
            (net.trim().parse::<Ipv6Addr>(), prefix.trim().parse::<u32>())
        else {
            return false;
        };
        if prefix_len > 128 {
            return false;
        }
        let net_bits = u128::from(network);
        let ip_bits = u128::from(ip);
        if prefix_len == 0 {
            return true;
        }
        let mask = u128::MAX << (128 - prefix_len);
        return (net_bits & mask) == (ip_bits & mask);
    }

    // Range: "2001:db8::1-2001:db8::ff"
    if let Some((start, end)) = pattern.split_once('-') {
        if let (Ok(s), Ok(e)) = (
            start.trim().parse::<Ipv6Addr>(),
            end.trim().parse::<Ipv6Addr>(),
        ) {
            let v = u128::from(ip);
            return v >= u128::from(s) && v <= u128::from(e);
        }
        return false;
    }

    // Exact.
    pattern
        .trim()
        .parse::<Ipv6Addr>()
        .map(|a| a == ip)
        .unwrap_or(false)
}

fn match_port_list(list: &str, port: u16) -> bool {
    if is_match_all(list) {
        return true;
    }
    split_list(list).any(|tok| match_port_pattern(tok, port))
}

fn match_port_pattern(pattern: &str, port: u16) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some((start, end)) = pattern.split_once('-') {
        match (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
            (Ok(s), Ok(e)) => port >= s && port <= e,
            _ => false,
        }
    } else {
        pattern
            .trim()
            .parse::<u16>()
            .map(|p| p == port)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn glob_matches_process_names() {
        let m = compile_glob("fire*.exe").unwrap();
        assert!(m.is_match("firefox.exe"));
        assert!(m.is_match("FIREFOX.EXE")); // case-insensitive
        assert!(!m.is_match("chrome.exe"));

        let m = compile_glob("vpn*.exe").unwrap();
        assert!(m.is_match("vpnclient.exe"));
        assert!(!m.is_match("myvpn.exe"));

        let m = compile_glob("*steam*").unwrap();
        assert!(m.is_match("steamwebhelper.exe"));
        assert!(m.is_match("mysteamapp"));

        let q = compile_glob("a?c.exe").unwrap();
        assert!(q.is_match("abc.exe"));
        assert!(!q.is_match("ac.exe"));
    }

    #[test]
    fn ipv4_patterns() {
        assert!(match_ipv4_pattern(
            "192.168.1.1",
            "192.168.1.1".parse().unwrap()
        ));
        assert!(match_ipv4_pattern(
            "192.168.*.*",
            "192.168.5.9".parse().unwrap()
        ));
        assert!(!match_ipv4_pattern(
            "192.168.*.*",
            "10.0.0.1".parse().unwrap()
        ));
        assert!(match_ipv4_pattern(
            "10.0.0.1-10.0.0.10",
            "10.0.0.5".parse().unwrap()
        ));
        assert!(!match_ipv4_pattern(
            "10.0.0.1-10.0.0.10",
            "10.0.0.20".parse().unwrap()
        ));
        // IPv6 pattern never matches IPv4
        assert!(!match_ipv4_pattern("::1", "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_patterns() {
        assert!(match_ipv6_pattern("::1", "::1".parse().unwrap()));
        assert!(match_ipv6_pattern(
            "2001:db8::/32",
            "2001:db8:1234::1".parse().unwrap()
        ));
        assert!(!match_ipv6_pattern(
            "2001:db8::/32",
            "2001:dbff::1".parse().unwrap()
        ));
        assert!(match_ipv6_pattern("*", "fe80::1".parse().unwrap()));
        // IPv4 pattern never matches IPv6
        assert!(!match_ipv6_pattern("127.0.0.1", "::1".parse().unwrap()));
    }

    #[test]
    fn port_patterns() {
        assert!(match_port_pattern("443", 443));
        assert!(!match_port_pattern("443", 80));
        assert!(match_port_pattern("8000-9000", 8443));
        assert!(!match_port_pattern("8000-9000", 9001));
        assert!(match_port_list("80;443;8000-9000", 443));
        assert!(match_port_list("*", 12345));
    }

    #[test]
    fn no_rules_defaults_to_direct() {
        let set = RuleSet::new(&[]);
        let m = set.evaluate("chrome.exe", v4("1.2.3.4"), 443, false, None);
        assert_eq!(m.action, RuleAction::Direct);
    }

    #[test]
    fn specific_process_beats_wildcard_fallback() {
        let rules = [
            Rule::new("chrome.exe")
                .action(RuleAction::Proxy)
                .proxy_config(7),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);
        let m = set.evaluate("chrome.exe", v4("1.2.3.4"), 443, false, None);
        assert_eq!(m.action, RuleAction::Proxy);
        assert_eq!(m.proxy_config_id, 7);
        // Other process falls through to the wildcard fallback.
        let m = set.evaluate("notepad.exe", v4("1.2.3.4"), 443, false, None);
        assert_eq!(m.action, RuleAction::Direct);
    }

    #[test]
    fn filtered_wildcard_matches_before_fallback() {
        let rules = [
            Rule::new("*").ports("443").action(RuleAction::Block),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);
        assert_eq!(
            set.evaluate("x.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("x.exe", v4("1.2.3.4"), 80, false, None).action,
            RuleAction::Direct
        );
    }

    #[test]
    fn except_hosts_skips_rule() {
        let rules = [
            Rule::new("*")
                .except("127.0.0.1;::1")
                .action(RuleAction::Proxy),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);
        // Loopback is excepted from the proxy rule -> falls to Direct fallback.
        assert_eq!(
            set.evaluate("x.exe", v4("127.0.0.1"), 443, false, None)
                .action,
            RuleAction::Direct
        );
        // Non-loopback still proxied.
        assert_eq!(
            set.evaluate("x.exe", v4("8.8.8.8"), 443, false, None)
                .action,
            RuleAction::Proxy
        );
    }

    #[test]
    fn protocol_filter() {
        let rules = [Rule::new("*")
            .ports("443")
            .protocol(RuleProtocol::Udp)
            .action(RuleAction::Block)];
        let set = RuleSet::new(&rules);
        // UDP 443 blocked (QUIC), TCP 443 not.
        assert_eq!(
            set.evaluate("x.exe", v4("1.2.3.4"), 443, true, None).action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("x.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Direct
        );
    }

    #[test]
    fn domain_filter_matches_via_cache() {
        let rules = [
            Rule::new("*")
                .domains("*.evil.com")
                .action(RuleAction::Block),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);
        assert!(set.needs_domain_resolution());
        assert_eq!(
            set.evaluate("x.exe", v4("1.2.3.4"), 443, false, Some("relay.evil.com"))
                .action,
            RuleAction::Block
        );
        // No domain resolved -> domain rule can't match -> fallback Direct.
        assert_eq!(
            set.evaluate("x.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Direct
        );
    }

    #[test]
    fn ipv6_destination_matches() {
        let rules = [Rule::new("*")
            .hosts("2001:db8::/32")
            .action(RuleAction::Block)];
        let set = RuleSet::new(&rules);
        assert_eq!(
            set.evaluate("x.exe", v6("2001:db8::1"), 443, false, None)
                .action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("x.exe", v6("2001:dbff::1"), 443, false, None)
                .action,
            RuleAction::Direct
        );
    }

    #[test]
    fn comma_and_whitespace_separators() {
        // split_list handles both ';' and ',' delimiters with trimming.
        let rule = Rule::new("chrome.exe , firefox.exe").action(RuleAction::Block);
        let set = RuleSet::new(&[rule]);
        // Both process names should match despite the comma + whitespace separator.
        assert_eq!(
            set.evaluate("chrome.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("firefox.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        // Unrelated process does not match.
        assert_eq!(
            set.evaluate("notepad.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Direct
        );
    }

    /// Engine rule strings keep Windows names (`chrome.exe`); on Linux the
    /// same processes resolve as `chrome`. The `.exe` suffix must not break
    /// matching in either direction.
    #[test]
    fn windows_exe_rules_match_unix_process_names() {
        let rules = [Rule::new("chrome.exe;brave.exe").action(RuleAction::Block)];
        let set = RuleSet::new(&rules);
        // Linux process names carry no suffix.
        assert_eq!(
            set.evaluate("chrome", v4("1.2.3.4"), 443, false, None).action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("brave", v4("1.2.3.4"), 443, false, None).action,
            RuleAction::Block
        );
        // Windows names still match (both sides normalized).
        assert_eq!(
            set.evaluate("CHROME.EXE", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        // Unrelated process does not match.
        assert_eq!(
            set.evaluate("firefox", v4("1.2.3.4"), 443, false, None).action,
            RuleAction::Direct
        );
    }

    /// Rules authored without a suffix (`firefox`) match Windows names too.
    #[test]
    fn unix_style_rules_match_windows_process_names() {
        let rules = [Rule::new("firefox").action(RuleAction::Block)];
        let set = RuleSet::new(&rules);
        assert_eq!(
            set.evaluate("firefox.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
    }

    /// Glob suffixes are preserved: `chrome*` must still match `chrome.exe`,
    /// and `*.exe` degenerates to `*` only because every Windows binary has
    /// the suffix anyway.
    #[test]
    fn glob_patterns_survive_exe_normalization() {
        let rules = [Rule::new("chrome*").action(RuleAction::Block)];
        let set = RuleSet::new(&rules);
        assert_eq!(
            set.evaluate("chrome.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("chrome-helper", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("chromium", v4("1.2.3.4"), 443, false, None).action,
            RuleAction::Direct
        );
    }

    #[test]
    fn strip_exe_suffix_is_case_insensitive_and_globsafe() {
        assert_eq!(strip_exe_suffix("chrome.exe"), "chrome");
        assert_eq!(strip_exe_suffix("CHROME.EXE"), "CHROME");
        assert_eq!(strip_exe_suffix("Brave.Exe"), "Brave");
        assert_eq!(strip_exe_suffix("firefox"), "firefox");
        assert_eq!(strip_exe_suffix("chrome*"), "chrome*");
        assert_eq!(strip_exe_suffix("*.exe"), "*");
        assert_eq!(strip_exe_suffix("a?.exe"), "a?");
        assert_eq!(strip_exe_suffix(""), "");
    }

    #[test]
    fn port_range_at_bounds() {
        // Range 1-65535 covers the entire valid u16 port space except 0.
        assert!(match_port_pattern("1-65535", 1));
        assert!(match_port_pattern("1-65535", 65535));
        assert!(!match_port_pattern("1-65535", 0));
        // Range 0-0 matches only port 0.
        assert!(match_port_pattern("0-0", 0));
        assert!(!match_port_pattern("0-0", 1));
    }

    #[test]
    fn ipv4_range_ordering() {
        // When the start IP is numerically higher than the end IP the
        // range never matches because the code uses start <= ip <= end.
        // This is intentional: callers must supply ranges in ascending
        // order (e.g. "10.0.0.1-10.0.0.10").
        let ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        assert!(!match_ipv4_pattern("10.0.0.10-10.0.0.1", ip));
        // Confirm the correctly-ordered range does match.
        assert!(match_ipv4_pattern("10.0.0.1-10.0.0.10", ip));
    }

    #[test]
    fn ipv6_cidr_boundary_bits() {
        // /32 means only the top 32 bits are significant.
        // 2001:0db8:ffff:… still shares the 2001:0db8 prefix → matches.
        assert!(match_ipv6_pattern(
            "2001:db8::/32",
            "2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
        // 2001:0db9:: differs in the 32nd bit → does not match.
        assert!(!match_ipv6_pattern(
            "2001:db8::/32",
            "2001:0db9::".parse().unwrap()
        ));
    }

    #[test]
    fn any_is_wildcard_synonym() {
        // "ANY" (any casing) is treated identically to "*".
        assert!(is_match_all("ANY"));
        assert!(is_match_all("any"));
        assert!(is_match_all("Any"));

        // A rule created with "ANY" acts as a wildcard process matcher.
        let rules = [Rule::new("ANY").action(RuleAction::Block)];
        let set = RuleSet::new(&rules);
        // ANY matches any process → captured as fallback.
        assert_eq!(
            set.evaluate("chrome.exe", v4("8.8.8.8"), 443, false, None)
                .action,
            RuleAction::Block
        );
        assert_eq!(
            set.evaluate("random.exe", v4("8.8.8.8"), 443, false, None)
                .action,
            RuleAction::Block
        );
    }

    #[test]
    fn multiple_proxy_config_ids() {
        let rules = [
            Rule::new("chrome.exe")
                .action(RuleAction::Proxy)
                .proxy_config(3),
            Rule::new("firefox.exe")
                .action(RuleAction::Proxy)
                .proxy_config(7),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);

        let m = set.evaluate("chrome.exe", v4("1.2.3.4"), 443, false, None);
        assert_eq!(m.action, RuleAction::Proxy);
        assert_eq!(m.proxy_config_id, 3);

        let m = set.evaluate("firefox.exe", v4("1.2.3.4"), 443, false, None);
        assert_eq!(m.action, RuleAction::Proxy);
        assert_eq!(m.proxy_config_id, 7);
    }

    #[test]
    fn rule_ordering_first_specific_wins() {
        // A fully-wildcard fallback rule (no filters) is held back, so a
        // specific rule later in the list still wins when it matches.
        let rules = [
            Rule::new("*").action(RuleAction::Proxy),
            Rule::new("chrome.exe")
                .ports("443")
                .action(RuleAction::Block),
        ];
        let set = RuleSet::new(&rules);

        // chrome.exe on port 443 → specific rule wins over wildcard fallback.
        assert_eq!(
            set.evaluate("chrome.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Block
        );
        // chrome.exe on port 80 → specific rule doesn't match port → fallback.
        assert_eq!(
            set.evaluate("chrome.exe", v4("1.2.3.4"), 80, false, None)
                .action,
            RuleAction::Proxy
        );
        // Other process → no specific rule matches → fallback.
        assert_eq!(
            set.evaluate("firefox.exe", v4("1.2.3.4"), 443, false, None)
                .action,
            RuleAction::Proxy
        );
    }

    #[test]
    fn except_with_multiple_entries() {
        // except() with semicolon-separated entries: each one is checked
        // independently. IPv4 octet wildcards are supported (CIDR is not).
        let rules = [
            Rule::new("*")
                .except("127.0.0.1;::1;10.*.*.*")
                .action(RuleAction::Proxy),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);

        // 10.0.0.5 matches 10.*.*.* → excepted from proxy → falls to Direct.
        assert_eq!(
            set.evaluate("x.exe", v4("10.0.0.5"), 443, false, None)
                .action,
            RuleAction::Direct
        );
        // 8.8.8.8 is not in any except entry → proxied.
        assert_eq!(
            set.evaluate("x.exe", v4("8.8.8.8"), 443, false, None)
                .action,
            RuleAction::Proxy
        );
    }

    #[test]
    fn complex_except_falls_through() {
        // "except" means "skip this rule" — it does not directly produce
        // an action. Here the first rule excepts loopback so it is skipped;
        // with no fallback rule the connection gets the default Direct.
        let rules = [Rule::new("*")
            .except("127.0.0.1;::1")
            .action(RuleAction::Proxy)];
        let set = RuleSet::new(&rules);

        // 127.0.0.1 is excepted → rule skipped → no match → Direct.
        assert_eq!(
            set.evaluate("x.exe", v4("127.0.0.1"), 443, false, None)
                .action,
            RuleAction::Direct
        );
        // 8.8.8.8 is not excepted → rule matches → Proxy.
        assert_eq!(
            set.evaluate("x.exe", v4("8.8.8.8"), 443, false, None)
                .action,
            RuleAction::Proxy
        );
    }

    #[test]
    fn rule_with_null_domain_when_domain_required() {
        // When the resolved domain is None, a domain-filtering rule cannot
        // match and the connection falls through to the fallback.
        let rules = [
            Rule::new("*")
                .domains("*.example.com")
                .action(RuleAction::Block),
            Rule::new("*").action(RuleAction::Direct),
        ];
        let set = RuleSet::new(&rules);
        assert!(set.needs_domain_resolution());

        // Domain is None → domain rule skipped → falls to Direct fallback.
        assert_eq!(
            set.evaluate("x.exe", v4("93.184.216.34"), 443, false, None)
                .action,
            RuleAction::Direct
        );
        // Same IP but with a matching domain → blocked.
        assert_eq!(
            set.evaluate(
                "x.exe",
                v4("93.184.216.34"),
                443,
                false,
                Some("www.example.com")
            )
            .action,
            RuleAction::Block
        );
    }
}

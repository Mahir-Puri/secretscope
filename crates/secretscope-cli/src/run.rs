//! Command orchestration: scan, map credentials to identities, analyze blast
//! radius, score risk, print, and choose an exit code.
//!
//! Exit codes:
//! - 0: completed, nothing reached the configured severity threshold
//! - 1: at least one finding reached or exceeded the threshold
//! - 2: an error (bad input, unreadable config, git failure)

use crate::config::FileConfig;
use crate::output::{render_json, render_text, Meta};
use clap::{Args, ValueEnum};
use secretscope_graph::{analyze_with_tree, BlastRadius};
use secretscope_iam::{load_account, Account};
use secretscope_risk::{assess, RiskAssessment, Severity};
use secretscope_scanner::{scan, Finding, ScanOptions};
use std::path::PathBuf;
use std::str::FromStr;

pub const EXIT_OK: i32 = 0;
pub const EXIT_THRESHOLD: i32 = 1;
pub const EXIT_ERROR: i32 = 2;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Directory to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Include git history in the scan.
    #[arg(long)]
    pub history: bool,

    /// Force git history off, overriding configuration.
    #[arg(long = "no-history")]
    pub no_history: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: Format,

    /// Exit non-zero when a finding reaches this severity (low, medium, high, critical).
    #[arg(long = "fail-on")]
    pub fail_on: Option<String>,

    /// Directory of synthetic IAM fixtures used for blast-radius analysis.
    #[arg(long = "iam-dir")]
    pub iam_dir: Option<PathBuf>,

    /// Extra path substring to exclude. May be repeated.
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,

    /// Path to a specific configuration file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Override the generic detector's entropy threshold.
    #[arg(long = "entropy-threshold")]
    pub entropy_threshold: Option<f64>,

    /// Disable ANSI colour in text output.
    #[arg(long = "no-color")]
    pub no_color: bool,
}

/// A finding plus everything the analysis derived from it.
pub struct AnalyzedFinding {
    pub finding: Finding,
    pub principal: Option<String>,
    pub blast: Option<BlastRadius>,
    pub tree: Option<String>,
    pub risk: RiskAssessment,
}

/// Entry point used by `main`. Never panics on expected errors.
pub fn run(args: ScanArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            EXIT_ERROR
        }
    }
}

fn parse_severity(s: &str) -> anyhow::Result<Severity> {
    Severity::from_str(s).map_err(|e| anyhow::anyhow!(e))
}

fn run_inner(args: ScanArgs) -> anyhow::Result<i32> {
    let root = args.path.clone();

    let config = match &args.config {
        Some(path) => FileConfig::load(path)?,
        None => FileConfig::discover(&root)?,
    };

    // Merge configuration with flags. Flags win.
    let scan_history = if args.no_history {
        false
    } else if args.history {
        true
    } else {
        config.scan_history.unwrap_or(false)
    };

    let entropy_threshold = args
        .entropy_threshold
        .or(config.entropy_threshold)
        .unwrap_or(4.2);

    let mut excludes = config.excluded_paths.clone();
    excludes.extend(args.exclude.clone());

    let fail_on: Option<Severity> = match &args.fail_on {
        Some(s) => Some(parse_severity(s)?),
        None => match &config.severity_threshold {
            Some(s) => Some(parse_severity(s)?),
            None => None,
        },
    };

    // Scan.
    let mut opts = ScanOptions::new(&root);
    opts.excludes = excludes;
    opts.detector.entropy_threshold = entropy_threshold;
    opts.scan_history = scan_history;
    let findings = scan(&opts)?;

    // Optional IAM account for blast-radius analysis.
    let account: Option<Account> = match &args.iam_dir {
        Some(dir) => Some(load_account(dir)?),
        None => None,
    };

    let analyzed: Vec<AnalyzedFinding> = findings
        .iter()
        .map(|f| analyze_finding(f, account.as_ref()))
        .collect();

    let meta = Meta {
        root: root.display().to_string(),
        history: scan_history,
    };

    let color = !args.no_color && std::env::var_os("NO_COLOR").is_none();
    let rendered = match args.format {
        Format::Text => render_text(&analyzed, &meta, color),
        Format::Json => render_json(&analyzed, &meta),
    };
    // Write once, and treat a closed pipe (e.g. piping into `head`) as a normal
    // early exit rather than a panic.
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Err(e) = writeln!(lock, "{rendered}") {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(EXIT_OK);
        }
        return Err(e.into());
    }

    // Exit code.
    let max = analyzed.iter().map(|a| a.risk.severity).max();
    if let (Some(threshold), Some(m)) = (fail_on, max) {
        if m.meets(threshold) {
            return Ok(EXIT_THRESHOLD);
        }
    }
    Ok(EXIT_OK)
}

fn analyze_finding(finding: &Finding, account: Option<&Account>) -> AnalyzedFinding {
    let mut principal = None;
    let mut blast = None;
    let mut tree = None;

    if finding.kind.is_aws() {
        if let Some(acct) = account {
            if let Some(p) = acct.principal_for_fingerprint(&finding.fingerprint) {
                principal = Some(p.to_string());
                if let Some((b, t)) = analyze_with_tree(acct, p) {
                    blast = Some(b);
                    tree = Some(t);
                }
            }
        }
    }

    let mapped = principal.is_some();
    let risk = assess(mapped, blast.as_ref());

    AnalyzedFinding {
        finding: finding.clone(),
        principal,
        blast,
        tree,
        risk,
    }
}

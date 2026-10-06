//! SecretScope benchmark runner.
//!
//! Generates synthetic inputs of controlled sizes with a fixed seed, then times
//! the scanner (sequential vs parallel), IAM loading, and blast-radius
//! analysis. Run with `cargo run --release -p benchmarks`.

mod harness;

use harness::{measure, Rng, Stats};
use secretscope_graph::analyze;
use secretscope_iam::{
    load_account, Account, CredentialMapping, Effect, Policy, Resource, Role, Statement, User,
};
use secretscope_scanner::{scan, ScanOptions};
use std::fs;
use std::path::{Path, PathBuf};

fn tmp(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("secretscope-bench-{tag}"));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

/// Generate `count` files of roughly `lines` lines. Every 25th file gets a
/// planted AWS key so the scanner has real matches to redact and fingerprint.
fn generate_repo(dir: &Path, count: usize, lines: usize) -> u64 {
    let mut rng = Rng::new(0x5eed_1234);
    let mut bytes = 0u64;
    for i in 0..count {
        let mut content = String::new();
        for _ in 0..lines {
            let n = 6 + (rng.next_u64() as usize % 8);
            content.push_str(&format!("{} = {}\n", rng.word(5), rng.word(n)));
        }
        if i % 25 == 0 {
            content.push_str(&format!(
                "AWS_ACCESS_KEY_ID={}{}\n",
                "AKIA", "IOSFODNN7EXAMPLE"
            ));
        }
        let path = dir.join(format!("file_{i:05}.env"));
        bytes += content.len() as u64;
        fs::write(path, content).unwrap();
    }
    bytes
}

fn bench_scanner() {
    println!("## Scanner throughput (working tree)\n");
    println!(
        "{:<10} {:>8} {:>10} {:>12} {:>12} {:>12}",
        "dataset", "files", "size", "mode", "mean", "files/s"
    );
    for (tag, count, lines) in [
        ("small", 50usize, 40usize),
        ("medium", 200, 40),
        ("large", 1000, 40),
    ] {
        let dir = tmp(tag);
        let bytes = generate_repo(&dir, count, lines);

        for parallel in [false, true] {
            let mut opts = ScanOptions::new(&dir);
            opts.parallel = parallel;
            let stats: Stats = measure(tag, 1, 5, || {
                let found = scan(&opts).unwrap();
                std::hint::black_box(found);
            });
            let mode = if parallel { "parallel" } else { "sequential" };
            println!(
                "{:<10} {:>8} {:>9}K {:>12} {:>10.2}ms {:>12.0}",
                tag,
                count,
                bytes / 1024,
                mode,
                stats.mean.as_secs_f64() * 1000.0,
                stats.per_second(count as f64)
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
    println!();
}

fn bench_iam_load() {
    println!("## IAM fixture loading\n");
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("fixtures/aws/demo-account");
    let stats = measure("load demo-account", 5, 200, || {
        let acct = load_account(&dir).unwrap();
        std::hint::black_box(acct);
    });
    println!(
        "{:<24} mean {:>8.2}us   min {:>8.2}us   ~{:.0} loads/s\n",
        stats.label,
        stats.mean.as_secs_f64() * 1e6,
        stats.min.as_secs_f64() * 1e6,
        stats.per_second(1.0)
    );
}

/// Build a synthetic account with a chain of `depth` assumable roles, each with
/// one reachable bucket, to exercise graph build plus traversal.
fn chain_account(depth: usize) -> Account {
    let mut roles = Vec::new();
    let mut policies = Vec::new();
    let mut resources = Vec::new();

    let user = User {
        name: "start-user".to_string(),
        policies: vec!["p0".to_string()],
    };
    policies.push(Policy {
        name: "p0".to_string(),
        statements: vec![Statement {
            effect: Effect::Allow,
            actions: vec!["sts:AssumeRole".to_string()],
            resources: vec!["arn:aws:iam::123456789012:role/role-1".to_string()],
        }],
    });

    for i in 1..=depth {
        let arn = format!("arn:aws:iam::123456789012:role/role-{i}");
        let bucket = format!("arn:aws:s3:::bucket-{i}/*");
        let mut statements = vec![Statement {
            effect: Effect::Allow,
            actions: vec!["s3:GetObject".to_string()],
            resources: vec![bucket.clone()],
        }];
        if i < depth {
            statements.push(Statement {
                effect: Effect::Allow,
                actions: vec!["sts:AssumeRole".to_string()],
                resources: vec![format!("arn:aws:iam::123456789012:role/role-{}", i + 1)],
            });
        }
        policies.push(Policy {
            name: format!("p{i}"),
            statements,
        });
        roles.push(Role {
            name: format!("role-{i}"),
            arn,
            policies: vec![format!("p{i}")],
        });
        resources.push(Resource {
            arn: bucket,
            service: "s3".to_string(),
            environment: "production".to_string(),
            sensitive: true,
        });
    }

    Account {
        users: vec![user],
        roles,
        policies,
        resources,
        credentials: vec![CredentialMapping {
            fingerprint: "deadbeef".to_string(),
            principal: "start-user".to_string(),
        }],
    }
}

fn bench_graph() {
    println!("## Blast-radius analysis (role-assumption chain)\n");
    println!(
        "{:<10} {:>8} {:>12} {:>14}",
        "depth", "roles", "mean", "analyses/s"
    );
    for depth in [5usize, 20, 50] {
        let acct = chain_account(depth);
        let stats = measure("analyze", 5, 100, || {
            let radius = analyze(&acct, "start-user").unwrap();
            std::hint::black_box(radius);
        });
        println!(
            "{:<10} {:>8} {:>10.2}us {:>14.0}",
            depth,
            depth,
            stats.mean.as_secs_f64() * 1e6,
            stats.per_second(1.0)
        );
    }
    println!();
}

fn main() {
    println!("# SecretScope benchmark results\n");
    println!(
        "Build: {}   (numbers are wall-clock on the current machine)\n",
        if cfg!(debug_assertions) {
            "debug (run with --release for representative numbers)"
        } else {
            "release"
        }
    );
    bench_scanner();
    bench_iam_load();
    bench_graph();
}

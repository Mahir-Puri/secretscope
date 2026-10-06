//! A tiny, dependency-free timing harness.
//!
//! Criterion would be the usual choice, but its dependency tree pulls crates
//! that require a newer Rust edition than this project's 1.75 baseline. Rather
//! than raise the baseline for a benchmark, this module does the essential
//! parts by hand: run a closure many times, discard warmup, and report mean,
//! minimum, and sample standard deviation. Numbers are wall-clock and therefore
//! machine dependent; the README records the machine they were taken on.

use std::time::{Duration, Instant};

pub struct Stats {
    pub label: String,
    pub samples: usize,
    pub mean: Duration,
    pub min: Duration,
    pub stddev: Duration,
}

impl Stats {
    pub fn per_second(&self, items: f64) -> f64 {
        items / self.mean.as_secs_f64()
    }
}

/// Run `f` for `warmup` untimed iterations, then `samples` timed iterations.
pub fn measure<F: FnMut()>(label: &str, warmup: usize, samples: usize, mut f: F) -> Stats {
    for _ in 0..warmup {
        f();
    }
    let mut times: Vec<Duration> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f();
        times.push(start.elapsed());
    }

    let total: Duration = times.iter().sum();
    let mean = total / samples as u32;
    let min = *times.iter().min().unwrap();

    let mean_ns = mean.as_nanos() as f64;
    let var = times
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean_ns;
            diff * diff
        })
        .sum::<f64>()
        / samples as f64;
    let stddev = Duration::from_nanos(var.sqrt() as u64);

    Stats {
        label: label.to_string(),
        samples,
        mean,
        min,
        stddev,
    }
}

/// Deterministic xorshift64 generator so datasets are identical run to run.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn word(&mut self, len: usize) -> String {
        const CH: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| CH[(self.next_u64() as usize) % CH.len()] as char)
            .collect()
    }
}

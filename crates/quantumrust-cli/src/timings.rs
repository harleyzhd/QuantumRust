use std::time::Instant;

use serde_json::{json, Value};

#[derive(Clone, Copy)]
struct Usage {
    self_cpu_s: f64,
    children_cpu_s: f64,
    self_peak_mb: f64,
    children_peak_mb: f64,
}

fn usage() -> Usage {
    fn read(who: libc::c_int) -> libc::rusage {
        // SAFETY: `getrusage` only writes a `rusage` into the pointer it is
        // given, and a zeroed `rusage` is a valid start value.
        unsafe {
            let mut r: libc::rusage = std::mem::zeroed();
            libc::getrusage(who, &mut r);
            r
        }
    }
    let cpu = |r: &libc::rusage| {
        let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
        t(r.ru_utime) + t(r.ru_stime)
    };
    let mb = |r: &libc::rusage| {
        let raw = r.ru_maxrss as f64;
        if cfg!(target_os = "macos") {
            raw / (1024.0 * 1024.0)
        } else {
            raw / 1024.0
        }
    };
    let me = read(libc::RUSAGE_SELF);
    let kids = read(libc::RUSAGE_CHILDREN);
    Usage {
        self_cpu_s: cpu(&me),
        children_cpu_s: cpu(&kids),
        self_peak_mb: mb(&me),
        children_peak_mb: mb(&kids),
    }
}

pub struct Timings {
    start: Instant,
    last: Instant,
    last_usage: Usage,
    stages: Vec<Value>,
}

impl Timings {
    pub fn start() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last: now,
            last_usage: usage(),
            stages: Vec::new(),
        }
    }

    pub fn mark(&mut self, stage: &str) {
        let now = Instant::now();
        let u = usage();
        self.stages.push(json!({
            "stage": stage,
            "wall_s": (now - self.last).as_secs_f64(),
            "cpu_self_s": u.self_cpu_s - self.last_usage.self_cpu_s,
            "cpu_children_s": u.children_cpu_s - self.last_usage.children_cpu_s,
            "peak_self_mb": u.self_peak_mb,
            "peak_children_mb": u.children_peak_mb,
        }));
        self.last = now;
        self.last_usage = u;
    }

    pub fn to_json(&self) -> Value {
        let u = usage();
        json!({
            "stages": self.stages,
            "total_wall_s": (Instant::now() - self.start).as_secs_f64(),
            "peak_self_mb": u.self_peak_mb,
            "peak_children_mb": u.children_peak_mb,
            "note": "peak_* is the high-water mark reached by the end of each stage \
                     (getrusage ru_maxrss); children = the largest single waited-for \
                     child process, i.e. one rustc extraction driver",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_are_recorded_in_order_with_sane_values() {
        let mut t = Timings::start();
        let _ballast: Vec<u8> = vec![1; 4 << 20];
        t.mark("first");
        t.mark("second");
        let j = t.to_json();
        let stages = j["stages"].as_array().unwrap();
        assert_eq!(stages[0]["stage"], "first");
        assert_eq!(stages[1]["stage"], "second");
        assert!(stages[0]["wall_s"].as_f64().unwrap() >= 0.0);
        assert!(
            stages[1]["peak_self_mb"].as_f64().unwrap()
                >= stages[0]["peak_self_mb"].as_f64().unwrap()
        );
        assert!(j["peak_self_mb"].as_f64().unwrap() > 1.0, "{j}");
    }
}

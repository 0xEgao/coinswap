//! Hotpath helpers for interactive CLI binaries.
//!
//! The `hotpath` crate can emit timing/allocation reports, but by default those
//! are not necessarily printed in a human-friendly table format for `cargo run`
//! workflows. This module provides a guard that:
//! - ensures a JSON report is emitted to a file (unless the user configured output)
//! - renders a concise table to stdout at program exit
/// A CLI-oriented hotpath guard.
///
/// When compiled with the `hotpath` feature, constructing this guard starts
/// hotpath collection and, on drop, prints a small bench table to stdout.
///
/// When `hotpath` is not enabled, this is a no-op.
pub struct HotpathCliGuard {
    #[cfg(feature = "hotpath")]
    guard: Option<hotpath::HotpathGuard>,
    #[cfg(feature = "hotpath")]
    output_path: std::path::PathBuf,
    #[cfg(feature = "hotpath")]
    output_format_is_json: bool,
}

impl HotpathCliGuard {
    /// Start hotpath collection for a CLI binary.
    ///
    /// This will respect user-provided `HOTPATH_OUTPUT_FORMAT` and
    /// `HOTPATH_OUTPUT_PATH`. If `HOTPATH_OUTPUT_FORMAT` is not set, it defaults
    /// to `json-pretty` and writes to `./hotpath/<name>_<pid>.json`.
    pub fn start(name: &'static str) -> Self {
        #[cfg(feature = "hotpath")]
        {
            use std::{env, fs};

            let output_format_is_json = match env::var("HOTPATH_OUTPUT_FORMAT") {
                Ok(v) => v.starts_with("json"),
                Err(_) => {
                    env::set_var("HOTPATH_OUTPUT_FORMAT", "json-pretty");
                    true
                }
            };

            let output_path = match env::var_os("HOTPATH_OUTPUT_PATH") {
                Some(existing) => std::path::PathBuf::from(existing),
                None => {
                    let pid = std::process::id();
                    let base_dir = env::current_dir().unwrap_or_else(|_| env::temp_dir());
                    let out_dir = base_dir.join("hotpath");
                    let _ = fs::create_dir_all(&out_dir);
                    let out_path = out_dir.join(format!("{name}_{pid}.json"));
                    env::set_var("HOTPATH_OUTPUT_PATH", out_path.to_string_lossy().to_string());
                    out_path
                }
            };

            let guard = hotpath::HotpathGuardBuilder::new(name).build();
            Self {
                guard: Some(guard),
                output_path,
                output_format_is_json,
            }
        }

        #[cfg(not(feature = "hotpath"))]
        {
            let _ = name;
            Self {}
        }
    }
}

#[cfg(feature = "hotpath")]
fn print_hotpath_tables_from_json(report_path: &std::path::Path) {
    use std::{fs, thread, time::Duration};

    fn truncate(s: &str, max: usize) -> &str {
        if s.len() <= max {
            s
        } else {
            // Truncate at a UTF-8 boundary.
            let mut end = max;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            &s[..end]
        }
    }

    let mut json = String::new();
    let mut read_ok = false;
    for _ in 0..20 {
        match fs::read_to_string(report_path) {
            Ok(s) => {
                json = s;
                read_ok = true;
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(25)),
        }
    }
    if !read_ok {
        eprintln!("[hotpath] report not readable at {}", report_path.display());
        return;
    }

    let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
        eprintln!(
            "[hotpath] failed to parse JSON report at {}",
            report_path.display()
        );
        return;
    };

    fn print_section(v: &serde_json::Value, key: &str) {
        let Some(section) = v.get(key) else {
            return;
        };
        let elapsed = section
            .get("time_elapsed")
            .and_then(|x| x.as_str())
            .unwrap_or("?");

        let Some(rows) = section.get("data").and_then(|x| x.as_array()) else {
            return;
        };

        println!("\n[hotpath] {key} (elapsed {elapsed})");
        println!(
            "{:<80} {:>7} {:>12} {:>12} {:>12} {:>9}",
            "name", "calls", "total", "avg", "p95", "%total"
        );
        println!("{}", "-".repeat(80 + 7 + 12 + 12 + 12 + 9 + 5));

        for row in rows.iter().take(50) {
            let name = row.get("name").and_then(|x| x.as_str()).unwrap_or("?");
            let calls = row
                .get("calls")
                .and_then(|x| x.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_owned());
            let total = row.get("total").and_then(|x| x.as_str()).unwrap_or("?");
            let avg = row.get("avg").and_then(|x| x.as_str()).unwrap_or("?");
            let p95 = row.get("p95").and_then(|x| x.as_str()).unwrap_or("?");
            let pct = row
                .get("percent_total")
                .and_then(|x| x.as_str())
                .unwrap_or("?");

            println!(
                "{:<80} {:>7} {:>12} {:>12} {:>12} {:>9}",
                truncate(name, 80),
                calls,
                total,
                avg,
                p95,
                pct
            );
        }
    }

    print_section(&v, "functions_timing");
    print_section(&v, "functions_alloc");
}

impl Drop for HotpathCliGuard {
    fn drop(&mut self) {
        #[cfg(feature = "hotpath")]
        {
            // Ensure the report is emitted before we attempt to read it.
            let _ = self.guard.take();

            if !self.output_format_is_json {
                // User configured a non-JSON output format; we can't render tables.
                return;
            }
            print_hotpath_tables_from_json(&self.output_path);
        }
    }
}

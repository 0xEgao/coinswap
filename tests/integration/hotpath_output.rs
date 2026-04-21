#[cfg(feature = "hotpath")]
pub fn print_hotpath_tables_from_env() {
    use std::{env, fs, path::Path, thread, time::Duration};

    fn truncate(s: &str, max: usize) -> &str {
        if s.len() <= max {
            s
        } else {
            let mut end = max;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            &s[..end]
        }
    }

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

    let Some(path_os) = env::var_os("HOTPATH_OUTPUT_PATH") else {
        eprintln!("[hotpath] HOTPATH_OUTPUT_PATH not set; skipping table output");
        return;
    };
    let report_path = Path::new(&path_os);

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

    print_section(&v, "functions_timing");
    print_section(&v, "functions_alloc");
}

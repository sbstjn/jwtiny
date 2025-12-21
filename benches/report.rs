use std::fs;
use std::io::Write;
use std::path::Path;

const REPORTS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reports");

/// Initialize the reports directory
pub fn init_reports_dir() {
    fs::create_dir_all(REPORTS_DIR).expect("Failed to create reports directory");
}

/// Write benchmark results to a report file
pub fn write_report(filename: &str, header: &str, rows: &[String]) {
    init_reports_dir();
    let path = Path::new(REPORTS_DIR).join(filename);

    let mut file = fs::File::create(&path).unwrap_or_else(|_| {
        panic!("Failed to create report file: {}", path.display());
    });

    writeln!(file, "{}", header).expect("Failed to write header");
    for row in rows {
        writeln!(file, "{}", row).expect("Failed to write row");
    }
}

/// Calculate operations per second from nanoseconds per iteration
pub fn calculate_ops_per_sec(nanos_per_iter: f64) -> u64 {
    if nanos_per_iter > 0.0 {
        (1_000_000_000.0 / nanos_per_iter) as u64
    } else {
        0
    }
}

/// Create a CSV row from fields
pub fn create_row(fields: &[&str]) -> String {
    fields.join(", ")
}

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use std::sync::OnceLock;

/// A demonstration score in [0, 100], based on non-negative measured values.
#[pyfunction]
fn calculate_network_score(ping_ms: f64, jitter_ms: f64, loss_percent: f64) -> PyResult<f64> {
    if !ping_ms.is_finite()
        || !jitter_ms.is_finite()
        || !loss_percent.is_finite()
        || ping_ms < 0.0
        || jitter_ms < 0.0
        || !(0.0..=100.0).contains(&loss_percent)
    {
        return Err(PyValueError::new_err("expected finite, non-negative measurements and loss in [0, 100]"));
    }
    Ok((100.0 - ping_ms * 0.1 - jitter_ms * 0.2 - loss_percent * 2.0).clamp(0.0, 100.0))
}

/// Parse Windows ping response lines into latency samples in milliseconds.
#[pyfunction]
fn parse_ping_output(raw_text: &str) -> PyResult<Vec<f64>> {
    static TTL_RE: OnceLock<Regex> = OnceLock::new();
    static VALUE_RE: OnceLock<Regex> = OnceLock::new();
    static LEGACY_RE: OnceLock<Regex> = OnceLock::new();
    let ttl_re = TTL_RE.get_or_init(|| Regex::new(r"(?i)TTL\s*=").expect("valid TTL regex"));
    let value_re = VALUE_RE.get_or_init(|| Regex::new(r"([=<])\s*(\d+(?:[.,]\d+)?)").expect("valid value regex"));
    let legacy_re = LEGACY_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:time|время)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)")
            .expect("valid legacy regex")
    });
    let mut samples = Vec::new();
    for line in raw_text.lines() {
        let prefix = ttl_re.find(line).map_or("", |match_| &line[..match_.start()]);
        let mut last = value_re.captures_iter(prefix).last();
        if last.is_none() {
            last = legacy_re.captures_iter(line).last();
        }
        if let Some(capture) = last {
            let operator = capture.get(1).map(|value| value.as_str()).unwrap_or("=");
            let number = capture
                .get(2)
                .map(|value| value.as_str().replace(',', "."))
                .unwrap_or_default();
            if let Ok(value) = number.parse::<f64>() {
                samples.push(if operator == "<" { 0.5 } else { value });
            }
        }
    }
    Ok(samples)
}

/// Extract hop indices, bodies, and RTT samples from already split lines.
#[pyfunction]
fn parse_tracert_rows(lines: Vec<String>) -> Vec<(String, String, Vec<f64>)> {
    static HOP_RE: OnceLock<Regex> = OnceLock::new();
    static RTT_RE: OnceLock<Regex> = OnceLock::new();
    let hop_re = HOP_RE.get_or_init(|| Regex::new(r"^\s*([0-9]+)\s+(.+)$").expect("valid hop regex"));
    let rtt_re = RTT_RE.get_or_init(|| Regex::new(r"(?i)<?([0-9]+(?:[.,][0-9]+)?)\s*(?:ms|мс)").expect("valid RTT regex"));
    let mut rows = Vec::new();
    for line in lines {
        if let Some(hop) = hop_re.captures(&line) {
            let body = hop[2].to_owned();
            let samples = rtt_re.captures_iter(&body)
                .filter_map(|sample| sample[1].replace(',', ".").parse::<f64>().ok())
                .collect();
            rows.push((hop[1].to_owned(), body, samples));
        }
    }
    rows
}

#[pymodule]
fn netvision_rs(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(calculate_network_score, module)?)?;
    module.add_function(wrap_pyfunction!(parse_ping_output, module)?)?;
    module.add_function(wrap_pyfunction!(parse_tracert_rows, module)?)?;
    Ok(())
}

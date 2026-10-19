//! Exact npm version advisory lookup. Source code and target URLs never leave Slurp.
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    package: String,
    version: String,
}
fn valid(input: &Input) -> bool {
    [
        "jquery",
        "lodash",
        "angular",
        "bootstrap",
        "moment",
        "vue",
        "react",
        "react-dom",
        "handlebars",
        "underscore",
        "axios",
        "dompurify",
    ]
    .contains(&input.package.as_str())
        && input.version.len() <= 50
        && input.version.split('.').take(3).count() == 3
        && input.version.split('.').all(|part| {
            !part.is_empty() && part.len() <= 10 && part.bytes().all(|c| c.is_ascii_digit())
        })
        && input.version.split('.').count() == 3
}
fn summarize(value: &Value) -> Vec<Value> {
    value["vulns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v.get("withdrawn").is_none())
        .take(50)
        .filter_map(|v| {
            let id = v["id"].as_str()?.chars().take(100).collect::<String>();
            let summary = v["summary"]
                .as_str()
                .unwrap_or("Vulnerable dependency advisory")
                .chars()
                .take(1000)
                .collect::<String>();
            let aliases: Vec<_> = v["aliases"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .take(10)
                .map(|s| s.chars().take(100).collect::<String>())
                .collect();
            Some(json!({"id":id,"summary":summary,"aliases":aliases}))
        })
        .collect()
}
async fn query(input: &Input) -> Result<Value, String> {
    let url = reqwest::Url::parse("https://api.osv.dev/v1/query").unwrap();
    let client = crate::http_target::client(&url, 10000).await?;
    let mut response = client
        .post(url)
        .json(&json!({"package":{"ecosystem":"npm","name":input.package},"version":input.version}))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("OSV returned {}", response.status()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 2_000_000 {
            return Err("OSV response exceeds 2 MB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let parsed: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok(
        json!({"ok":true,"package":input.package,"version":input.version,"advisories":summarize(&parsed)}),
    )
}
pub(crate) async fn lookup(Json(input): Json<Input>) -> Json<Value> {
    if !valid(&input) {
        return Json(
            json!({"ok":false,"error":"Expected a supported npm package and exact stable x.y.z version"}),
        );
    }
    type Cache = Mutex<HashMap<String, (Instant, Value)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    static SLOTS: OnceLock<Semaphore> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = format!("{}@{}", input.package, input.version);
    if let Some((_, value)) = cache
        .lock()
        .unwrap()
        .get(&key)
        .filter(|(at, _)| at.elapsed() < Duration::from_secs(3600))
    {
        return Json(value.clone());
    }
    let Ok(_permit) = SLOTS.get_or_init(|| Semaphore::new(4)).try_acquire() else {
        return Json(json!({"ok":false,"error":"Dependency lookup capacity reached"}));
    };
    let value = match tokio::time::timeout(Duration::from_secs(12), query(&input)).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return Json(json!({"ok":false,"error":error})),
        Err(_) => return Json(json!({"ok":false,"error":"OSV lookup timed out"})),
    };
    let mut saved = cache.lock().unwrap();
    saved.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(3600));
    if saved.len() >= 256 {
        saved.clear();
    }
    saved.insert(key, (Instant::now(), value.clone()));
    Json(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_packages_ranges_and_code() {
        for (package, version) in [("jquery", "3.4.1"), ("lodash", "4.17.20")] {
            assert!(valid(&Input {
                package: package.into(),
                version: version.into()
            }));
        }
        for (package, version) in [
            ("https://evil.test", "1.2.3"),
            ("jquery", "^3.4.1"),
            ("jquery", "1.2.3<script>"),
            ("jquery", "1.2.3.4"),
        ] {
            assert!(!valid(&Input {
                package: package.into(),
                version: version.into()
            }));
        }
    }
    #[test]
    fn summarizes_only_nonwithdrawn_advisories_without_full_details() {
        let result = summarize(
            &json!({"vulns":[{"id":"GHSA-example","summary":"Example","aliases":["CVE-2026-1234"],"details":"long"},{"id":"withdrawn","withdrawn":"2026-01-01"}]}),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["id"], "GHSA-example");
        assert!(result[0].get("details").is_none());
    }
}

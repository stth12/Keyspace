#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
mod clock;
mod protocol;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
use tokio::sync::Mutex;
#[derive(serde::Deserialize)]
struct Config {
    api_url: String,
    issuer: String,
    product_id: String,
    root_public_key: String,
}
struct ClientState {
    config: Config,
    http: reqwest::Client,
    gate: Mutex<()>,
    clock: clock::Clock,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .unwrap_or(0)
}
fn credential_service() -> String {
    let c: Config =
        serde_json::from_str(include_str!("../client-config.json")).expect("public config");
    format!("dev.onlinekeygen.desktop:{}:{}", c.issuer, c.product_id)
}
fn entry(name: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(&credential_service(), name).map_err(|_| "STORAGE_ERROR".into())
}
fn read(name: &str) -> Result<String, String> {
    entry(name)?
        .get_password()
        .map_err(|_| "INVALID_SESSION".into())
}
fn write(name: &str, value: &str) -> Result<(), String> {
    entry(name)?
        .set_password(value)
        .map_err(|_| "STORAGE_ERROR".into())
}
fn remove(name: &str) {
    if let Ok(e) = entry(name) {
        let _ = e.delete_credential();
    }
}
fn device() -> Result<String, String> {
    if let Ok(d) = read("device") {
        uuid::Uuid::parse_str(&d).map_err(|_| "STORAGE_ERROR")?;
        return Ok(d);
    }
    let d = uuid::Uuid::new_v4().to_string();
    write("device", &d)?;
    Ok(d)
}
async fn request(
    s: &ClientState,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> Result<Value, String> {
    let url = format!("{}/api/v1{}", s.config.api_url, path);
    let mut r = if let Some(b) = body {
        s.http.post(url).json(&b)
    } else {
        s.http.get(url)
    };
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    let mut response = r.send().await.map_err(|_| "NETWORK_ERROR")?;
    let status = response.status();
    if response.content_length().is_some_and(|n| n > 65536) {
        return Err("INVALID_RESPONSE".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "NETWORK_ERROR")? {
        if bytes.len() + chunk.len() > 65536 {
            return Err("INVALID_RESPONSE".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if status.as_u16() == 204 {
        return Ok(json!({}));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "INVALID_RESPONSE")?;
    if !status.is_success() {
        if status.as_u16() == 503 {
            return Err("NETWORK_ERROR".into());
        }
        return Err(value["error"]["code"]
            .as_str()
            .unwrap_or("INVALID_RESPONSE")
            .to_string());
    }
    Ok(value)
}
fn scope(s: &ClientState, d: &str) -> Value {
    json!({"product_id":s.config.product_id,"device_id":d})
}
fn save_tokens(value: &Value) -> Result<(), String> {
    write(
        "access",
        value["session"]["token"]
            .as_str()
            .ok_or("INVALID_RESPONSE")?,
    )?;
    write(
        "refresh",
        value["refresh"]["token"]
            .as_str()
            .ok_or("INVALID_RESPONSE")?,
    )?;
    write("anchor", &now().to_string())
}
async fn cache_proof(s: &ClientState, d: &str, access: &str) -> Result<(), String> {
    let proof = request(
        s,
        "/licenses/offline-token",
        Some(scope(s, d)),
        Some(access),
    )
    .await?;
    let manifest = request(s, "/signing-keys/manifest", None, None).await?;
    let minimum = read("manifest_version")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let payload = protocol::manifest(
        &manifest,
        &s.config.root_public_key,
        &s.config.issuer,
        now(),
        minimum,
    )?;
    let raw = proof["token"].as_str().ok_or("INVALID_RESPONSE")?;
    protocol::offline(
        raw,
        &payload["keys"],
        &s.config.issuer,
        &s.config.product_id,
        d,
        now(),
    )?;
    write("offline", raw)?;
    write("manifest", &manifest.to_string())?;
    write("manifest_version", &payload["version"].to_string())?;
    write("anchor", &now().to_string())
}
fn offline(s: &ClientState, d: &str) -> Result<Value, String> {
    let last = read("anchor")?
        .parse::<u64>()
        .map_err(|_| "OFFLINE_EXPIRED")?;
    let current = s.clock.effective(now(), last)?;
    let m: Value = serde_json::from_str(&read("manifest")?).map_err(|_| "INVALID_SIGNATURE")?;
    let minimum = read("manifest_version")?
        .parse::<u64>()
        .map_err(|_| "INVALID_SIGNATURE")?;
    let p = protocol::manifest(
        &m,
        &s.config.root_public_key,
        &s.config.issuer,
        current,
        minimum,
    )?;
    let result = protocol::offline(
        &read("offline")?,
        &p["keys"],
        &s.config.issuer,
        &s.config.product_id,
        d,
        current,
    )?;
    write("anchor", &current.to_string())?;
    let mut value = serde_json::to_value(result).map_err(|_| "INVALID_SIGNATURE")?;
    value["offline"] = json!(true);
    Ok(value)
}
#[tauri::command]
async fn login(s: State<'_, ClientState>, license_key: String) -> Result<Value, String> {
    let _lock = s.gate.lock().await;
    let d = device()?;
    let response = request(
        &s,
        "/licenses/activate",
        Some(json!({"license_key":license_key,"product_id":s.config.product_id,"device_id":d})),
        None,
    )
    .await?;
    remove("offline");
    save_tokens(&response)?;
    if let Ok(access) = read("access") {
        if let Err(e) = cache_proof(&s, &d, &access).await {
            if e != "NETWORK_ERROR" {
                remove("offline");
            }
        }
    }
    let mut view = response;
    view.as_object_mut()
        .ok_or("INVALID_RESPONSE")?
        .remove("session");
    view.as_object_mut().unwrap().remove("refresh");
    Ok(view)
}
#[tauri::command]
async fn resume(s: State<'_, ClientState>) -> Result<Value, String> {
    let _lock = s.gate.lock().await;
    let d = device()?;
    let access = read("access")?;
    match request(&s, "/licenses/validate", Some(scope(&s, &d)), Some(&access)).await {
        Ok(v) => Ok(v),
        Err(e) if e == "NETWORK_ERROR" => offline(&s, &d),
        Err(e) if e == "INVALID_SESSION" || e == "SESSION_EXPIRED" => {
            let refresh = read("refresh")?;
            let result = request(
                &s,
                "/application-sessions/refresh",
                Some(
                    json!({"refresh_token":refresh,"product_id":s.config.product_id,"device_id":d}),
                ),
                None,
            )
            .await;
            match result {
                Ok(v) => {
                    save_tokens(&v)?;
                    let token = read("access")?;
                    let view =
                        match request(&s, "/licenses/validate", Some(scope(&s, &d)), Some(&token))
                            .await
                        {
                            Ok(v) => v,
                            Err(e) if e == "NETWORK_ERROR" => return offline(&s, &d),
                            Err(e) => {
                                remove("offline");
                                return Err(e);
                            }
                        };
                    if let Err(e) = cache_proof(&s, &d, &token).await {
                        if e != "NETWORK_ERROR" && e != "RATE_LIMITED" {
                            remove("offline");
                        }
                    }
                    Ok(view)
                }
                Err(e) if e == "NETWORK_ERROR" => offline(&s, &d),
                Err(e) => {
                    remove("offline");
                    remove("refresh");
                    remove("access");
                    Err(e)
                }
            }
        }
        Err(e) => {
            remove("offline");
            Err(e)
        }
    }
}
#[tauri::command]
async fn logout(s: State<'_, ClientState>) -> Result<(), String> {
    let _lock = s.gate.lock().await;
    if let (Ok(d), Ok(t)) = (device(), read("access")) {
        let _ = request(
            &s,
            "/application-sessions/logout",
            Some(scope(&s, &d)),
            Some(&t),
        )
        .await;
    }
    for name in ["access", "refresh", "offline"] {
        remove(name);
    }
    Ok(())
}
fn main() {
    let config: Config = serde_json::from_str(include_str!("../client-config.json"))
        .expect("Invalid public client configuration");
    if !cfg!(debug_assertions) && !config.api_url.starts_with("https://") {
        panic!("Release requires HTTPS client configuration");
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client");
    tauri::Builder::default()
        .manage(ClientState {
            config,
            http,
            gate: Mutex::new(()),
            clock: clock::Clock::new(now()),
        })
        .invoke_handler(tauri::generate_handler![login, resume, logout])
        .run(tauri::generate_context!())
        .expect("Application runtime failed");
}

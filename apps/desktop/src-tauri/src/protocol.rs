use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    #[serde(rename = "type")]
    kind: String,
    signature_algorithm: String,
    encryption_algorithm: String,
    key_id: String,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Offline {
    pub version: u32,
    pub issuer: String,
    pub audience: String,
    pub license_id: String,
    pub user_id: String,
    pub product_id: String,
    pub device_id: String,
    pub issued_at: u64,
    pub valid_until: u64,
    pub license_expires_at: Option<u64>,
    pub lifetime: bool,
    pub license_version: u64,
    pub nonce: String,
}
fn canonical(v: &Value) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(v).map_err(|_| "INVALID_SIGNATURE".into())
}
fn verify_bytes(public: &str, data: &[u8], signature: &str) -> Result<(), String> {
    let k = VerifyingKey::from_public_key_pem(public).map_err(|_| "INVALID_SIGNATURE")?;
    let s = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "INVALID_SIGNATURE")?;
    let sig = Signature::from_slice(&s).map_err(|_| "INVALID_SIGNATURE")?;
    k.verify_strict(data, &sig)
        .map_err(|_| "INVALID_SIGNATURE".into())
}
pub fn manifest(
    value: &Value,
    root: &str,
    issuer: &str,
    now: u64,
    minimum: u64,
) -> Result<Value, String> {
    let p = &value["payload"];
    if p["issuer"] != issuer
        || p["version"].as_u64().unwrap_or(0) < minimum
        || p["expires_at"].as_u64().unwrap_or(0) <= now
        || p["issued_at"].as_u64().unwrap_or(u64::MAX) > now + 30
    {
        return Err("INVALID_SIGNATURE".into());
    }
    verify_bytes(
        root,
        &canonical(p)?,
        value["signature"].as_str().ok_or("INVALID_SIGNATURE")?,
    )?;
    Ok(p.clone())
}
pub fn offline(
    token: &str,
    keys: &Value,
    issuer: &str,
    product: &str,
    device: &str,
    now: u64,
) -> Result<Offline, String> {
    if token.len() > 8192 {
        return Err("INVALID_SIGNATURE".into());
    }
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 4 || segments[0] != "LP1" {
        return Err("INVALID_SIGNATURE".into());
    }
    let decode = |s: &str, max: usize| -> Result<Vec<u8>, String> {
        let b = URL_SAFE_NO_PAD.decode(s).map_err(|_| "INVALID_SIGNATURE")?;
        if b.len() > max || URL_SAFE_NO_PAD.encode(&b) != s {
            return Err("INVALID_SIGNATURE".into());
        }
        Ok(b)
    };
    let hbytes = decode(segments[1], 512)?;
    let hvalue: Value = serde_json::from_slice(&hbytes).map_err(|_| "INVALID_SIGNATURE")?;
    if canonical(&hvalue)? != hbytes {
        return Err("INVALID_SIGNATURE".into());
    }
    let h: Header = serde_json::from_value(hvalue).map_err(|_| "INVALID_SIGNATURE")?;
    if h.version != 1
        || h.kind != "offline-license"
        || h.signature_algorithm != "Ed25519"
        || h.encryption_algorithm != "none"
    {
        return Err("INVALID_SIGNATURE".into());
    }
    let key = keys
        .as_array()
        .ok_or("INVALID_SIGNATURE")?
        .iter()
        .find(|k| {
            k["id"] == h.key_id && k["purpose"] == "offline-license" && k["status"] != "REVOKED"
        })
        .ok_or("INVALID_SIGNATURE")?;
    verify_bytes(
        key["publicKey"].as_str().ok_or("INVALID_SIGNATURE")?,
        segments[..3].join(".").as_bytes(),
        segments[3],
    )?;
    let bytes = decode(segments[2], 4096)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "INVALID_SIGNATURE")?;
    if canonical(&value)? != bytes {
        return Err("INVALID_SIGNATURE".into());
    }
    let p: Offline = serde_json::from_value(value).map_err(|_| "INVALID_SIGNATURE")?;
    if p.version != 1
        || p.issuer != issuer
        || p.audience != "offline-license"
        || p.product_id != product
        || p.device_id != device
        || p.issued_at > now + 30
        || p.valid_until <= now
        || p.valid_until <= p.issued_at
        || p.valid_until - p.issued_at > 604800
        || p.issued_at < key["notBefore"].as_u64().unwrap_or(u64::MAX)
        || p.valid_until > key["verifyUntil"].as_u64().unwrap_or(0)
        || p.license_version == 0
        || p.lifetime != p.license_expires_at.is_none()
        || p.license_expires_at.is_some_and(|e| p.valid_until > e)
    {
        return Err("OFFLINE_EXPIRED".into());
    }
    for id in [&p.license_id, &p.user_id, &p.product_id, &p.device_id] {
        uuid::Uuid::parse_str(id).map_err(|_| "INVALID_SIGNATURE")?;
    }
    if decode(&p.nonce, 16)?.len() != 16 {
        return Err("INVALID_SIGNATURE".into());
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../../packages/lp1-spec/vectors/offline.json"
        ))
        .unwrap()
    }
    #[test]
    fn accepts_node_generated_signature() {
        let f = fixture();
        let now = f["now"].as_u64().unwrap();
        let p = manifest(
            &f["manifest"],
            f["root_public_key"].as_str().unwrap(),
            f["issuer"].as_str().unwrap(),
            now,
            1,
        )
        .unwrap();
        let proof = offline(
            f["token"].as_str().unwrap(),
            &p["keys"],
            f["issuer"].as_str().unwrap(),
            f["product_id"].as_str().unwrap(),
            f["device_id"].as_str().unwrap(),
            now,
        )
        .unwrap();
        assert!(proof.lifetime);
    }
    #[test]
    fn rejects_tamper_and_expiration() {
        let f = fixture();
        let token = f["token"].as_str().unwrap();
        let keys = &f["manifest"]["payload"]["keys"];
        let issuer = f["issuer"].as_str().unwrap();
        let product = f["product_id"].as_str().unwrap();
        let device = f["device_id"].as_str().unwrap();
        assert!(offline(token, keys, issuer, product, device, 2000086400).is_err());
        assert!(offline(token, keys, issuer, "other", device, 2000000001).is_err());
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        parts[3] = URL_SAFE_NO_PAD.encode([0u8; 64]);
        assert!(offline(&parts.join("."), keys, issuer, product, device, 2000000001).is_err());
    }
    #[test]
    fn rejects_manifest_rollback() {
        let f = fixture();
        assert!(manifest(
            &f["manifest"],
            f["root_public_key"].as_str().unwrap(),
            f["issuer"].as_str().unwrap(),
            2000000001,
            2
        )
        .is_err());
    }
}

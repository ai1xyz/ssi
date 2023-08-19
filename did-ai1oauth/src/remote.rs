use std::env;

use reqwest::StatusCode;

const DEFAULT_DID_RESOLUTION_URI: &str = "https://3wbyu4xc5l.execute-api.us-east-1.amazonaws.com/did/";

pub(crate) async fn get_public_key(did: &str) -> Option<Vec<u8>> {
    let url = format!("{}public_key?did={}", get_uri(), did);
    let client = reqwest::Client::new();

    let response = client
        .get(url)
        .send()
        .await;

    let response = if let Ok(resp) = response { resp } else { return None; };

    if response.status() != StatusCode::OK { return None }

    if let Some(pubkey_str) = response.text().await.ok() {
        let result_opt = multibase::decode(pubkey_str).ok();
        if let Some((_base, key)) = result_opt { Some(key) } else { None }
    } else { None }
}

pub(crate) fn get_uri() -> String {
    let did_resolver_uri = env::var("SCRAIOAUTH_DID_RESOLUTION_URI")
        .unwrap_or(DEFAULT_DID_RESOLUTION_URI.to_string());

    if did_resolver_uri.ends_with('/') { did_resolver_uri } else {
        format!("{did_resolver_uri}/")
    }
}
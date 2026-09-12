//! End-to-end OAuth spike against a real PDS, using the localhost dev client.
//!
//! Deliberately an EXAMPLE, not wired into the app: it answers "does a real
//! authorization server accept what we build?" without touching `web.rs`,
//! `config.rs` or the live login path. It drives the same modules the real
//! implementation will.
//!
//! Run:
//!   cargo run --example oauth_spike -- <handle-or-did> [pds-url]
//!
//! It prints an authorization URL, waits on `127.0.0.1:8080` for the callback,
//! completes the exchange, and reports what came back. **No token is ever
//! printed** — only its shape.

use anyhow::{bail, Context, Result};
use feather_reader::oauth::{
    client_auth::{self, AuthMethod},
    crypto::Codec,
    discovery, dpop, fetch, flow,
    keys::SigningKey,
    metadata::{self, ClientConfig},
    request::{self, Retry},
    resolve, store, token,
};
use reqwest::Client;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

/// Where the browser is sent back to. Must be a loopback URL for the dev client.
const REDIRECT_PORT: u16 = 8080;
const SCOPE: &str = "atproto transition:generic";

/// Show that a secret exists without disclosing it.
fn shape(secret: &str) -> String {
    format!("<{} chars, sha256 {}…>", secret.len(), {
        let d = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());
        hex_prefix(d.as_ref())
    })
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Flags are filtered out first, so `--write-test` cannot be mistaken for the
    // optional PDS override.
    let mut args = std::env::args().skip(1).filter(|a| !a.starts_with("--"));
    let subject = args
        .next()
        .context("usage: oauth_spike <handle-or-did> [pds] [--write-test]")?;
    let pds_override = args.next();

    let http = Client::new();
    let pool = feather_reader::store::init_url("sqlite::memory:").await?;
    store::init_schema(&pool).await?;
    let codec = Codec::new(Some("spike-only-passphrase-not-a-real-key"))?;

    // ── 1. identity ──────────────────────────────────────────────────────────
    println!("\n=== 1. identity ===");
    let (did, pds_url) = match pds_override {
        Some(pds) => {
            println!("  pds        {pds} (supplied)");
            (subject.clone(), pds)
        }
        None => resolve_identity(&http, &subject).await?,
    };
    println!("  did        {did}");

    // ── 2. discovery ─────────────────────────────────────────────────────────
    println!("\n=== 2. discovery ===");
    let prm_url = format!(
        "{}/.well-known/oauth-protected-resource",
        discovery::origin_of(&pds_url)?
    );
    let prm = fetch::get_json(&http, &prm_url, fetch::JSON).await?;
    let issuer = discovery::validate_protected_resource(&prm, &pds_url)?;
    println!("  issuer     {issuer}");

    let asm_url = format!("{issuer}/.well-known/oauth-authorization-server");
    let asm = fetch::get_json(&http, &asm_url, fetch::JSON).await?;

    // Dev client => `none`. The AS must actually support it.
    let auth_method = AuthMethod::negotiate(true);
    let server =
        discovery::validate_authorization_server(&asm, &issuer, &pds_url, auth_method.as_str())?;
    println!("  auth       {}", auth_method.as_str());
    println!("  par        {}", server.par_endpoint);
    println!("  token      {}", server.token_endpoint);

    // ── 3. client identity + session key ─────────────────────────────────────
    println!("\n=== 3. client + session key ===");
    let client_cfg = ClientConfig::new(&format!("http://127.0.0.1:{REDIRECT_PORT}"), SCOPE, true)?;
    let client_id = metadata::client_id(&client_cfg);
    let redirect_uri = metadata::redirect_uri(&client_cfg);
    println!("  client_id  {client_id}");
    println!("  redirect   {redirect_uri}");

    // Generated BEFORE PAR and used for every request thereafter: the AS binds
    // the request_uri to this key's thumbprint.
    let session_key = SigningKey::generate("spike-session-dpop");
    println!("  dpop jkt   {}", session_key.thumbprint()?);

    // ── 4. PAR ───────────────────────────────────────────────────────────────
    println!("\n=== 4. pushed authorization request ===");
    let verifier = flow::new_pkce_verifier();
    let state = flow::new_state();
    let binding_token = flow::new_binding_token();

    let par_request = flow::ParRequest {
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        scope: SCOPE,
        state: &state,
        code_challenge: &flow::pkce_challenge(&verifier),
        login_hint: Some(&subject),
    };
    let mut params = flow::par_params(&par_request);
    params.extend(client_auth::credential_params(
        auth_method,
        &client_id,
        None,
    )?);
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let outcome = request::send_with_dpop(
        &http,
        &pool,
        &request::DpopRequest {
            endpoint: dpop::Endpoint::AuthorizationServer,
            url: &server.par_endpoint,
            key: &session_key,
            access_token: None,
            body: request::DpopBody::Form(&borrowed),
            // PAR is safe to repeat: nothing is consumed by a rejected attempt.
            retry: Retry::Allowed,
        },
    )
    .await?;
    println!("  status     {}", outcome.status);
    if !outcome.is_success() {
        bail!(
            "PAR failed: {}",
            String::from_utf8_lossy(&outcome.body)
                .chars()
                .take(400)
                .collect::<String>()
        );
    }
    let par = flow::parse_par_response(&outcome.json()?)?;
    println!(
        "  request_uri {} (expires in {}s)",
        par.request_uri, par.expires_in
    );

    // Persist the pending login exactly as the real flow would.
    store::put_pending(
        &pool,
        &codec,
        &store::PendingAuth {
            state: state.clone(),
            browser_binding_hash: flow::binding_hash(&binding_token),
            pkce_verifier: verifier.clone(),
            dpop_key_jwk: session_key.to_jwk_json()?,
            issuer: issuer.clone(),
            pds_url: pds_url.clone(),
            did: did.clone(),
            auth_method: auth_method.as_str().to_string(),
            auth_kid: None,
            redirect_uri: redirect_uri.clone(),
            requested_scope: SCOPE.to_string(),
            request_uri: par.request_uri.clone(),
            app_return_to: None,
            expires_at: chrono::Utc::now().timestamp() + par.expires_in.min(600),
        },
    )
    .await?;

    // ── 5. authorize ─────────────────────────────────────────────────────────
    let authorize =
        flow::authorize_url(&server.authorization_endpoint, &client_id, &par.request_uri)?;
    println!("\n=== 5. authorize ===");
    println!("\n  Open this in a browser and approve:\n\n  {authorize}\n");
    println!("  Listening on 127.0.0.1:{REDIRECT_PORT} for the callback…");

    let query = wait_for_callback(REDIRECT_PORT)?;

    // ── 6. callback ──────────────────────────────────────────────────────────
    println!("\n=== 6. callback ===");
    let params = parse_query(&query);
    let callback = flow::CallbackParams {
        code: params.get("code").cloned(),
        state: params.get("state").cloned(),
        iss: params.get("iss").cloned(),
        error: params.get("error").cloned(),
        error_description: params.get("error_description").cloned(),
        response: params.get("response").cloned(),
    };
    println!("  iss        {:?}", callback.iss);
    println!(
        "  code       {}",
        callback.code.as_deref().map_or("<none>".into(), shape)
    );

    let (pending, code) = flow::complete_callback(
        &pool,
        &codec,
        &callback,
        Some(&binding_token),
        chrono::Utc::now().timestamp(),
    )
    .await?;
    println!("  binding    OK (state consumed, cookie matched)");

    // ── 7. token exchange ────────────────────────────────────────────────────
    println!("\n=== 7. token exchange ===");
    let key = SigningKey::from_jwk_json(&pending.dpop_key_jwk, "spike-session-dpop")?;
    let mut params =
        token::token_request_params(&code, &pending.redirect_uri, &pending.pkce_verifier);
    params.extend(client_auth::credential_params(
        auth_method,
        &client_id,
        None,
    )?);
    let borrowed: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let outcome = request::send_with_dpop(
        &http,
        &pool,
        &request::DpopRequest {
            endpoint: dpop::Endpoint::AuthorizationServer,
            url: &server.token_endpoint,
            key: &key,
            access_token: None,
            body: request::DpopBody::Form(&borrowed),
            // A nonce challenge is rejected BEFORE the grant is processed, so
            // the code is not consumed and the request is safe to resend. The
            // nonce harvested at PAR is routinely stale by now: approval can
            // take minutes and a server nonce lasts at most five.
            retry: Retry::Allowed,
        },
    )
    .await?;
    println!("  status     {}", outcome.status);
    if !outcome.is_success() {
        bail!(
            "token exchange failed: {}",
            String::from_utf8_lossy(&outcome.body)
                .chars()
                .take(400)
                .collect::<String>()
        );
    }

    let tokens = token::parse_token_response(&outcome.json()?)?;
    println!("\n=== 8. result ===");
    println!("  sub        {}", tokens.sub);
    println!("  token_type {}", tokens.token_type);
    println!("  scope      {}", tokens.granted_scope);
    println!("  expires_in {:?}", tokens.expires_in);
    println!("  access     {}", shape(&tokens.access_token));
    println!(
        "  refresh    {}",
        tokens
            .refresh_token
            .as_deref()
            .map_or("<none>".into(), shape)
    );
    println!("  sub == resolved did: {}", tokens.sub == pending.did);

    // ── 9. a real repo read, through the DPoP-bound XRPC layer ───────────────
    println!("\n=== 9. authenticated repo read ===");
    let session = store::OAuthSession {
        sub: tokens.sub.clone(),
        issuer: pending.issuer.clone(),
        aud: pending.pds_url.clone(),
        dpop_key_jwk: pending.dpop_key_jwk.clone(),
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone().unwrap_or_default(),
        token_type: tokens.token_type.clone(),
        granted_scope: tokens.granted_scope.clone(),
        expires_at: tokens
            .expires_in
            .map(|s| chrono::Utc::now().timestamp() + s),
    };
    store::put_session(&pool, &codec, &session).await?;
    println!("  session    stored and read back AAD-bound");
    let stored = store::get_session(&pool, &codec, &tokens.sub)
        .await?
        .context("session did not round-trip")?;

    let repo = feather_reader::oauth::xrpc::Repo {
        http: &http,
        pool: &pool,
        session: &stored,
        key: &key,
    };
    for collection in [
        feather_reader::lexicon::nsid::SUBSCRIPTION,
        feather_reader::lexicon::nsid::FOLDER,
        feather_reader::lexicon::nsid::SAVED,
    ] {
        match repo.list_records(collection, Some(5), None).await {
            Ok((records, cursor)) => println!(
                "  {collection}: {} record(s), cursor {}",
                records.len(),
                cursor.as_deref().unwrap_or("<none>")
            ),
            Err(err) => println!("  {collection}: FAILED -- {err:#}"),
        }
    }

    if std::env::args().any(|a| a == "--write-test") {
        write_test(&repo).await?;
    } else {
        println!("\n  (writes not exercised; pass --write-test to include them)");
    }

    println!("\nEnd to end OK.\n");
    Ok(())
}

/// Exercise every write operation against a REAL repo, then clean up.
///
/// Uses a collection the reader never reads, so a failure part-way cannot leave
/// anything visible in the UI — and deletes what it creates on every exit path,
/// including the failing ones.
async fn write_test(repo: &feather_reader::oauth::xrpc::Repo<'_>) -> Result<()> {
    const COLLECTION: &str = "com.feather.spikeTest";
    println!("\n=== 10. write path ({COLLECTION}) ===");

    let mut created: Vec<String> = Vec::new();
    let outcome = run_writes(repo, COLLECTION, &mut created).await;

    // Clean up whatever exists, whether the run above succeeded or not.
    for rkey in &created {
        match repo.delete_record(COLLECTION, rkey).await {
            Ok(()) => println!("  cleanup    deleted {rkey}"),
            Err(err) => println!("  cleanup    FAILED to delete {rkey}: {err:#}"),
        }
    }
    let (left, _) = repo.list_records(COLLECTION, Some(10), None).await?;
    println!(
        "  remaining  {} record(s) in the test collection",
        left.len()
    );
    outcome
}

async fn run_writes(
    repo: &feather_reader::oauth::xrpc::Repo<'_>,
    collection: &str,
    created: &mut Vec<String>,
) -> Result<()> {
    use feather_reader::atproto::WriteOp;
    use serde_json::json;

    let record = json!({
        "$type": collection,
        "note": "feather-reader OAuth spike; safe to delete",
        "createdAt": chrono::Utc::now().to_rfc3339(),
    });

    let written = repo.create_record(collection, &record).await?;
    let rkey = written
        .rkey()
        .context("createRecord returned no usable rkey")?
        .to_string();
    created.push(rkey.clone());
    println!("  create     OK -> {rkey}");

    let (records, _) = repo.list_records(collection, Some(10), None).await?;
    println!("  list       {} record(s) after create", records.len());

    let updated = json!({
        "$type": collection,
        "note": "feather-reader OAuth spike; updated",
        "createdAt": chrono::Utc::now().to_rfc3339(),
    });
    repo.put_record(collection, &rkey, &updated).await?;
    println!("  put        OK (same rkey)");

    // applyWrites: a batch create, to prove the batch body is accepted.
    let batch_rkey = format!("spike{}", chrono::Utc::now().timestamp());
    repo.apply_writes(&[WriteOp::Create {
        collection: collection.to_string(),
        rkey: Some(batch_rkey.clone()),
        value: record.clone(),
    }])
    .await?;
    created.push(batch_rkey.clone());
    println!("  applyWrites OK -> {batch_rkey}");

    let (records, _) = repo.list_records(collection, Some(10), None).await?;
    println!("  list       {} record(s) after batch", records.len());
    Ok(())
}

/// handle/DID -> DID -> document -> PDS, through the PRODUCTION resolver.
///
/// Was hand-rolled here and shelled out to `dig`; that stopgap hid the
/// multi-string TXT chunk case entirely, since `dig` joins chunks itself.
async fn resolve_identity(http: &Client, subject: &str) -> Result<(String, String)> {
    let dns = resolve::resolver()?;
    let account = resolve::resolve(&dns, http, subject, "https://plc.directory").await?;
    match &account.handle {
        Some(handle) => println!("  handle     {handle} (verified bidirectionally)"),
        None => println!("  handle     <unverified>"),
    }
    println!("  pds        {}", account.pds_url);
    Ok((account.did, account.pds_url))
}

/// Block on a single callback request and return its query string.
fn wait_for_callback(port: u16) -> Result<String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("binding 127.0.0.1:{port} for the callback"))?;
    let (stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let target = request_line
        .split_whitespace()
        .nth(1)
        .context("malformed callback request line")?;
    let query = target
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .to_string();

    let mut stream = stream;
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCallback received. Return to the terminal.\r\n",
    )?;
    Ok(query)
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

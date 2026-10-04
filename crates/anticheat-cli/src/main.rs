use anticheat_core::AnticheatConfig;
use anticheat_model::{AccountId, RequestContext, RequestId, ServerState, SessionId};
use anticheat_rules::Engine;
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
struct CheckBody {
    account_id: String,
    session_id: String,
    request_id: String,
    sequence: u64,
    nonce: String,
    timestamp_ms: i64,
    endpoint: String,
    ip: Option<String>,
    device_fingerprint: Option<String>,
    udkey: Option<String>,
    gdkey: Option<String>,
    is_admin: Option<bool>,
    payload: serde_json::Value,
    state: Option<ServerState>,
}

#[derive(Serialize)]
struct HealthBody {
    status: String,
    version: String,
}

async fn health() -> Json<HealthBody> {
    Json(HealthBody {
        status: String::from("ok"),
        version: String::from("0.1.0"),
    })
}

async fn check(
    axum::extract::State(engine): axum::extract::State<Arc<Engine>>,
    Json(body): Json<CheckBody>,
) -> Json<anticheat_model::CheckResult> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let payload_bytes = serde_json::to_string(&body.payload)
        .map(|text| text.len())
        .unwrap_or(0);
    let ctx = RequestContext {
        account_id: AccountId::new(body.account_id),
        session_id: SessionId::new(body.session_id),
        request_id: RequestId::new(body.request_id),
        sequence: body.sequence,
        nonce: body.nonce,
        timestamp_ms: body.timestamp_ms,
        received_ms: now_ms,
        endpoint: body.endpoint,
        operation: anticheat_model::OperationKind::Unknown,
        ip: body.ip,
        device_fingerprint: body.device_fingerprint,
        udkey: body.udkey,
        gdkey: body.gdkey,
        is_admin: body.is_admin.unwrap_or(false),
        payload: body.payload,
        payload_bytes,
    };
    let state = body.state.unwrap_or_default();
    Json(engine.evaluate(&ctx, &state, now_ms))
}

fn print_usage() {
    println!("anticheat 0.1.0");
    println!("usage:");
    println!("  anticheat validate-config <path>");
    println!("  anticheat check <input.json>");
    println!("  anticheat daemon [--port 12777] [--token <secret>]");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }
    match args[1].as_str() {
        "validate-config" => {
            if args.len() < 3 {
                eprintln!("missing config path");
                std::process::exit(2);
            }
            let text = std::fs::read_to_string(&args[2]).unwrap_or_else(|err| {
                eprintln!("read failed: {err}");
                std::process::exit(2);
            });
            match serde_json::from_str::<AnticheatConfig>(&text) {
                Ok(_) => println!("config ok"),
                Err(err) => {
                    eprintln!("config invalid: {err}");
                    std::process::exit(1);
                }
            }
        }
        "check" => {
            if args.len() < 3 {
                eprintln!("missing input path");
                std::process::exit(2);
            }
            let text = std::fs::read_to_string(&args[2]).unwrap_or_else(|err| {
                eprintln!("read failed: {err}");
                std::process::exit(2);
            });
            let body: CheckBody = serde_json::from_str(&text).unwrap_or_else(|err| {
                eprintln!("input invalid: {err}");
                std::process::exit(2);
            });
            let engine = Engine::new(AnticheatConfig::default());
            let now_ms = chrono::Utc::now().timestamp_millis();
            let payload_bytes = serde_json::to_string(&body.payload)
                .map(|text| text.len())
                .unwrap_or(0);
            let ctx = RequestContext {
                account_id: AccountId::new(body.account_id),
                session_id: SessionId::new(body.session_id),
                request_id: RequestId::new(body.request_id),
                sequence: body.sequence,
                nonce: body.nonce,
                timestamp_ms: body.timestamp_ms,
                received_ms: now_ms,
                endpoint: body.endpoint,
                operation: anticheat_model::OperationKind::Unknown,
                ip: body.ip,
                device_fingerprint: body.device_fingerprint,
                udkey: body.udkey,
                gdkey: body.gdkey,
                is_admin: body.is_admin.unwrap_or(false),
                payload: body.payload,
                payload_bytes,
            };
            let state = body.state.unwrap_or_default();
            let result = engine.evaluate(&ctx, &state, now_ms);
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
            if !result.allowed {
                std::process::exit(3);
            }
        }
        "daemon" => {
            let mut port = 12777;
            let mut token = String::new();
            let mut index = 2;
            while index < args.len() {
                if args[index] == "--port" && index + 1 < args.len() {
                    port = args[index + 1].parse().unwrap_or(12777);
                    index += 2;
                } else if args[index] == "--token" && index + 1 < args.len() {
                    token = args[index + 1].clone();
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if token.is_empty() {
                token = std::env::var("ANTICHEAT_TOKEN").unwrap_or_default();
            }
            if token.is_empty() {
                eprintln!("daemon requires --token or ANTICHEAT_TOKEN");
                std::process::exit(2);
            }
            let engine = Arc::new(Engine::new(AnticheatConfig::default()));
            let app = Router::new()
                .route("/health", axum::routing::get(health))
                .route("/check", post(check))
                .with_state(engine);
            let bind = format!("127.0.0.1:{port}");
            println!("listening on {bind}");
            let listener = tokio::net::TcpListener::bind(&bind)
                .await
                .unwrap_or_else(|err| {
                    eprintln!("bind failed: {err}");
                    std::process::exit(1);
                });
            axum::serve(listener, app).await.unwrap_or_else(|err| {
                eprintln!("serve failed: {err}");
                std::process::exit(1);
            });
        }
        _ => print_usage(),
    }
}

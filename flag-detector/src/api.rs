//! HTTP API 服务模块
//! 提供 REST API 支持

use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    http::{header, HeaderValue, Method, Request},
    middleware::Next,
    response::Json,
    response::Response,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{decoder, matcher, DetectorConfig, ExtractedString};

/// API 状态
pub struct ApiState {
    pub config: DetectorConfig,
}

/// 分析请求
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub content: String,
    pub mode: Option<String>,
}

/// 分析响应
#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub success: bool,
    pub flags: Vec<FlagResult>,
    pub file_info: Option<FileInfo>,
    pub logs: Vec<LogEntry>,
}

/// Flag 结果
#[derive(Debug, Serialize)]
pub struct FlagResult {
    pub content: String,
    pub confidence: f64,
    pub source: String,
    pub encoding: Option<String>,
}

/// 文件信息
#[derive(Debug, Serialize)]
pub struct FileInfo {
    pub name: String,
    pub size: usize,
    pub file_type: String,
}

/// 日志条目
#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub module: String,
    pub action: String,
}

async fn cors_layer(
    req: Request<Body>,
    next: Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::NO_CONTENT;
        add_cors_headers(res.headers_mut());
        return res;
    }

    let mut res = next.run(req).await;
    add_cors_headers(res.headers_mut());
    res
}

fn add_cors_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
}

/// 创建 API 路由
pub fn create_router(config: DetectorConfig) -> Router {
    let api_state = Arc::new(ApiState { config });

    Router::new()
        .route("/api/health", get(health_check))
        .route("/api/analyze", post(analyze_text))
        .layer(axum::middleware::from_fn(cors_layer))
        .with_state(api_state)
}

/// 健康检查
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// 分析文本内容
async fn analyze_text(
    State(api_state): State<Arc<ApiState>>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, StatusCode> {
    let mut logs = Vec::new();
    let mut flags = Vec::new();

    // 记录开始
    logs.push(log_entry("info", "system", "开始分析文本内容"));

    // 提取字符串
    logs.push(log_entry("info", "extractor", "提取字符串"));
    let extracted = vec![ExtractedString {
        content: req.content,
        offset: 0,
    }];

    // 解码
    logs.push(log_entry("info", "decoder", "尝试解码"));
    let decoded = decoder::decode_strings(&extracted, &api_state.config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 匹配 Flag
    logs.push(log_entry("info", "matcher", "匹配 Flag 模式"));
    let detected = matcher::match_flags(&decoded, &api_state.config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for flag in detected {
        logs.push(log_entry(
            "info",
            "matcher",
            &format!("发现 Flag: {}", flag.content),
        ));
        flags.push(FlagResult {
            content: flag.content,
            confidence: f64::from(flag.confidence),
            source: format!("{:?}", flag.encoding_chain),
            encoding: None,
        });
    }

    logs.push(log_entry(
        "info",
        "system",
        &format!("分析完成，共发现 {} 个 Flag", flags.len()),
    ));

    Ok(Json(AnalyzeResponse {
        success: true,
        flags,
        file_info: None,
        logs,
    }))
}

fn log_entry(
    level: &str,
    module: &str,
    action: &str,
) -> LogEntry {
    LogEntry {
        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
        level: level.to_string(),
        module: module.to_string(),
        action: action.to_string(),
    }
}

/// 启动 API 服务器
///
/// # Errors
///
/// 当绑定端口失败或服务运行过程中出现 I/O 错误时返回错误。
pub async fn start_server(
    config: DetectorConfig,
    port: u16,
) -> anyhow::Result<()> {
    let app = create_router(config);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    log::info!("ZMctf API 服务器启动在 http://localhost:{port}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::response::Json;

    #[tokio::test]
    async fn test_health_check_ok() {
        let Json(v) = health_check().await;
        assert_eq!(v["status"], "ok");
        assert!(v.get("version").is_some());
    }

    #[tokio::test]
    async fn test_analyze_returns_flag() {
        let api_state = Arc::new(ApiState {
            config: DetectorConfig::default(),
        });

        let req = AnalyzeRequest {
            content: "flag{unit_test}".to_string(),
            mode: None,
        };

        let Json(resp) = analyze_text(State(api_state), Json(req))
            .await
            .expect("analyze_text should succeed");

        assert!(resp.success);
        assert!(!resp.flags.is_empty());
    }
}

//! HTTP API 服务模块
//! 提供 REST API 支持

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::Json,
    response::Response,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::AppConfig;
use crate::{decoder, extractor, matcher, ExtractedString};

/// API 状态
pub struct ApiState {
    config_path: PathBuf,
    config: RwLock<AppConfig>,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;

fn err_bad_request(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.into())
}

fn err_payload_too_large(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::PAYLOAD_TOO_LARGE, message.into())
}

fn err_internal(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, message.into())
}

/// 分析请求
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub content: String,
    pub mode: Option<String>,
}

/// 二进制分析请求（Base64）
#[derive(Debug, Deserialize)]
pub struct AnalyzeBytesRequest {
    pub data_base64: String,
    pub file_name: Option<String>,
    pub mode: Option<String>,
}

/// 后端配置响应
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub config_path: String,
    pub config: AppConfig,
}

/// 默认配置响应
#[derive(Debug, Serialize)]
pub struct DefaultConfigResponse {
    pub config: AppConfig,
    pub toml: String,
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
        HeaderValue::from_static("GET, POST, PUT, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
}

/// 创建 API 路由
pub fn create_router(
    app_config: AppConfig,
    config_path: PathBuf,
) -> Router {
    let api_state = Arc::new(ApiState {
        config_path,
        config: RwLock::new(app_config),
    });
    Router::new()
        .route("/api/health", get(health_check))
        .route("/api/analyze", post(analyze_text))
        .route("/api/analyze_bytes", post(analyze_bytes))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/config/default", get(get_default_config))
        .route("/api/config/reload", post(reload_config))
        .route("/api/config/reset", post(reset_config))
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

async fn get_config(State(api_state): State<Arc<ApiState>>) -> ApiResult<ConfigResponse> {
    let config = api_state.config.read().await.clone();
    Ok(Json(ConfigResponse {
        config_path: api_state.config_path.to_string_lossy().to_string(),
        config,
    }))
}

async fn get_default_config() -> ApiResult<DefaultConfigResponse> {
    Ok(Json(DefaultConfigResponse {
        config: AppConfig::default(),
        toml: AppConfig::generate_default_config(),
    }))
}

async fn put_config(
    State(api_state): State<Arc<ApiState>>,
    Json(next_config): Json<AppConfig>,
) -> ApiResult<ConfigResponse> {
    next_config
        .validate()
        .map_err(|e| err_bad_request(e.to_string()))?;

    let config_path = api_state.config_path.clone();
    let next_state = next_config.clone();
    tokio::task::spawn_blocking(move || next_config.save(&config_path))
        .await
        .map_err(|e| err_internal(e.to_string()))?
        .map_err(|e| err_internal(e.to_string()))?;

    *api_state.config.write().await = next_state.clone();

    Ok(Json(ConfigResponse {
        config_path: api_state.config_path.to_string_lossy().to_string(),
        config: next_state,
    }))
}

async fn reload_config(State(api_state): State<Arc<ApiState>>) -> ApiResult<ConfigResponse> {
    let config_path = api_state.config_path.clone();
    let loaded = tokio::task::spawn_blocking(move || AppConfig::load(&config_path))
        .await
        .map_err(|e| err_internal(e.to_string()))?
        .map_err(|e| err_internal(e.to_string()))?;

    loaded
        .validate()
        .map_err(|e| err_bad_request(e.to_string()))?;

    *api_state.config.write().await = loaded.clone();

    Ok(Json(ConfigResponse {
        config_path: api_state.config_path.to_string_lossy().to_string(),
        config: loaded,
    }))
}

async fn reset_config(State(api_state): State<Arc<ApiState>>) -> ApiResult<ConfigResponse> {
    let config_path = api_state.config_path.clone();
    let reset = AppConfig::default();
    reset
        .validate()
        .map_err(|e| err_bad_request(e.to_string()))?;

    let reset_for_save = reset.clone();
    tokio::task::spawn_blocking(move || reset_for_save.save(&config_path))
        .await
        .map_err(|e| err_internal(e.to_string()))?
        .map_err(|e| err_internal(e.to_string()))?;

    *api_state.config.write().await = reset.clone();

    Ok(Json(ConfigResponse {
        config_path: api_state.config_path.to_string_lossy().to_string(),
        config: reset,
    }))
}

/// 分析文本内容
async fn analyze_text(
    State(api_state): State<Arc<ApiState>>,
    Json(req): Json<AnalyzeRequest>,
) -> ApiResult<AnalyzeResponse> {
    let mut logs = Vec::new();
    let mut flags = Vec::new();

    // 记录开始
    logs.push(log_entry("info", "system", "开始分析文本内容"));

    let app_config = api_state.config.read().await.clone();
    let detector_config = app_config.to_detector_config();

    if req.content.len() > detector_config.max_file_size {
        return Err(err_payload_too_large(format!(
            "输入文本超过限制: {} bytes",
            req.content.len()
        )));
    }

    // 构造输入字符串
    logs.push(log_entry("info", "extractor", "构造输入字符串"));
    let extracted = vec![ExtractedString {
        content: req.content,
        offset: 0,
    }];

    // 解码
    logs.push(log_entry("info", "decoder", "尝试解码"));
    let decoded = decoder::decode_strings(&extracted, &detector_config)
        .map_err(|e| err_internal(e.to_string()))?;

    // 匹配 Flag
    logs.push(log_entry("info", "matcher", "匹配 Flag 模式"));
    let detected = matcher::match_flags(&decoded, &detector_config)
        .map_err(|e| err_internal(e.to_string()))?;

    for flag in detected {
        logs.push(log_entry(
            "info",
            "matcher",
            &format!("发现 Flag: {}", flag.content),
        ));
        flags.push(FlagResult {
            content: flag.content,
            confidence: f64::from(flag.confidence),
            source: flag.pattern,
            encoding: Some(format!("{:?}", flag.encoding_chain)),
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

/// 分析二进制内容（Base64 输入）
async fn analyze_bytes(
    State(api_state): State<Arc<ApiState>>,
    Json(req): Json<AnalyzeBytesRequest>,
) -> ApiResult<AnalyzeResponse> {
    let mut logs = Vec::new();
    let mut flags = Vec::new();

    logs.push(log_entry("info", "system", "开始分析二进制内容"));

    let app_config = api_state.config.read().await.clone();
    let detector_config = app_config.to_detector_config();

    logs.push(log_entry("info", "decoder", "Base64 解码"));
    let data = general_purpose::STANDARD
        .decode(req.data_base64)
        .map_err(|e| err_bad_request(format!("base64 解码失败: {e}")))?;

    logs.push(log_entry("info", "magic", "文件魔数识别"));
    let magic = crate::magic::detect_bytes(&data);

    logs.push(log_entry("info", "extractor", "提取字符串"));
    let extracted = extractor::extract_strings_from_bytes(&data, &detector_config)
        .map_err(|e| err_payload_too_large(e.to_string()))?;

    logs.push(log_entry("info", "decoder", "尝试解码"));
    let decoded = decoder::decode_strings(&extracted, &detector_config)
        .map_err(|e| err_internal(e.to_string()))?;

    logs.push(log_entry("info", "matcher", "匹配 Flag 模式"));
    let detected = matcher::match_flags(&decoded, &detector_config)
        .map_err(|e| err_internal(e.to_string()))?;

    for flag in detected {
        logs.push(log_entry(
            "info",
            "matcher",
            &format!("发现 Flag: {}", flag.content),
        ));
        flags.push(FlagResult {
            content: flag.content,
            confidence: f64::from(flag.confidence),
            source: flag.pattern,
            encoding: Some(format!("{:?}", flag.encoding_chain)),
        });
    }

    logs.push(log_entry(
        "info",
        "system",
        &format!("分析完成，共发现 {} 个 Flag", flags.len()),
    ));

    let file_name = req.file_name.unwrap_or_else(|| "<bytes>".to_string());
    let file_info = FileInfo {
        name: file_name,
        size: data.len(),
        file_type: format!("{} ({})", magic.extension, magic.description),
    };

    Ok(Json(AnalyzeResponse {
        success: true,
        flags,
        file_info: Some(file_info),
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
    app_config: AppConfig,
    config_path: PathBuf,
    port: u16,
) -> anyhow::Result<()> {
    let app = create_router(app_config, config_path);
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
            config_path: PathBuf::from("test-config.toml"),
            config: RwLock::new(AppConfig::default()),
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

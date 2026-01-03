use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

/// WebSocket 日志消息
#[derive(Debug, Clone, Serialize)]
pub struct WsLogMessage {
    pub timestamp: String,
    pub level: LogLevel,
    pub module: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// 日志级别
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,  // 原子操作
    Info,   // 主要步骤
    Result, // 分析结果
    Flag,   // 发现 Flag
    Error,  // 错误
}

/// 分析完成消息
#[derive(Debug, Clone, Serialize)]
pub struct WsCompleteMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub report: serde_json::Value,
}

/// WebSocket 状态
pub struct WsState {
    pub tx: broadcast::Sender<String>,
}

impl WsState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { tx }
    }

    /// 发送日志消息
    pub fn send_log(&self, msg: &WsLogMessage) {
        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = self.tx.send(json);
        }
    }

    /// 发送完成消息
    pub fn send_complete(&self, report: serde_json::Value) {
        let msg = WsCompleteMessage {
            msg_type: "complete".to_string(),
            report,
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = self.tx.send(json);
        }
    }
}

impl Default for WsState {
    fn default() -> Self {
        Self::new()
    }
}

/// WebSocket 处理器
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State((_api_state, ws_state)): State<(Arc<crate::api::ApiState>, Arc<WsState>)>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, ws_state))
}

async fn handle_socket(socket: WebSocket, state: Arc<WsState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    // 发送日志到客户端
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // 接收客户端命令（可选）
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(_msg)) = receiver.next().await {
            // 可以处理客户端发送的命令
        }
    });

    // 等待任一任务完成
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}

/// 获取当前时间戳字符串
pub fn now() -> String {
    use chrono::Local;
    Local::now().format("%H:%M:%S").to_string()
}

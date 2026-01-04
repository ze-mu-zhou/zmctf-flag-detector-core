//! `ZMctf` API 服务器入口

use flag_detector::{api, AppConfig};
use std::path::PathBuf;
use std::sync::Once;

static LOGGER_INIT: Once = Once::new();

struct SimpleStdoutLogger;

impl log::Log for SimpleStdoutLogger {
    fn enabled(
        &self,
        metadata: &log::Metadata<'_>,
    ) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(
        &self,
        record: &log::Record<'_>,
    ) {
        if !self.enabled(record.metadata()) {
            return;
        }
        println!(
            "[{}] {}: {}",
            record.level(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {}
}

static LOGGER: SimpleStdoutLogger = SimpleStdoutLogger;

fn init_logger() {
    LOGGER_INIT.call_once(|| {
        let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Info));
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    init_logger();

    // 读取配置（优先环境变量 ZMCTF_CONFIG，其次默认路径）
    let config_path =
        std::env::var_os("ZMCTF_CONFIG").map_or_else(AppConfig::default_config_path, PathBuf::from);
    let app_config = AppConfig::load_or_default(Some(&config_path));

    // 启动服务器
    let port = std::env::var("ZMCTF_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    api::start_server(app_config, config_path, port).await
}

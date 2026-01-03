//! `ZMctf` API 服务器入口

use flag_detector::{api, DetectorConfig};
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

    // 默认配置
    let config = DetectorConfig::default();

    // 启动服务器
    api::start_server(config, 8080).await
}

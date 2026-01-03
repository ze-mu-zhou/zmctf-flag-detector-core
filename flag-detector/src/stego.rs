//! 图片隐写检测模块
//!
//! 支持 LSB 提取、EXIF 分析、PNG 块（chunk）分析等

use anyhow::Result;
use image::{DynamicImage, GenericImageView};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zmctf_constraints::{read_file_with_limit, read_to_end_with_limit, ResourceLimits};

fn ratio_usize_to_f32(
    numer: usize,
    denom: usize,
) -> f32 {
    if denom == 0 {
        0.0
    } else {
        let max = usize::from(u16::MAX);
        let numer_u16 = u16::try_from(numer.min(max)).unwrap_or(u16::MAX);
        let denom_u16 = u16::try_from(denom.min(max)).unwrap_or(u16::MAX);
        if denom_u16 == 0 {
            0.0
        } else {
            f32::from(numer_u16) / f32::from(denom_u16)
        }
    }
}

/// LSB提取通道顺序
#[derive(Debug, Clone, Copy, Default)]
pub enum LsbChannelOrder {
    #[default]
    RGB,
    BGR,
    RBG,
    GBR,
    GRB,
    BRG,
    R,
    G,
    B,
    RGBA,
    BGRA,
}

impl LsbChannelOrder {
    /// 获取通道索引顺序
    const fn indices(&self) -> &[usize] {
        match self {
            Self::RGB => &[0, 1, 2],
            Self::BGR => &[2, 1, 0],
            Self::RBG => &[0, 2, 1],
            Self::GBR => &[1, 2, 0],
            Self::GRB => &[1, 0, 2],
            Self::BRG => &[2, 0, 1],
            Self::R => &[0],
            Self::G => &[1],
            Self::B => &[2],
            Self::RGBA => &[0, 1, 2, 3],
            Self::BGRA => &[2, 1, 0, 3],
        }
    }

    /// 所有通道顺序
    const fn all() -> &'static [Self] {
        &[Self::RGB, Self::BGR, Self::R, Self::G, Self::B, Self::RGBA]
    }
}

/// LSB提取配置
#[derive(Debug, Clone)]
pub struct LsbConfig {
    pub bits: u8, // 提取位数 (1-8)
    pub channel_order: LsbChannelOrder,
    pub row_order: bool,  // true=行优先, false=列优先
    pub msb_first: bool,  // true=MSB优先, false=LSB优先
    pub max_bytes: usize, // 最大提取字节数
}

impl Default for LsbConfig {
    fn default() -> Self {
        Self {
            bits: 1,
            channel_order: LsbChannelOrder::RGB,
            row_order: true,
            msb_first: false,
            max_bytes: 65536,
        }
    }
}

/// 隐写检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegoResult {
    /// 检测方法
    pub method: String,
    /// 提取的数据
    pub data: Vec<u8>,
    /// 数据的文本表示（如果可打印）
    pub text: Option<String>,
    /// 置信度
    pub confidence: f32,
    /// 描述
    pub description: String,
}

/// PNG Chunk信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PngChunk {
    /// Chunk类型（4字节ASCII）
    pub chunk_type: String,
    /// 数据长度
    pub length: u32,
    /// 数据内容
    pub data: Vec<u8>,
    /// CRC校验值
    pub crc: u32,
    /// 文件中的偏移
    pub offset: u64,
}

/// EXIF元数据
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExifData {
    pub entries: HashMap<String, String>,
}

/// 隐写分析器
#[derive(Clone)]
pub struct StegoAnalyzer {
    /// 最大提取数据大小
    pub max_extract_size: usize,
    /// LSB提取的位数
    pub lsb_bits: u8,
    /// 全局资源与安全约束（文件大小、外部命令 timeout/截断等）。
    pub resources: ResourceLimits,
}

impl Default for StegoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StegoAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_extract_size: 1024 * 1024, // 1MB
            lsb_bits: 1,
            resources: ResourceLimits::default(),
        }
    }

    /// 应用全局资源与安全约束。
    #[must_use]
    pub fn with_resource_limits(
        mut self,
        resources: ResourceLimits,
    ) -> Self {
        self.resources = resources;
        self
    }

    /// 分析图片文件
    ///
    /// # Errors
    ///
    /// 当读取文件失败或图片解析失败时返回错误。
    pub fn analyze_file(
        &self,
        path: &Path,
    ) -> Result<Vec<StegoResult>> {
        let data = read_file_with_limit(path, self.resources.input_max_bytes)?;
        self.analyze_bytes(&data)
    }

    /// 分析图片字节
    ///
    /// # Errors
    ///
    /// 当图片解析失败时返回错误。
    pub fn analyze_bytes(
        &self,
        data: &[u8],
    ) -> Result<Vec<StegoResult>> {
        let mut results = Vec::new();

        // 检测文件类型
        if data.len() < 8 {
            return Ok(results);
        }

        // PNG分析
        if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            results.extend(self.analyze_png(data));
        }
        // JPEG分析
        else if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
            results.extend(Self::analyze_jpeg(data));
        }
        // BMP分析
        else if data.len() >= 2 && &data[0..2] == b"BM" {
            results.extend(self.analyze_bmp(data));
        }

        // 通用LSB分析
        if let Some(lsb_result) = self.extract_lsb_generic(data) {
            results.push(lsb_result);
        }

        // 检测文件尾部附加数据
        if let Some(trailing) = Self::detect_trailing_data(data) {
            results.push(trailing);
        }

        Ok(results)
    }

    /// 分析PNG文件
    fn analyze_png(
        &self,
        data: &[u8],
    ) -> Vec<StegoResult> {
        let mut results = Vec::new();
        let chunks = Self::parse_png_chunks(data);

        // 检查文本块
        for chunk in &chunks {
            match chunk.chunk_type.as_str() {
                "tEXt" | "zTXt" | "iTXt" => {
                    // 文本块可能包含隐藏信息
                    if let Some(text) = self.decode_png_text_chunk(chunk) {
                        results.push(StegoResult {
                            method: format!("PNG {} 块", chunk.chunk_type),
                            data: chunk.data.clone(),
                            text: Some(text.clone()),
                            confidence: 0.7,
                            description: format!("在 {} 块中发现文本: {}", chunk.chunk_type, text),
                        });
                    }
                }
                "IEND" => {
                    // 检查IEND后的数据
                    let iend_end = usize::try_from(chunk.offset)
                        .unwrap_or(usize::MAX)
                        .saturating_add(12); // 4 length + 4 type + 4 crc
                    if iend_end < data.len() {
                        let trailing = &data[iend_end..];
                        if !trailing.is_empty() && !trailing.iter().all(|&b| b == 0) {
                            let text = bytes_to_text(trailing);
                            results.push(StegoResult {
                                method: "PNG 尾部附加数据".to_string(),
                                data: trailing.to_vec(),
                                text,
                                confidence: 0.9,
                                description: format!(
                                    "在 IEND 之后发现数据: {} 字节",
                                    trailing.len()
                                ),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // PNG LSB提取
        if let Some(lsb) = self.extract_png_lsb(data) {
            results.push(lsb);
        }

        results
    }

    /// 解析 PNG 块
    fn parse_png_chunks(data: &[u8]) -> Vec<PngChunk> {
        let mut chunks = Vec::new();
        let mut offset = 8usize; // 跳过PNG签名

        while offset + 12 <= data.len() {
            let length = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            let chunk_type = String::from_utf8_lossy(&data[offset + 4..offset + 8]).to_string();

            let data_start = offset + 8;
            let data_end = data_start + length as usize;

            if data_end + 4 > data.len() {
                break;
            }

            let chunk_data = data[data_start..data_end].to_vec();
            let crc = u32::from_be_bytes([
                data[data_end],
                data[data_end + 1],
                data[data_end + 2],
                data[data_end + 3],
            ]);

            chunks.push(PngChunk {
                chunk_type: chunk_type.clone(),
                length,
                data: chunk_data,
                crc,
                offset: offset as u64,
            });

            if chunk_type == "IEND" {
                break;
            }

            offset = data_end + 4;
        }

        chunks
    }

    /// 解码 PNG 文本块
    fn decode_png_text_chunk(
        &self,
        chunk: &PngChunk,
    ) -> Option<String> {
        match chunk.chunk_type.as_str() {
            "tEXt" => {
                // tEXt: keyword\0text
                if let Some(null_pos) = chunk.data.iter().position(|&b| b == 0) {
                    let text = &chunk.data[null_pos + 1..];
                    return bytes_to_text(text);
                }
            }
            "zTXt" => {
                // zTXt: keyword\0compression_method\0compressed_text
                if let Some(null_pos) = chunk.data.iter().position(|&b| b == 0) {
                    if null_pos + 2 < chunk.data.len() {
                        let compressed = &chunk.data[null_pos + 2..];
                        // 尝试zlib解压
                        if let Ok((decompressed, truncated)) =
                            decompress_zlib(compressed, self.max_extract_size)
                        {
                            let mut text = bytes_to_text(&decompressed)?;
                            if truncated {
                                text.push_str(" [zlib 解压已截断]");
                            }
                            return Some(text);
                        }
                    }
                }
            }
            "iTXt" => {
                // iTXt: keyword\0compression_flag\0compression_method\0language\0translated_keyword\0text
                let parts: Vec<&[u8]> = chunk.data.split(|&b| b == 0).collect();
                if parts.len() >= 5 {
                    return bytes_to_text(parts[parts.len() - 1]);
                }
            }
            _ => {}
        }
        None
    }

    /// 提取PNG LSB数据 - 完整实现
    fn extract_png_lsb(
        &self,
        data: &[u8],
    ) -> Option<StegoResult> {
        let img = image::load_from_memory(data).ok()?;

        // 尝试多种通道顺序
        for &order in LsbChannelOrder::all() {
            let config = LsbConfig {
                bits: self.lsb_bits,
                channel_order: order,
                max_bytes: self.max_extract_size,
                ..Default::default()
            };

            if let Some(result) = Self::extract_image_lsb(&img, &config) {
                return Some(result);
            }
        }
        None
    }

    /// 从图像提取LSB数据
    fn extract_image_lsb(
        img: &DynamicImage,
        config: &LsbConfig,
    ) -> Option<StegoResult> {
        let (width, height) = img.dimensions();
        let rgba = img.to_rgba8();
        let indices = config.channel_order.indices();
        let mask = (1u8 << config.bits) - 1;

        let mut extracted = Vec::new();
        let mut current_byte = 0u8;
        let mut bit_count = 0u8;

        let pixels: Vec<_> = if config.row_order {
            (0..height)
                .flat_map(|y| (0..width).map(move |x| (x, y)))
                .collect()
        } else {
            (0..width)
                .flat_map(|x| (0..height).map(move |y| (x, y)))
                .collect()
        };

        'outer: for (x, y) in pixels {
            let pixel = rgba.get_pixel(x, y).0;
            for &idx in indices {
                if idx >= 4 {
                    continue;
                }
                let bits = pixel[idx] & mask;

                for i in 0..config.bits {
                    let bit = if config.msb_first {
                        (bits >> (config.bits - 1 - i)) & 1
                    } else {
                        (bits >> i) & 1
                    };
                    current_byte = (current_byte << 1) | bit;
                    bit_count += 1;

                    if bit_count == 8 {
                        extracted.push(current_byte);
                        current_byte = 0;
                        bit_count = 0;

                        if extracted.len() >= config.max_bytes {
                            break 'outer;
                        }
                    }
                }
            }
        }

        Self::validate_lsb_result(&extracted, &format!("PNG LSB {:?}", config.channel_order))
    }

    /// 验证LSB提取结果
    fn validate_lsb_result(
        data: &[u8],
        method: &str,
    ) -> Option<StegoResult> {
        if data.len() < 4 {
            return None;
        }

        // 检查是否全是相同值
        if data.iter().all(|&b| b == data[0]) {
            return None;
        }

        let text = bytes_to_text(data);

        // 检查flag模式
        if let Some(ref t) = text {
            let lower = t.to_lowercase();
            if lower.contains("flag{") || lower.contains("ctf{") || lower.contains("key{") {
                return Some(StegoResult {
                    method: method.to_string(),
                    data: data.to_vec(),
                    text,
                    confidence: 0.95,
                    description: "在 LSB 数据中发现 Flag 模式".to_string(),
                });
            }
        }

        // 检查可打印比例
        let printable = data
            .iter()
            .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D)
            .count();
        let ratio = ratio_usize_to_f32(printable, data.len());

        if ratio > 0.8 && data.len() > 20 {
            return Some(StegoResult {
                method: method.to_string(),
                data: data.to_vec(),
                text,
                confidence: ratio,
                description: format!("LSB 数据中可打印字符比例较高（{:.0}%）", ratio * 100.0),
            });
        }

        None
    }

    /// 使用指定配置提取LSB (公开API)
    #[must_use]
    pub fn extract_lsb_with_config(
        &self,
        data: &[u8],
        config: &LsbConfig,
    ) -> Option<StegoResult> {
        let img = image::load_from_memory(data).ok()?;
        Self::extract_image_lsb(&img, config)
    }

    /// 暴力尝试所有LSB配置 (并行)
    #[must_use]
    pub fn extract_lsb_bruteforce(
        &self,
        data: &[u8],
    ) -> Vec<StegoResult> {
        let Ok(img) = image::load_from_memory(data) else {
            return Vec::new();
        };

        // 生成所有配置组合
        let configs: Vec<LsbConfig> = LsbChannelOrder::all()
            .iter()
            .flat_map(|&order| {
                (1..=2u8).flat_map(move |bits| {
                    [true, false].iter().flat_map(move |&row_order| {
                        [false, true].iter().map(move |&msb_first| LsbConfig {
                            bits,
                            channel_order: order,
                            row_order,
                            msb_first,
                            max_bytes: self.max_extract_size,
                        })
                    })
                })
            })
            .collect();

        configs
            .par_iter()
            .filter_map(|config| Self::extract_image_lsb(&img, config))
            .collect()
    }

    /// 分析JPEG文件
    fn analyze_jpeg(data: &[u8]) -> Vec<StegoResult> {
        let mut results = Vec::new();

        // 查找JPEG注释段 (0xFF 0xFE)
        let mut i = 2;
        while i + 4 < data.len() {
            if data[i] == 0xFF {
                let marker = data[i + 1];
                if marker == 0xFE {
                    // COM（注释）段
                    let length = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                    if i + 2 + length <= data.len() {
                        let comment = &data[i + 4..i + 2 + length];
                        if let Some(text) = bytes_to_text(comment) {
                            results.push(StegoResult {
                                method: "JPEG 注释".to_string(),
                                data: comment.to_vec(),
                                text: Some(text.clone()),
                                confidence: 0.8,
                                description: format!("发现注释: {text}"),
                            });
                        }
                    }
                }
                // 跳过段
                if (0xE0..=0xEF).contains(&marker) || marker == 0xFE {
                    let length = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                    i += 2 + length;
                } else if marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker) {
                    i += 2;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        // 检测JPEG EOI后的数据
        for i in (0..data.len().saturating_sub(1)).rev() {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                let eoi_end = i + 2;
                if eoi_end < data.len() {
                    let trailing = &data[eoi_end..];
                    if trailing.len() > 10 && !trailing.iter().all(|&b| b == 0) {
                        let text = bytes_to_text(trailing);
                        results.push(StegoResult {
                            method: "JPEG 尾部附加数据".to_string(),
                            data: trailing.to_vec(),
                            text,
                            confidence: 0.9,
                            description: format!("在 EOI 之后发现数据: {} 字节", trailing.len()),
                        });
                    }
                }
                break;
            }
        }

        results
    }

    /// 分析BMP文件
    fn analyze_bmp(
        &self,
        data: &[u8],
    ) -> Vec<StegoResult> {
        let mut results = Vec::new();

        if data.len() < 54 {
            return results;
        }

        // BMP文件大小
        let file_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;

        // 检查文件尾部数据
        if file_size < data.len() {
            let trailing = &data[file_size..];
            if !trailing.is_empty() && !trailing.iter().all(|&b| b == 0) {
                let text = bytes_to_text(trailing);
                results.push(StegoResult {
                    method: "BMP 尾部附加数据".to_string(),
                    data: trailing.to_vec(),
                    text,
                    confidence: 0.9,
                    description: format!("在 BMP 之后发现数据: {} 字节", trailing.len()),
                });
            }
        }

        // BMP LSB提取
        if let Some(lsb) = self.extract_bmp_lsb(data) {
            results.push(lsb);
        }

        results
    }

    /// 提取BMP LSB数据
    fn extract_bmp_lsb(
        &self,
        data: &[u8],
    ) -> Option<StegoResult> {
        if data.len() < 54 {
            return None;
        }

        // 获取像素数据偏移
        let pixel_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
        if pixel_offset >= data.len() {
            return None;
        }

        let pixel_data = &data[pixel_offset..];

        // 提取LSB
        let mut extracted = Vec::new();
        let mut current_byte = 0u8;
        let mut bit_count = 0;

        for &byte in pixel_data.iter().take(self.max_extract_size * 8) {
            let lsb = byte & 1;
            current_byte = (current_byte << 1) | lsb;
            bit_count += 1;

            if bit_count == 8 {
                extracted.push(current_byte);
                current_byte = 0;
                bit_count = 0;

                // 检查是否有有意义的数据
                if extracted.len() >= 4 {
                    // 检查是否全是0或全是相同值
                    if extracted.iter().all(|&b| b == 0)
                        || extracted.iter().all(|&b| b == extracted[0])
                    {
                        return None;
                    }
                }
            }
        }

        // 检查提取的数据是否有意义
        let printable_ratio = extracted
            .iter()
            .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D || b == 0x09)
            .count();
        let printable_ratio = ratio_usize_to_f32(printable_ratio, extracted.len().max(1));

        if printable_ratio > 0.7 && extracted.len() > 10 {
            let text = bytes_to_text(&extracted);
            return Some(StegoResult {
                method: "BMP LSB".to_string(),
                data: extracted,
                text,
                confidence: printable_ratio,
                description: "从 BMP 像素数据中提取 LSB".to_string(),
            });
        }

        None
    }

    /// 通用LSB提取
    fn extract_lsb_generic(
        &self,
        data: &[u8],
    ) -> Option<StegoResult> {
        if data.len() < 100 {
            return None;
        }

        // 简单的LSB提取
        let mut extracted = Vec::new();
        let mut current_byte = 0u8;
        let mut bit_count = 0;

        for &byte in data.iter().skip(100).take(self.max_extract_size * 8) {
            let lsb = byte & 1;
            current_byte = (current_byte << 1) | lsb;
            bit_count += 1;

            if bit_count == 8 {
                extracted.push(current_byte);
                current_byte = 0;
                bit_count = 0;
            }
        }

        // 检查是否包含flag模式
        let text = bytes_to_text(&extracted);
        if let Some(ref t) = text {
            let lower = t.to_lowercase();
            if lower.contains("flag{") || lower.contains("ctf{") {
                return Some(StegoResult {
                    method: "通用 LSB".to_string(),
                    data: extracted,
                    text,
                    confidence: 0.95,
                    description: "在 LSB 数据中发现 Flag 模式".to_string(),
                });
            }
        }

        None
    }

    /// 检测文件尾部附加数据
    fn detect_trailing_data(data: &[u8]) -> Option<StegoResult> {
        // 检查是否有 ZIP 签名在文件中间
        for i in 100..data.len().saturating_sub(4) {
            if data[i..].starts_with(b"PK\x03\x04") {
                let trailing = &data[i..];
                return Some(StegoResult {
                    method: "内嵌 ZIP".to_string(),
                    data: trailing.to_vec(),
                    text: None,
                    confidence: 0.95,
                    description: format!("在偏移 {i} 处发现 ZIP 压缩包"),
                });
            }
        }

        None
    }

    /// 获取 PNG 块
    ///
    /// # Errors
    ///
    /// 当读取文件失败或输入不是 PNG 时返回错误。
    pub fn get_png_chunks(
        &self,
        path: &Path,
    ) -> Result<Vec<PngChunk>> {
        let data = read_file_with_limit(path, self.resources.input_max_bytes)?;

        if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
            anyhow::bail!("不是有效的 PNG 文件");
        }

        Ok(Self::parse_png_chunks(&data))
    }
}

/// 将字节转换为文本（如果可打印）
fn bytes_to_text(data: &[u8]) -> Option<String> {
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D || b == 0x09)
        .count();

    if ratio_usize_to_f32(printable, data.len().max(1)) > 0.7 {
        // 尝试UTF-8解码
        if let Ok(s) = String::from_utf8(data.to_vec()) {
            return Some(s);
        }
        // 回退到有损转换
        Some(String::from_utf8_lossy(data).to_string())
    } else {
        None
    }
}

/// 简单的zlib解压（需要flate2 crate）
fn decompress_zlib(
    data: &[u8],
    max_bytes: usize,
) -> Result<(Vec<u8>, bool)> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    read_to_end_with_limit(&mut decoder, u64::try_from(max_bytes).unwrap_or(u64::MAX))
}

/// 便捷函数：分析图片文件
///
/// # Errors
///
/// 当读取文件失败或图片解析失败时返回错误。
pub fn analyze_image(path: &Path) -> Result<Vec<StegoResult>> {
    StegoAnalyzer::new().analyze_file(path)
}

/// 便捷函数：分析图片字节
///
/// # Errors
///
/// 当图片解析失败时返回错误。
pub fn analyze_image_bytes(data: &[u8]) -> Result<Vec<StegoResult>> {
    StegoAnalyzer::new().analyze_bytes(data)
}

// ============================================================================
// 外部工具集成 - steghide, zsteg, binwalk, exiftool, strings
// ============================================================================

use tool_runner::ToolCommand;

/// 外部隐写工具配置
#[derive(Clone, Debug)]
pub struct ExternalToolsConfig {
    pub steghide_path: PathBuf,
    pub zsteg_path: PathBuf,
    pub binwalk_path: PathBuf,
    pub exiftool_path: PathBuf,
    pub strings_path: PathBuf,
    pub foremost_path: PathBuf,
    pub stegseek_path: PathBuf,
    /// 全局资源与安全约束（timeout/stdout/stderr 上限等）。
    pub resources: ResourceLimits,
}

impl Default for ExternalToolsConfig {
    fn default() -> Self {
        Self {
            steghide_path: PathBuf::from("steghide"),
            zsteg_path: PathBuf::from("zsteg"),
            binwalk_path: PathBuf::from("binwalk"),
            exiftool_path: PathBuf::from("exiftool"),
            strings_path: PathBuf::from("strings"),
            foremost_path: PathBuf::from("foremost"),
            stegseek_path: PathBuf::from("stegseek"),
            resources: ResourceLimits::default(),
        }
    }
}

/// 两态开关：替代 `bool`，避免配置结构体出现过多布尔字段。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Toggle {
    #[default]
    Disabled,
    Enabled,
}

impl Toggle {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Steghide 配置 - 100% CLI参数覆盖
#[derive(Clone, Debug, Default)]
pub struct SteghideConfig {
    pub passphrase: Option<String>,    // -p, --passphrase
    pub extract_file: Option<PathBuf>, // -xf, --extractfile
    pub force: Toggle,                 // -f, --force
    pub quiet: Toggle,                 // -q, --quiet
    pub verbose: Toggle,               // -v, --verbose
    pub encryption: Option<String>,    // -e, --encryption (algo:mode)
    pub compression: Option<u8>,       // -z, --compress (1-9)
    pub no_compression: Toggle,        // -Z, --ncompress
    pub checksum: Toggle,              // -K, --checksum
    pub no_checksum: Toggle,           // -N, --nochecksum
    pub embed_name: Option<String>,    // -n, --embedname
    pub no_embed_name: Toggle,         // 未知/兼容：保留字段
    pub radius: Option<u32>,           // -r, --radius
}

/// Zsteg 配置 - 100% CLI参数覆盖
#[derive(Clone, Debug, Default)]
pub struct ZstegConfig {
    pub channels: Option<String>,    // -c, --channels (rgb, bgr, rgba, etc.)
    pub bits: Option<String>,        // -b, --bits (1,2,3,4,5,6,7,8)
    pub order: Option<String>,       // -o, --order (auto, xy, yx, XY, etc.)
    pub prime: Toggle,               // -p, --prime
    pub invert: Toggle,              // -i, --invert
    pub pixel_order: Option<String>, // --pixel-order
    pub limit: Option<usize>,        // -l, --limit
    pub min_str_len: Option<usize>,  // --min-str-len
    pub strings: Toggle,             // -s, --strings
    pub all: Toggle,                 // -a, --all
    pub verbose: Toggle,             // -v, --verbose
    pub extra_checks: Toggle,        // -E, --extra
}

/// Binwalk 配置 - 100% CLI参数覆盖
#[derive(Clone, Debug, Default)]
pub struct BinwalkConfig {
    pub signature: Toggle,          // -B, --signature
    pub raw: Option<String>,        // -R, --raw
    pub opcodes: Toggle,            // -A, --opcodes
    pub cast: Option<String>,       // -C, --cast
    pub entropy: Toggle,            // -E, --entropy
    pub heuristic: Toggle,          // -H, --heuristic
    pub extract: Toggle,            // -e, --extract
    pub matryoshka: Toggle,         // -M, --matryoshka
    pub depth: Option<u32>,         // -d, --depth
    pub directory: Option<PathBuf>, // -C, --directory
    pub quiet: Toggle,              // -q, --quiet
    pub verbose: Toggle,            // -v, --verbose
    pub offset: Option<u64>,        // -o, --offset
    pub length: Option<u64>,        // -l, --length
    pub include: Option<String>,    // -y, --include
    pub exclude: Option<String>,    // -x, --exclude
    pub log: Option<PathBuf>,       // -f, --log
    pub csv: Toggle,                // --csv
}

/// Exiftool 配置 - 常用参数
#[derive(Clone, Debug, Default)]
pub struct ExiftoolConfig {
    pub all_tags: Toggle,         // -a, --all
    pub binary: Toggle,           // -b, --binary
    pub common: Toggle,           // -common
    pub json: Toggle,             // -json
    pub short: Toggle,            // -s, --short
    pub verbose: Toggle,          // -v, --verbose
    pub extract_embedded: Toggle, // -ee, --extractEmbedded
    pub unknown: Toggle,          // -u, --unknown
    pub duplicates: Toggle,       // -D, --duplicates
    pub group: Option<String>,    // -g, --group
    pub tags: Vec<String>,        // 指定标签
}

/// 外部工具集成器
pub struct ExternalTools {
    config: ExternalToolsConfig,
}

impl Default for ExternalTools {
    fn default() -> Self {
        Self::new(ExternalToolsConfig::default())
    }
}

impl ExternalTools {
    #[must_use]
    pub const fn new(config: ExternalToolsConfig) -> Self {
        Self { config }
    }

    /// 检查工具是否可用
    #[must_use]
    pub fn check_tool(
        &self,
        tool: &str,
    ) -> bool {
        tool_runner::resolve_program(tool).is_ok()
    }

    /// 运行 steghide extract
    ///
    /// # Errors
    ///
    /// 当执行 `steghide` 失败、超时或输出解析失败时返回错误。
    pub fn steghide_extract(
        &self,
        image: &Path,
        cfg: &SteghideConfig,
    ) -> Result<StegoResult> {
        let mut cmd = ToolCommand::new(self.config.steghide_path.clone());
        cmd.push_arg("extract").push_arg("-sf").push_arg(image);
        cmd.apply_limits(&self.config.resources.external_tools.for_tool("steghide"));

        if let Some(ref p) = cfg.passphrase {
            cmd.push_arg("-p").push_arg(p);
        } else {
            cmd.arg("-p").arg("");
        } // 尝试空密码
        if let Some(ref f) = cfg.extract_file {
            cmd.arg("-xf").arg(f);
        }
        if cfg.force.is_enabled() {
            cmd.arg("-f");
        }
        if cfg.quiet.is_enabled() {
            cmd.arg("-q");
        }
        if cfg.verbose.is_enabled() {
            cmd.arg("-v");
        }
        if let Some(z) = cfg.compression {
            cmd.arg("-z").arg(z.to_string());
        }
        if cfg.no_compression.is_enabled() {
            cmd.arg("-Z");
        }
        if cfg.checksum.is_enabled() {
            cmd.arg("-K");
        }
        if cfg.no_checksum.is_enabled() {
            cmd.arg("-N");
        }
        if let Some(ref name) = cfg.embed_name {
            cmd.arg("-n").arg(name);
        }

        let output = cmd.run()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut marker = String::new();
        if output.timed_out {
            marker.push_str(" [timeout]");
        }
        if output.stdout_truncated {
            marker.push_str(" [stdout 已截断]");
        }
        if output.stderr_truncated {
            marker.push_str(" [stderr 已截断]");
        }

        Ok(StegoResult {
            method: "steghide".to_string(),
            data: output.stdout.clone(),
            text: if stdout.is_empty() {
                None
            } else {
                Some(stdout.to_string())
            },
            confidence: if output.status.success() { 1.0 } else { 0.0 },
            description: format!("steghide: {stdout}{stderr}{marker}"),
        })
    }

    /// 运行 steghide info
    ///
    /// # Errors
    ///
    /// 当执行 `steghide` 失败或超时时返回错误。
    pub fn steghide_info(
        &self,
        image: &Path,
    ) -> Result<StegoResult> {
        let tool_limits = self.config.resources.external_tools.for_tool("steghide");
        let output = {
            let mut cmd = ToolCommand::new(self.config.steghide_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("info")
                .arg(image)
                .arg("-p")
                .arg("");
            cmd.run()?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.timed_out {
            anyhow::bail!("steghide 执行超时");
        }
        Ok(StegoResult {
            method: "steghide_info".to_string(),
            data: output.stdout.clone(),
            text: Some(stdout.to_string()),
            confidence: 0.8,
            description: "Steghide 文件信息".to_string(),
        })
    }

    /// 运行 zsteg
    ///
    /// # Errors
    ///
    /// 当执行 `zsteg` 失败或超时时返回错误。
    pub fn zsteg_analyze(
        &self,
        image: &Path,
        cfg: &ZstegConfig,
    ) -> Result<Vec<StegoResult>> {
        let mut cmd = ToolCommand::new(self.config.zsteg_path.clone());
        cmd.arg(image);
        cmd.apply_limits(&self.config.resources.external_tools.for_tool("zsteg"));

        if cfg.all.is_enabled() {
            cmd.arg("-a");
        }
        if cfg.verbose.is_enabled() {
            cmd.arg("-v");
        }
        if cfg.strings.is_enabled() {
            cmd.arg("-s");
        }
        if cfg.extra_checks.is_enabled() {
            cmd.arg("-E");
        }
        if cfg.prime.is_enabled() {
            cmd.arg("-p");
        }
        if cfg.invert.is_enabled() {
            cmd.arg("-i");
        }
        if let Some(ref c) = cfg.channels {
            cmd.arg("-c").arg(c);
        }
        if let Some(ref b) = cfg.bits {
            cmd.arg("-b").arg(b);
        }
        if let Some(ref o) = cfg.order {
            cmd.arg("-o").arg(o);
        }
        if let Some(l) = cfg.limit {
            cmd.arg("-l").arg(l.to_string());
        }
        if let Some(m) = cfg.min_str_len {
            cmd.arg("--min-str-len").arg(m.to_string());
        }

        let output = cmd.run()?;
        if output.timed_out {
            anyhow::bail!("zsteg 执行超时");
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let truncated = output.stdout_truncated;

        let mut results = Vec::new();
        for line in stdout.lines() {
            if line.contains("text:") || line.contains("flag") || line.contains("CTF") {
                results.push(StegoResult {
                    method: "zsteg".to_string(),
                    data: line.as_bytes().to_vec(),
                    text: Some(line.to_string()),
                    confidence: 0.9,
                    description: if truncated {
                        format!("{line} [stdout 已截断]")
                    } else {
                        line.to_string()
                    },
                });
            }
        }

        if results.is_empty() {
            results.push(StegoResult {
                method: "zsteg".to_string(),
                data: output.stdout.clone(),
                text: Some(stdout.to_string()),
                confidence: 0.5,
                description: if truncated {
                    "zsteg 输出（已截断）".to_string()
                } else {
                    "zsteg 输出".to_string()
                },
            });
        }

        Ok(results)
    }

    /// 运行 binwalk
    ///
    /// # Errors
    ///
    /// 当执行 `binwalk` 失败或超时时返回错误。
    pub fn binwalk_analyze(
        &self,
        file: &Path,
        cfg: &BinwalkConfig,
    ) -> Result<Vec<StegoResult>> {
        let mut cmd = ToolCommand::new(self.config.binwalk_path.clone());
        cmd.apply_limits(&self.config.resources.external_tools.for_tool("binwalk"));

        if cfg.signature.is_enabled() {
            cmd.arg("-B");
        }
        if cfg.opcodes.is_enabled() {
            cmd.arg("-A");
        }
        if cfg.entropy.is_enabled() {
            cmd.arg("-E");
        }
        if cfg.heuristic.is_enabled() {
            cmd.arg("-H");
        }
        if cfg.extract.is_enabled() {
            cmd.arg("-e");
        }
        if cfg.matryoshka.is_enabled() {
            cmd.arg("-M");
        }
        if cfg.quiet.is_enabled() {
            cmd.arg("-q");
        }
        if cfg.verbose.is_enabled() {
            cmd.arg("-v");
        }
        if cfg.csv.is_enabled() {
            cmd.arg("--csv");
        }
        if let Some(ref c) = cfg.cast {
            cmd.arg("-C").arg(c);
        }
        if let Some(ref log_path) = cfg.log {
            cmd.arg("-f").arg(log_path);
        }
        if let Some(d) = cfg.depth {
            cmd.arg("-d").arg(d.to_string());
        }
        if let Some(ref dir) = cfg.directory {
            cmd.arg("-C").arg(dir);
        }
        if let Some(o) = cfg.offset {
            cmd.arg("-o").arg(o.to_string());
        }
        if let Some(l) = cfg.length {
            cmd.arg("-l").arg(l.to_string());
        }
        if let Some(ref y) = cfg.include {
            cmd.arg("-y").arg(y);
        }
        if let Some(ref x) = cfg.exclude {
            cmd.arg("-x").arg(x);
        }
        if let Some(ref r) = cfg.raw {
            cmd.arg("-R").arg(r);
        }

        cmd.arg(file);

        let output = cmd.run()?;
        if output.timed_out {
            anyhow::bail!("binwalk 执行超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "binwalk 执行失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let truncated = output.stdout_truncated;

        let mut results = Vec::new();
        for line in stdout.lines() {
            if !line.trim().is_empty() && !line.starts_with("DECIMAL") {
                results.push(StegoResult {
                    method: "binwalk".to_string(),
                    data: line.as_bytes().to_vec(),
                    text: Some(line.to_string()),
                    confidence: 0.8,
                    description: if truncated {
                        format!("{line} [stdout 已截断]")
                    } else {
                        line.to_string()
                    },
                });
            }
        }

        Ok(results)
    }

    /// 运行 exiftool
    ///
    /// # Errors
    ///
    /// 当执行 `exiftool` 失败、超时或输出解析失败时返回错误。
    pub fn exiftool_analyze(
        &self,
        file: &Path,
        cfg: &ExiftoolConfig,
    ) -> Result<ExifData> {
        let mut cmd = ToolCommand::new(self.config.exiftool_path.clone());
        cmd.apply_limits(&self.config.resources.external_tools.for_tool("exiftool"));

        if cfg.all_tags.is_enabled() {
            cmd.arg("-a");
        }
        if cfg.binary.is_enabled() {
            cmd.arg("-b");
        }
        if cfg.common.is_enabled() {
            cmd.arg("-common");
        }
        if cfg.json.is_enabled() {
            cmd.arg("-json");
        }
        if cfg.short.is_enabled() {
            cmd.arg("-s");
        }
        if cfg.verbose.is_enabled() {
            cmd.arg("-v");
        }
        if cfg.extract_embedded.is_enabled() {
            cmd.arg("-ee");
        }
        if cfg.unknown.is_enabled() {
            cmd.arg("-u");
        }
        if cfg.duplicates.is_enabled() {
            cmd.arg("-D");
        }
        if let Some(ref g) = cfg.group {
            cmd.arg("-g").arg(g);
        }
        for tag in &cfg.tags {
            cmd.arg(format!("-{tag}"));
        }

        cmd.arg(file);

        let output = cmd.run()?;
        if output.timed_out {
            anyhow::bail!("exiftool 执行超时");
        }
        if cfg.json.is_enabled() && output.stdout_truncated {
            anyhow::bail!(
                "exiftool JSON 输出被截断（stdout_max_bytes={}），无法可靠解析；请提高资源上限或收紧提取范围",
                output.stdout_max_bytes
            );
        }
        if !output.status.success() {
            anyhow::bail!(
                "exiftool 执行失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut exif = ExifData::default();
        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once(':') {
                exif.entries
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok(exif)
    }

    /// 运行 strings
    ///
    /// # Errors
    ///
    /// 当执行 `strings` 失败或超时时返回错误。
    pub fn strings_extract(
        &self,
        file: &Path,
        min_len: usize,
    ) -> Result<Vec<String>> {
        let tool_limits = self.config.resources.external_tools.for_tool("strings");
        let output = {
            let mut cmd = ToolCommand::new(self.config.strings_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-n")
                .arg(min_len.to_string())
                .arg(file);
            cmd.run()?
        };
        if output.timed_out {
            anyhow::bail!("strings 执行超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "strings 执行失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut lines: Vec<String> = stdout.lines().map(str::to_owned).collect();
        if output.stdout_truncated {
            lines.push("[stdout 已截断]".to_string());
        }
        Ok(lines)
    }

    /// 综合分析 - 使用所有可用工具
    ///
    /// # Errors
    ///
    /// 当内置分析读取或解析失败时返回错误（外部工具失败会被吞掉并继续）。
    pub fn full_analysis(
        &self,
        file: &Path,
    ) -> Result<Vec<StegoResult>> {
        let mut results = Vec::new();

        // 内置分析
        let analyzer = StegoAnalyzer::new();
        if let Ok(r) = analyzer.analyze_file(file) {
            results.extend(r);
        }

        // zsteg (PNG)
        if self.check_tool("zsteg") {
            if let Ok(r) = self.zsteg_analyze(
                file,
                &ZstegConfig {
                    all: Toggle::Enabled,
                    ..Default::default()
                },
            ) {
                results.extend(r);
            }
        }

        // binwalk
        if self.check_tool("binwalk") {
            if let Ok(r) = self.binwalk_analyze(
                file,
                &BinwalkConfig {
                    signature: Toggle::Enabled,
                    ..Default::default()
                },
            ) {
                results.extend(r);
            }
        }

        // steghide (JPEG/BMP)
        if self.check_tool("steghide") {
            if let Ok(r) = self.steghide_info(file) {
                results.push(r);
            }
        }

        // exiftool
        if self.check_tool("exiftool") {
            if let Ok(exif) = self.exiftool_analyze(file, &ExiftoolConfig::default()) {
                for (k, v) in &exif.entries {
                    if v.to_lowercase().contains("flag") || v.to_lowercase().contains("ctf") {
                        results.push(StegoResult {
                            method: "exiftool".to_string(),
                            data: v.as_bytes().to_vec(),
                            text: Some(format!("{k}: {v}")),
                            confidence: 0.95,
                            description: format!("EXIF metadata: {k} = {v}"),
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_signature() {
        let png_sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(
            &png_sig[0..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
    }

    #[test]
    fn test_bytes_to_text() {
        let data = b"Hello World";
        assert_eq!(bytes_to_text(data), Some("Hello World".to_string()));

        let binary = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(bytes_to_text(&binary), None);
    }
}

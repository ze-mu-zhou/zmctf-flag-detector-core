//! PCAP 流量分析模块
//!
//! 支持 PCAP/PCAPNG 格式解析，HTTP/DNS/TCP 流重组

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use zmctf_constraints::{read_file_with_limit, ResourceLimits};

/// PCAP 文件头
const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;
const PCAPNG_MAGIC: u32 = 0x0a0d_0d0a;

/// 链路层类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    Ethernet,
    RawIP,
    LinuxSLL,
    Unknown(u32),
}

impl From<u32> for LinkType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Ethernet,
            101 => Self::RawIP,
            113 => Self::LinuxSLL,
            _ => Self::Unknown(v),
        }
    }
}

/// IP 协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpProtocol {
    ICMP,
    TCP,
    UDP,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::ICMP,
            6 => Self::TCP,
            17 => Self::UDP,
            _ => Self::Unknown(v),
        }
    }
}

/// 数据包信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub index: usize,
    pub timestamp: f64,
    pub length: u32,
    pub captured_length: u32,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<IpProtocol>,
    pub tcp_seq: Option<u32>,  // TCP 序号
    pub tcp_ack: Option<u32>,  // TCP 确认号
    pub tcp_flags: Option<u8>, // TCP 标志位
    pub payload: Vec<u8>,
}

/// TCP 流
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStream {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub data: Vec<u8>,
    pub packets: Vec<usize>,
}

/// TCP 分段 (内部使用)
#[derive(Debug, Clone)]
struct TcpSegment {
    seq: u32,
    data: Vec<u8>,
    pkt_index: usize,
}

/// HTTP 请求/响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMessage {
    pub is_request: bool,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// DNS 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub query: String,
    pub record_type: String,
    pub answer: Option<String>,
}

/// PCAP 分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapAnalysis {
    pub packet_count: usize,
    pub link_type: LinkType,
    pub duration: f64,
    pub packets: Vec<Packet>,
    pub tcp_streams: Vec<TcpStream>,
    pub http_messages: Vec<HttpMessage>,
    pub dns_records: Vec<DnsRecord>,
    pub extracted_strings: Vec<String>,
    pub flags: Vec<String>,
}

/// PCAP 分析器
#[derive(Clone, Default)]
pub enum TcpReassembly {
    #[default]
    Enabled,
    Disabled,
}

#[derive(Clone)]
pub struct PcapFeatures {
    pub extract_strings: bool,
    pub parse_http: bool,
    pub parse_dns: bool,
    pub tcp_reassembly: TcpReassembly,
}

impl Default for PcapFeatures {
    fn default() -> Self {
        Self {
            extract_strings: true,
            parse_http: true,
            parse_dns: true,
            tcp_reassembly: TcpReassembly::Enabled,
        }
    }
}

pub struct PcapAnalyzer {
    pub features: PcapFeatures,
    pub max_packets: usize,
    pub resources: ResourceLimits,
}

impl Default for PcapAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            features: PcapFeatures::default(),
            max_packets: 100_000,
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

    /// 分析 PCAP 文件
    ///
    /// # Errors
    ///
    /// - 当读取文件失败或超过输入大小上限时返回错误。
    /// - 当 PCAP/PCAPNG 解析失败时返回错误。
    pub fn analyze_file(
        &self,
        path: &Path,
    ) -> Result<PcapAnalysis> {
        let data = read_file_with_limit(path, self.resources.input_max_bytes)?;
        self.analyze_bytes(&data)
    }

    /// 分析 PCAP 字节
    ///
    /// # Errors
    ///
    /// 当 PCAP/PCAPNG 解析失败或输入数据过短时返回错误。
    pub fn analyze_bytes(
        &self,
        data: &[u8],
    ) -> Result<PcapAnalysis> {
        if data.len() < 24 {
            anyhow::bail!("数据过短，无法解析 PCAP");
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match magic {
            PCAP_MAGIC_LE => Ok(self.parse_pcap(data, false)),
            PCAP_MAGIC_BE => Ok(self.parse_pcap(data, true)),
            PCAPNG_MAGIC => Ok(self.parse_pcapng(data)),
            _ => anyhow::bail!("未知的 PCAP 格式: {magic:08x}"),
        }
    }

    /// 解析 PCAP 格式
    fn parse_pcap(
        &self,
        data: &[u8],
        big_endian: bool,
    ) -> PcapAnalysis {
        let link_type = LinkType::from(Self::read_u32_endian(big_endian, &data[20..24]));
        let (packets, duration) = self.parse_pcap_packet_records(data, big_endian, link_type);
        self.build_analysis(link_type, duration, packets)
    }

    /// 解析 PCAPNG 格式
    fn parse_pcapng(
        &self,
        data: &[u8],
    ) -> PcapAnalysis {
        let (link_type, packets) = self.parse_pcapng_blocks(data);
        self.build_analysis(link_type, 0.0, packets)
    }

    fn build_analysis(
        &self,
        link_type: LinkType,
        duration: f64,
        packets: Vec<Packet>,
    ) -> PcapAnalysis {
        let tcp_streams = if matches!(self.features.tcp_reassembly, TcpReassembly::Enabled) {
            Self::reassemble_tcp_streams(&packets)
        } else {
            Vec::new()
        };

        let http_messages = if self.features.parse_http {
            Self::extract_http(&tcp_streams)
        } else {
            Vec::new()
        };

        let dns_records = if self.features.parse_dns {
            Self::extract_dns(&packets)
        } else {
            Vec::new()
        };

        let (extracted_strings, flags) = if self.features.extract_strings {
            Self::extract_strings_and_flags(&packets, &tcp_streams)
        } else {
            (Vec::new(), Vec::new())
        };

        let packet_count = packets.len();
        PcapAnalysis {
            packet_count,
            link_type,
            duration,
            packets,
            tcp_streams,
            http_messages,
            dns_records,
            extracted_strings,
            flags,
        }
    }

    fn parse_pcap_packet_records(
        &self,
        data: &[u8],
        big_endian: bool,
        link_type: LinkType,
    ) -> (Vec<Packet>, f64) {
        let mut packets = Vec::new();
        let mut offset = 24usize;
        let mut first_ts: Option<f64> = None;
        let mut last_ts: f64 = 0.0;

        while packets.len() < self.max_packets {
            let Some((packet, next_offset, timestamp)) =
                Self::parse_next_pcap_record(data, big_endian, link_type, offset, packets.len())
            else {
                break;
            };

            if first_ts.is_none() {
                first_ts = Some(timestamp);
            }
            last_ts = timestamp;
            packets.push(packet);
            offset = next_offset;
        }

        let duration = last_ts - first_ts.unwrap_or(0.0);
        (packets, duration)
    }

    fn parse_next_pcap_record(
        data: &[u8],
        big_endian: bool,
        link_type: LinkType,
        offset: usize,
        index: usize,
    ) -> Option<(Packet, usize, f64)> {
        if offset + 16 > data.len() {
            return None;
        }

        let timestamp_seconds = Self::read_u32_endian(big_endian, &data[offset..offset + 4]);
        let timestamp_microseconds =
            Self::read_u32_endian(big_endian, &data[offset + 4..offset + 8]);
        let captured_len = Self::read_u32_endian(big_endian, &data[offset + 8..offset + 12]);
        let original_len = Self::read_u32_endian(big_endian, &data[offset + 12..offset + 16]);

        let timestamp =
            f64::from(timestamp_seconds) + f64::from(timestamp_microseconds) / 1_000_000.0;

        let pkt_start = offset + 16;
        let pkt_end = pkt_start.saturating_add(usize::try_from(captured_len).ok()?);
        if pkt_end > data.len() {
            return None;
        }

        let pkt_data = &data[pkt_start..pkt_end];
        let mut packet = Packet {
            index,
            timestamp,
            length: original_len,
            captured_length: captured_len,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
        };

        Self::fill_packet_from_link_payload(&mut packet, pkt_data, link_type);
        Some((packet, pkt_end, timestamp))
    }

    fn parse_pcapng_blocks(
        &self,
        data: &[u8],
    ) -> (LinkType, Vec<Packet>) {
        let mut packets = Vec::new();
        let mut offset = 0usize;
        let mut link_type = LinkType::Ethernet;

        while offset + 8 <= data.len() && packets.len() < self.max_packets {
            let block_type = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let block_len = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if block_len < 12 || offset + block_len > data.len() {
                break;
            }

            match block_type {
                0x0000_0001 => {
                    if block_len >= 20 {
                        let lt = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);
                        link_type = LinkType::from(u32::from(lt));
                    }
                }
                0x0000_0006 => {
                    if let Some(packet) = Self::parse_pcapng_enhanced_packet(
                        data,
                        offset,
                        block_len,
                        link_type,
                        packets.len(),
                    ) {
                        packets.push(packet);
                    }
                }
                _ => {}
            }

            offset = offset.saturating_add(block_len);
        }

        (link_type, packets)
    }

    fn parse_pcapng_enhanced_packet(
        data: &[u8],
        offset: usize,
        block_len: usize,
        link_type: LinkType,
        index: usize,
    ) -> Option<Packet> {
        if block_len < 32 {
            return None;
        }

        let captured_len = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]);
        let original_len = u32::from_le_bytes([
            data[offset + 24],
            data[offset + 25],
            data[offset + 26],
            data[offset + 27],
        ]);

        let pkt_start = offset + 28;
        let pkt_end = pkt_start.saturating_add(usize::try_from(captured_len).ok()?);
        if pkt_end > data.len() {
            return None;
        }

        let pkt_data = &data[pkt_start..pkt_end];
        let mut packet = Packet {
            index,
            timestamp: 0.0,
            length: original_len,
            captured_length: captured_len,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            payload: Vec::new(),
        };
        Self::fill_packet_from_link_payload(&mut packet, pkt_data, link_type);
        Some(packet)
    }

    fn fill_packet_from_link_payload(
        packet: &mut Packet,
        pkt_data: &[u8],
        link_type: LinkType,
    ) {
        let Some(ip_off) = Self::ip_offset(pkt_data, link_type) else {
            return;
        };
        if pkt_data.len() <= ip_off {
            return;
        }
        Self::parse_ipv4_packet(packet, &pkt_data[ip_off..]);
    }

    fn ip_offset(
        pkt_data: &[u8],
        link_type: LinkType,
    ) -> Option<usize> {
        match link_type {
            LinkType::Ethernet => {
                if pkt_data.len() < 14 {
                    return None;
                }
                let ethertype = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
                (ethertype == 0x0800).then_some(14)
            }
            LinkType::RawIP => Some(0),
            LinkType::LinuxSLL => (pkt_data.len() >= 16).then_some(16),
            LinkType::Unknown(_) => None,
        }
    }

    fn parse_ipv4_packet(
        packet: &mut Packet,
        ip_data: &[u8],
    ) {
        if ip_data.len() < 20 {
            return;
        }

        let version = (ip_data[0] >> 4) & 0x0f;
        if version != 4 {
            return;
        }

        let ihl = (ip_data[0] & 0x0f) as usize * 4;
        if ip_data.len() < ihl + 4 {
            return;
        }

        packet.src_ip = Some(format!(
            "{}.{}.{}.{}",
            ip_data[12], ip_data[13], ip_data[14], ip_data[15]
        ));
        packet.dst_ip = Some(format!(
            "{}.{}.{}.{}",
            ip_data[16], ip_data[17], ip_data[18], ip_data[19]
        ));

        let protocol = IpProtocol::from(ip_data[9]);
        packet.protocol = Some(protocol);

        let transport = &ip_data[ihl..];
        match protocol {
            IpProtocol::TCP => Self::parse_tcp(packet, transport),
            IpProtocol::UDP => Self::parse_udp(packet, transport),
            _ => {}
        }
    }

    fn parse_tcp(
        packet: &mut Packet,
        transport: &[u8],
    ) {
        if transport.len() < 20 {
            return;
        }
        packet.src_port = Some(u16::from_be_bytes([transport[0], transport[1]]));
        packet.dst_port = Some(u16::from_be_bytes([transport[2], transport[3]]));
        packet.tcp_seq = Some(u32::from_be_bytes([
            transport[4],
            transport[5],
            transport[6],
            transport[7],
        ]));
        packet.tcp_ack = Some(u32::from_be_bytes([
            transport[8],
            transport[9],
            transport[10],
            transport[11],
        ]));
        packet.tcp_flags = Some(transport[13]);

        let header_len = ((transport[12] >> 4) as usize) * 4;
        if transport.len() > header_len {
            packet.payload = transport[header_len..].to_vec();
        }
    }

    fn parse_udp(
        packet: &mut Packet,
        transport: &[u8],
    ) {
        if transport.len() < 8 {
            return;
        }
        packet.src_port = Some(u16::from_be_bytes([transport[0], transport[1]]));
        packet.dst_port = Some(u16::from_be_bytes([transport[2], transport[3]]));
        if transport.len() > 8 {
            packet.payload = transport[8..].to_vec();
        }
    }

    fn extract_strings_and_flags(
        packets: &[Packet],
        tcp_streams: &[TcpStream],
    ) -> (Vec<String>, Vec<String>) {
        let mut extracted_strings = Vec::new();
        let mut flags = Vec::new();

        for stream in tcp_streams {
            let strings = extract_printable_strings(&stream.data);
            for s in &strings {
                if is_flag_pattern(s) {
                    flags.push(s.clone());
                }
            }
            extracted_strings.extend(strings);
        }

        for pkt in packets {
            if pkt.payload.is_empty() {
                continue;
            }
            let strings = extract_printable_strings(&pkt.payload);
            for s in &strings {
                if is_flag_pattern(s) {
                    flags.push(s.clone());
                }
            }
            extracted_strings.extend(strings);
        }

        flags.sort();
        flags.dedup();
        (extracted_strings, flags)
    }

    fn read_u32_endian(
        big_endian: bool,
        bytes: &[u8],
    ) -> u32 {
        if big_endian {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
    }

    /// TCP 流重组 - 基于序号排序
    fn reassemble_tcp_streams(packets: &[Packet]) -> Vec<TcpStream> {
        // 收集每个流的分段
        let mut stream_segments: HashMap<String, Vec<TcpSegment>> = HashMap::new();

        for pkt in packets {
            if pkt.protocol != Some(IpProtocol::TCP) {
                continue;
            }

            let (Some(src_ip), Some(dst_ip)) = (&pkt.src_ip, &pkt.dst_ip) else {
                continue;
            };

            let (Some(src_port), Some(dst_port)) = (pkt.src_port, pkt.dst_port) else {
                continue;
            };

            let Some(seq) = pkt.tcp_seq else {
                continue;
            };

            // 跳过无数据的包 (SYN/FIN/ACK only)
            if pkt.payload.is_empty() {
                continue;
            }

            // 双向流使用排序后的 key
            let key = if (src_ip.as_str(), src_port) < (dst_ip.as_str(), dst_port) {
                format!("{src_ip}:{src_port}-{dst_ip}:{dst_port}")
            } else {
                format!("{dst_ip}:{dst_port}-{src_ip}:{src_port}")
            };

            let segments = stream_segments.entry(key).or_default();
            segments.push(TcpSegment {
                seq,
                data: pkt.payload.clone(),
                pkt_index: pkt.index,
            });
        }

        // 重组每个流
        let mut streams = Vec::new();
        for (key, mut segments) in stream_segments {
            // 按序号排序
            segments.sort_by_key(|s| s.seq);

            // 去重 (处理重传)
            let mut seen_ranges: Vec<(u32, u32)> = Vec::new();
            let mut unique_segments = Vec::new();

            for seg in segments {
                let len = u32::try_from(seg.data.len()).unwrap_or(u32::MAX);
                let end = seg.seq.wrapping_add(len);
                let overlaps = seen_ranges.iter().any(|&(s, e)| {
                    // 检查是否完全重叠
                    seg.seq >= s && end <= e
                });

                if !overlaps && !seg.data.is_empty() {
                    seen_ranges.push((seg.seq, end));
                    unique_segments.push(seg);
                }
            }

            // 拼接数据
            let mut data = Vec::new();
            let mut packet_indices = Vec::new();

            for seg in &unique_segments {
                data.extend(&seg.data);
                packet_indices.push(seg.pkt_index);
            }

            if data.is_empty() {
                continue;
            }

            // 解析 key 获取地址信息
            let parts: Vec<&str> = key.split('-').collect();
            if parts.len() != 2 {
                continue;
            }
            let src_parts: Vec<&str> = parts[0].rsplitn(2, ':').collect();
            let dst_parts: Vec<&str> = parts[1].rsplitn(2, ':').collect();

            if src_parts.len() != 2 || dst_parts.len() != 2 {
                continue;
            }

            streams.push(TcpStream {
                src: src_parts[1].to_string(),
                dst: dst_parts[1].to_string(),
                src_port: src_parts[0].parse().unwrap_or(0),
                dst_port: dst_parts[0].parse().unwrap_or(0),
                data,
                packets: packet_indices,
            });
        }

        streams
    }

    /// 提取 HTTP 消息
    fn extract_http(streams: &[TcpStream]) -> Vec<HttpMessage> {
        let mut messages = Vec::new();

        for stream in streams {
            if stream.dst_port != 80
                && stream.dst_port != 8080
                && stream.src_port != 80
                && stream.src_port != 8080
            {
                continue;
            }

            if let Ok(text) = std::str::from_utf8(&stream.data) {
                for part in text.split("\r\n\r\n") {
                    if let Some(msg) = parse_http_message(part) {
                        messages.push(msg);
                    }
                }
            }
        }

        messages
    }

    /// 提取 DNS 记录
    fn extract_dns(packets: &[Packet]) -> Vec<DnsRecord> {
        let mut records = Vec::new();

        for pkt in packets {
            if pkt.protocol != Some(IpProtocol::UDP) {
                continue;
            }

            if pkt.src_port != Some(53) && pkt.dst_port != Some(53) {
                continue;
            }

            if pkt.payload.len() < 12 {
                continue;
            }

            if let Some(record) = parse_dns_packet(&pkt.payload) {
                records.push(record);
            }
        }

        records
    }
}

/// 解析 HTTP 消息
fn parse_http_message(text: &str) -> Option<HttpMessage> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return None;
    }

    let first_line = lines[0];
    let mut msg = HttpMessage {
        is_request: false,
        method: None,
        uri: None,
        status_code: None,
        headers: HashMap::new(),
        body: Vec::new(),
    };

    // 检查是请求还是响应
    if first_line.starts_with("HTTP/") {
        // 响应
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            msg.status_code = parts[1].parse().ok();
        }
    } else if first_line.contains("HTTP/") {
        // 请求
        msg.is_request = true;
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            msg.method = Some(parts[0].to_string());
            msg.uri = Some(parts[1].to_string());
        }
    } else {
        return None;
    }

    // 解析头部
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            msg.headers
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Some(msg)
}

/// 解析 DNS 数据包
fn parse_dns_packet(data: &[u8]) -> Option<DnsRecord> {
    if data.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }

    // 解析查询名称
    let mut offset = 12;
    let mut name_parts = Vec::new();

    while offset < data.len() {
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if offset + 1 + len > data.len() {
            break;
        }
        if let Ok(part) = String::from_utf8(data[offset + 1..offset + 1 + len].to_vec()) {
            name_parts.push(part);
        }
        offset += 1 + len;
    }

    if name_parts.is_empty() {
        return None;
    }

    let query = name_parts.join(".");

    // 解析类型
    let record_type = if offset + 2 <= data.len() {
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        match qtype {
            1 => "A".to_string(),
            5 => "CNAME".to_string(),
            15 => "MX".to_string(),
            16 => "TXT".to_string(),
            28 => "AAAA".to_string(),
            _ => format!("TYPE{qtype}"),
        }
    } else {
        "未知".to_string()
    };

    Some(DnsRecord {
        query,
        record_type,
        answer: None,
    })
}

/// 提取可打印字符串
fn extract_printable_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if (0x20..=0x7e).contains(&byte) {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }

    if current.len() >= 4 {
        strings.push(current);
    }

    strings
}

/// 检查是否为 flag 模式
fn is_flag_pattern(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("flag{") || lower.contains("ctf{") || lower.contains("key{")
}

/// 便捷函数：分析 PCAP 文件。
///
/// # Errors
///
/// 当读取文件或解析失败时返回错误。
pub fn analyze_pcap(path: &Path) -> Result<PcapAnalysis> {
    PcapAnalyzer::new().analyze_file(path)
}

/// 便捷函数：分析 PCAP 字节。
///
/// # Errors
///
/// 当解析失败时返回错误。
pub fn analyze_pcap_bytes(data: &[u8]) -> Result<PcapAnalysis> {
    PcapAnalyzer::new().analyze_bytes(data)
}

// ============================================================================
// 外部工具集成 - tshark, tcpdump
// ============================================================================

use std::path::PathBuf;
use tool_runner::ToolCommand;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TsharkOutputFormat {
    #[default]
    Default,
    Json,
    Pdml,
    Psml,
    Ek,
    Fields,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TsharkVerbosity {
    #[default]
    Normal,
    Verbose,
    Quiet,
}

#[derive(Clone, Debug)]
pub struct TsharkOutputOptions {
    pub format: TsharkOutputFormat,
    pub fields: Vec<String>,
    pub separator: Option<String>,
    pub verbosity: TsharkVerbosity,
    pub color: bool,
    pub print_hex: bool,
}

impl Default for TsharkOutputOptions {
    fn default() -> Self {
        Self {
            format: TsharkOutputFormat::Default,
            fields: Vec::new(),
            separator: None,
            verbosity: TsharkVerbosity::Normal,
            color: false,
            print_hex: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TsharkNameResolution {
    pub disable: bool,
    pub spec: Option<String>,
}

impl Default for TsharkNameResolution {
    fn default() -> Self {
        Self {
            disable: true,
            spec: None,
        }
    }
}

/// Tshark 配置 - 100% 常用CLI参数覆盖
#[derive(Clone, Debug)]
pub struct TsharkConfig {
    pub tshark_path: PathBuf,
    /// 全局资源与安全约束（timeout/stdout/stderr 上限等）。
    pub resources: ResourceLimits,

    // === 输入 ===
    pub interface: Option<String>,      // -i, --interface
    pub read_file: Option<PathBuf>,     // -r, --read-file
    pub read_filter: Option<String>,    // -R, --read-filter (display filter)
    pub capture_filter: Option<String>, // -f, --capture-filter (BPF)

    // === 输出与通用行为 ===
    pub output: TsharkOutputOptions,

    // === 过滤 ===
    pub display_filter: Option<String>, // -Y, --display-filter
    pub decode_as: Option<String>,      // -d, --decode-as

    // === 输出控制 ===
    pub count: Option<u32>,             // -c, --count
    pub autostop_duration: Option<u32>, // -a duration:
    pub autostop_filesize: Option<u32>, // -a filesize:
    pub autostop_packets: Option<u32>,  // -a packets:

    // === 协议解析 ===
    pub disable_protocol: Vec<String>,  // --disable-protocol
    pub enable_protocol: Vec<String>,   // --enable-protocol
    pub disable_heuristic: Vec<String>, // --disable-heuristic

    // === 统计 ===
    pub statistics: Option<String>,     // -z, --statistics
    pub export_objects: Option<String>, // --export-objects (http,smb,imf,tftp,dicom)

    // === 其他 ===
    pub name_resolution: TsharkNameResolution, // -n / -N
}

impl Default for TsharkConfig {
    fn default() -> Self {
        Self {
            tshark_path: PathBuf::from("tshark"),
            resources: ResourceLimits::default(),
            interface: None,
            read_file: None,
            read_filter: None,
            capture_filter: None,
            output: TsharkOutputOptions::default(),
            display_filter: None,
            decode_as: None,
            count: None,
            autostop_duration: None,
            autostop_filesize: None,
            autostop_packets: None,
            disable_protocol: Vec::new(),
            enable_protocol: Vec::new(),
            disable_heuristic: Vec::new(),
            statistics: None,
            export_objects: None,
            name_resolution: TsharkNameResolution::default(),
        }
    }
}

/// Tshark 集成器
pub struct Tshark {
    config: TsharkConfig,
}

impl Default for Tshark {
    fn default() -> Self {
        Self::new(TsharkConfig::default())
    }
}

impl Tshark {
    #[must_use]
    pub const fn new(config: TsharkConfig) -> Self {
        Self { config }
    }

    /// 检查 tshark 是否可用
    #[must_use]
    pub fn is_available(&self) -> bool {
        tool_runner::resolve_program(&self.config.tshark_path).is_ok()
    }

    /// 获取版本
    ///
    /// # Errors
    ///
    /// 当外部工具执行失败时返回错误。
    pub fn version(&self) -> Result<String> {
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        let output = {
            let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("--version")
                .stdout_max_bytes(16 * 1024)
                .stderr_max_bytes(16 * 1024);
            cmd.run()?
        };
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string())
    }

    /// 构建命令
    fn build_command(&self) -> ToolCommand {
        let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        cmd.apply_limits(&tool_limits);

        // 输入
        if let Some(ref i) = self.config.interface {
            cmd.push_arg("-i").push_arg(i.as_str());
        }
        if let Some(ref r) = self.config.read_file {
            cmd.push_arg("-r").push_arg(r.as_os_str());
        }
        if let Some(ref f) = self.config.capture_filter {
            cmd.push_arg("-f").push_arg(f.as_str());
        }

        // 输出格式
        match self.config.output.format {
            TsharkOutputFormat::Default => {}
            TsharkOutputFormat::Json => {
                cmd.push_arg("-T").push_arg("json");
            }
            TsharkOutputFormat::Pdml => {
                cmd.push_arg("-T").push_arg("pdml");
            }
            TsharkOutputFormat::Psml => {
                cmd.push_arg("-T").push_arg("psml");
            }
            TsharkOutputFormat::Ek => {
                cmd.push_arg("-T").push_arg("ek");
            }
            TsharkOutputFormat::Fields => {
                cmd.push_arg("-T").push_arg("fields");
                for f in &self.config.output.fields {
                    cmd.push_arg("-e").push_arg(f.as_str());
                }
                if let Some(ref s) = self.config.output.separator {
                    cmd.push_arg("-E").push_arg(format!("separator={s}"));
                }
            }
        }

        // 过滤
        if let Some(ref y) = self.config.display_filter {
            cmd.push_arg("-Y").push_arg(y.as_str());
        }
        if let Some(ref r) = self.config.read_filter {
            cmd.push_arg("-R").push_arg(r.as_str());
        }
        if let Some(ref d) = self.config.decode_as {
            cmd.push_arg("-d").push_arg(d.as_str());
        }

        // 输出控制
        match self.config.output.verbosity {
            TsharkVerbosity::Normal => {}
            TsharkVerbosity::Verbose => {
                cmd.push_arg("-V");
            }
            TsharkVerbosity::Quiet => {
                cmd.push_arg("-q");
            }
        }
        if let Some(c) = self.config.count {
            cmd.push_arg("-c").push_arg(c.to_string());
        }
        if let Some(d) = self.config.autostop_duration {
            cmd.push_arg("-a").push_arg(format!("duration:{d}"));
        }
        if let Some(s) = self.config.autostop_filesize {
            cmd.push_arg("-a").push_arg(format!("filesize:{s}"));
        }
        if let Some(p) = self.config.autostop_packets {
            cmd.push_arg("-a").push_arg(format!("packets:{p}"));
        }

        // 协议
        for p in &self.config.disable_protocol {
            cmd.push_arg("--disable-protocol").push_arg(p.as_str());
        }
        for p in &self.config.enable_protocol {
            cmd.push_arg("--enable-protocol").push_arg(p.as_str());
        }
        for h in &self.config.disable_heuristic {
            cmd.push_arg("--disable-heuristic").push_arg(h.as_str());
        }

        // 统计
        if let Some(ref z) = self.config.statistics {
            cmd.push_arg("-z").push_arg(z.as_str());
        }
        if let Some(ref e) = self.config.export_objects {
            cmd.push_arg("--export-objects").push_arg(e.as_str());
        }

        // 其他
        if self.config.name_resolution.disable {
            cmd.push_arg("-n");
        }
        if let Some(ref n) = self.config.name_resolution.spec {
            cmd.push_arg("-N").push_arg(n.as_str());
        }
        if self.config.output.color {
            cmd.push_arg("--color");
        }
        if self.config.output.print_hex {
            cmd.push_arg("-x");
        }

        cmd
    }

    /// 分析 PCAP 文件
    ///
    /// # Errors
    ///
    /// 当外部工具执行失败或输出解析失败时返回错误。
    pub fn analyze_file(
        &self,
        pcap_path: &Path,
    ) -> Result<TsharkResult> {
        let mut config = self.config.clone();
        config.read_file = Some(pcap_path.to_path_buf());
        let tshark = Self::new(config);

        let output = tshark.build_command().run()?;
        let expects_structured = matches!(
            tshark.config.output.format,
            TsharkOutputFormat::Json
                | TsharkOutputFormat::Pdml
                | TsharkOutputFormat::Psml
                | TsharkOutputFormat::Ek
                | TsharkOutputFormat::Fields
        );
        if expects_structured && output.stdout_truncated {
            anyhow::bail!(
                "tshark 输出被截断（stdout_max_bytes={}），无法可靠处理结构化输出；请提高资源上限或收紧过滤条件",
                output.stdout_max_bytes
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let truncation = TsharkTruncation {
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
        };
        Ok(TsharkResult {
            success: output.status.success() && !output.timed_out,
            output: stdout.to_string(),
            error: if output.timed_out {
                Some("tshark 执行超时".to_string())
            } else if stderr.is_empty() {
                None
            } else {
                Some(stderr.to_string())
            },
            packets: Vec::new(), // 需要解析
            timed_out: output.timed_out,
            truncation,
            elapsed_ms: u64::try_from(output.elapsed.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// 提取特定字段
    ///
    /// # Errors
    ///
    /// - 当执行 `tshark` 失败或超时时返回错误。
    /// - 当输出被截断导致无法可靠解析时返回错误。
    pub fn extract_fields(
        &self,
        pcap_path: &Path,
        fields: &[&str],
    ) -> Result<Vec<Vec<String>>> {
        let mut config = self.config.clone();
        config.read_file = Some(pcap_path.to_path_buf());
        config.output.format = TsharkOutputFormat::Fields;
        config.output.fields = fields.iter().map(ToString::to_string).collect();
        config.output.separator = Some("|".to_string());
        let tshark = Self::new(config);

        let output = tshark.build_command().run()?;
        if output.timed_out {
            anyhow::bail!("tshark 执行超时");
        }
        if output.stdout_truncated {
            anyhow::bail!(
                "tshark 输出被截断（stdout_max_bytes={}），无法可靠解析字段输出",
                output.stdout_max_bytes
            );
        }
        if !output.status.success() {
            anyhow::bail!(
                "tshark 执行失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut results = Vec::new();

        for line in stdout.lines() {
            if !line.trim().is_empty() {
                results.push(line.split('|').map(str::to_owned).collect());
            }
        }

        Ok(results)
    }

    /// 导出 HTTP 对象
    ///
    /// # Errors
    ///
    /// 当执行 `tshark` 或读取输出目录失败时返回错误。
    pub fn export_http_objects(
        &self,
        pcap_path: &Path,
        output_dir: &Path,
    ) -> Result<Vec<PathBuf>> {
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        let output = {
            let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-r")
                .arg(pcap_path.as_os_str())
                .arg("--export-objects")
                .arg(format!("http,{}", output_dir.display()))
                .arg("-q")
                .stdout_max_bytes(16 * 1024)
                .stderr_max_bytes(16 * 1024);
            cmd.run()?
        };
        if output.timed_out {
            anyhow::bail!("tshark 导出 HTTP 对象超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "tshark 导出 HTTP 对象失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // 列出导出的文件
        let mut files = Vec::new();
        if output_dir.exists() {
            for e in std::fs::read_dir(output_dir)?.flatten() {
                files.push(e.path());
            }
        }

        Ok(files)
    }

    /// 获取协议统计
    ///
    /// # Errors
    ///
    /// 当执行 `tshark` 失败或超时时返回错误。
    pub fn protocol_hierarchy(
        &self,
        pcap_path: &Path,
    ) -> Result<String> {
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        let output = {
            let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-r")
                .arg(pcap_path.as_os_str())
                .arg("-q")
                .arg("-z")
                .arg("io,phs");
            cmd.run()?
        };
        if output.timed_out {
            anyhow::bail!("tshark 获取协议统计超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "tshark 获取协议统计失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut s = String::from_utf8_lossy(&output.stdout).to_string();
        if output.stdout_truncated {
            s.push_str("\n[stdout 已截断]");
        }
        Ok(s)
    }

    /// 获取会话统计
    ///
    /// # Errors
    ///
    /// 当执行 `tshark` 失败或超时时返回错误。
    pub fn conversations(
        &self,
        pcap_path: &Path,
        protocol: &str,
    ) -> Result<String> {
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        let output = {
            let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-r")
                .arg(pcap_path.as_os_str())
                .arg("-q")
                .arg("-z")
                .arg(format!("conv,{protocol}"));
            cmd.run()?
        };
        if output.timed_out {
            anyhow::bail!("tshark 获取会话统计超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "tshark 获取会话统计失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut s = String::from_utf8_lossy(&output.stdout).to_string();
        if output.stdout_truncated {
            s.push_str("\n[stdout 已截断]");
        }
        Ok(s)
    }

    /// 跟踪 TCP 流
    ///
    /// # Errors
    ///
    /// 当执行 `tshark` 失败或超时时返回错误。
    pub fn follow_tcp_stream(
        &self,
        pcap_path: &Path,
        stream_index: u32,
    ) -> Result<String> {
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        let output = {
            let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-r")
                .arg(pcap_path.as_os_str())
                .arg("-q")
                .arg("-z")
                .arg(format!("follow,tcp,ascii,{stream_index}"));
            cmd.run()?
        };
        if output.timed_out {
            anyhow::bail!("tshark 跟踪 TCP 流超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "tshark 跟踪 TCP 流失败: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut s = String::from_utf8_lossy(&output.stdout).to_string();
        if output.stdout_truncated {
            s.push_str("\n[stdout 已截断]");
        }
        Ok(s)
    }

    /// 搜索包含特定字符串的包
    ///
    /// # Errors
    ///
    /// 当执行 `tshark` 失败或超时时返回错误。
    pub fn search_string(
        &self,
        pcap_path: &Path,
        pattern: &str,
    ) -> Result<Vec<String>> {
        let tool_limits = self.config.resources.external_tools.for_tool("tshark");
        let output = {
            let mut cmd = ToolCommand::new(self.config.tshark_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-r")
                .arg(pcap_path.as_os_str())
                .arg("-Y")
                .arg(format!("frame contains \"{pattern}\""));
            cmd.run()?
        };
        if output.timed_out {
            anyhow::bail!("tshark 搜索字符串超时");
        }
        if !output.status.success() {
            anyhow::bail!(
                "tshark 搜索字符串失败: {}",
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
}

/// Tshark 分析结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TsharkTruncation {
    #[serde(default)]
    pub stdout_truncated: bool,
    #[serde(default)]
    pub stderr_truncated: bool,
}

/// Tshark 分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsharkResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub packets: Vec<TsharkPacket>,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(flatten)]
    pub truncation: TsharkTruncation,
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// Tshark 包信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsharkPacket {
    pub number: u32,
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16_le(
        out: &mut Vec<u8>,
        v: u16,
    ) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u32_le(
        out: &mut Vec<u8>,
        v: u32,
    ) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_pcap_le_global_header(
        out: &mut Vec<u8>,
        link_type: u32,
    ) {
        out.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]); // PCAP_MAGIC_LE
        push_u16_le(out, 2); // major
        push_u16_le(out, 4); // minor
        push_u32_le(out, 0); // thiszone
        push_u32_le(out, 0); // sigfigs
        push_u32_le(out, 65_535); // snaplen
        push_u32_le(out, link_type); // network
    }

    fn push_pcap_le_record(
        out: &mut Vec<u8>,
        timestamp_seconds: u32,
        timestamp_microseconds: u32,
        pkt: &[u8],
    ) {
        let incl_len = u32::try_from(pkt.len()).unwrap_or(u32::MAX);
        push_u32_le(out, timestamp_seconds);
        push_u32_le(out, timestamp_microseconds);
        push_u32_le(out, incl_len);
        push_u32_le(out, incl_len);
        out.extend_from_slice(pkt);
    }

    #[must_use]
    fn ethernet_ipv4_packet(
        protocol: u8,
        l4_payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header (dest/src MAC + ethertype)
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype

        // IPv4 header (minimal 20 bytes)
        let total_len = u16::try_from(20 + l4_payload.len()).unwrap_or(u16::MAX);
        pkt.push(0x45); // version=4, ihl=5
        pkt.push(0); // dscp/ecn
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
        pkt.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment
        pkt.push(64); // ttl
        pkt.push(protocol);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (ignored)
        pkt.extend_from_slice(&[1, 2, 3, 4]); // src ip
        pkt.extend_from_slice(&[5, 6, 7, 8]); // dst ip

        pkt.extend_from_slice(l4_payload);
        pkt
    }

    #[must_use]
    fn udp_payload(
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // checksum
        out.extend_from_slice(payload);
        out
    }

    #[must_use]
    fn tcp_payload(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // ack
        out.push(0x50); // data offset=5
        out.push(0x18); // flags: PSH+ACK
        out.extend_from_slice(&0u16.to_be_bytes()); // window
        out.extend_from_slice(&0u16.to_be_bytes()); // checksum
        out.extend_from_slice(&0u16.to_be_bytes()); // urgent
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn test_link_type() {
        assert_eq!(LinkType::from(1), LinkType::Ethernet);
        assert_eq!(LinkType::from(101), LinkType::RawIP);
    }

    #[test]
    fn test_ip_protocol() {
        assert_eq!(IpProtocol::from(6), IpProtocol::TCP);
        assert_eq!(IpProtocol::from(17), IpProtocol::UDP);
    }

    #[test]
    fn test_extract_strings() {
        let data = b"hello\x00world\x00flag{test}";
        let strings = extract_printable_strings(data);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
        assert!(strings.contains(&"flag{test}".to_string()));
    }

    #[test]
    fn test_is_flag_pattern() {
        assert!(is_flag_pattern("flag{test}"));
        assert!(is_flag_pattern("CTF{test}"));
        assert!(!is_flag_pattern("hello world"));
    }

    #[test]
    fn test_analyze_pcap_udp_payload_extracts_flag() -> Result<()> {
        let payload = b"flag{test}";
        let udp = udp_payload(1234, 5678, payload);
        let frame = ethernet_ipv4_packet(17, &udp);

        let mut pcap = Vec::new();
        push_pcap_le_global_header(&mut pcap, 1);
        push_pcap_le_record(&mut pcap, 1, 0, &frame);

        let analysis = PcapAnalyzer::new().analyze_bytes(&pcap)?;
        assert_eq!(analysis.packet_count, 1);
        assert!(analysis.flags.iter().any(|s| s == "flag{test}"));
        Ok(())
    }

    #[test]
    fn test_analyze_pcap_tcp_reassembly_extracts_flag() -> Result<()> {
        let seg1 = tcp_payload(1111, 2222, 1, b"flag{");
        let seg2 = tcp_payload(1111, 2222, 6, b"test}");

        let frame1 = ethernet_ipv4_packet(6, &seg1);
        let frame2 = ethernet_ipv4_packet(6, &seg2);

        let mut pcap = Vec::new();
        push_pcap_le_global_header(&mut pcap, 1);
        push_pcap_le_record(&mut pcap, 1, 0, &frame1);
        push_pcap_le_record(&mut pcap, 2, 0, &frame2);

        let analysis = PcapAnalyzer::new().analyze_bytes(&pcap)?;
        assert_eq!(analysis.tcp_streams.len(), 1);
        assert!(analysis.flags.iter().any(|s| s == "flag{test}"));
        Ok(())
    }
}

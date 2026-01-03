//! 文件魔数检测模块
//!
//! 基于文件头字节识别真实文件类型，不依赖扩展名

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// 文件类型分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileCategory {
    Image,
    Archive,
    Audio,
    Video,
    Document,
    Executable,
    Data,
    Text,
    Unknown,
}

/// 文件魔数检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMagic {
    /// MIME类型
    pub mime_type: String,
    /// 推荐扩展名
    pub extension: String,
    /// 文件类型描述
    pub description: String,
    /// 文件分类
    pub category: FileCategory,
    /// 是否为压缩包
    pub is_archive: bool,
    /// 是否为图片
    pub is_image: bool,
    /// 是否为可执行文件
    pub is_executable: bool,
    /// 检测到的异常（如文件头伪装）
    pub anomalies: Vec<String>,
    /// 置信度 (0.0-1.0)
    pub confidence: f32,
}

impl Default for FileMagic {
    fn default() -> Self {
        Self {
            mime_type: "application/octet-stream".to_string(),
            extension: "bin".to_string(),
            description: "Unknown binary data".to_string(),
            category: FileCategory::Unknown,
            is_archive: false,
            is_image: false,
            is_executable: false,
            anomalies: Vec::new(),
            confidence: 0.0,
        }
    }
}

/// 魔数定义
struct MagicDef {
    magic: &'static [u8],
    offset: usize,
    mime: &'static str,
    ext: &'static str,
    desc: &'static str,
    category: FileCategory,
}

/// 内置魔数表
const MAGIC_TABLE: &[MagicDef] = &[
    // 图片格式 (35种)
    MagicDef {
        magic: &[0xFF, 0xD8, 0xFF],
        offset: 0,
        mime: "image/jpeg",
        ext: "jpg",
        desc: "JPEG image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        offset: 0,
        mime: "image/png",
        ext: "png",
        desc: "PNG image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"GIF87a",
        offset: 0,
        mime: "image/gif",
        ext: "gif",
        desc: "GIF image (87a)",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"GIF89a",
        offset: 0,
        mime: "image/gif",
        ext: "gif",
        desc: "GIF image (89a)",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"BM",
        offset: 0,
        mime: "image/bmp",
        ext: "bmp",
        desc: "BMP image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x01, 0x00],
        offset: 0,
        mime: "image/x-icon",
        ext: "ico",
        desc: "ICO icon",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x02, 0x00],
        offset: 0,
        mime: "image/x-icon",
        ext: "cur",
        desc: "CUR cursor",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"II*\x00",
        offset: 0,
        mime: "image/tiff",
        ext: "tiff",
        desc: "TIFF image (little-endian)",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"MM\x00*",
        offset: 0,
        mime: "image/tiff",
        ext: "tiff",
        desc: "TIFF image (big-endian)",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"8BPS",
        offset: 0,
        mime: "image/vnd.adobe.photoshop",
        ext: "psd",
        desc: "Adobe Photoshop",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"gimp xcf",
        offset: 0,
        mime: "image/x-xcf",
        ext: "xcf",
        desc: "GIMP XCF",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20],
        offset: 0,
        mime: "image/jp2",
        ext: "jp2",
        desc: "JPEG 2000",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0xFF, 0x4F, 0xFF, 0x51],
        offset: 0,
        mime: "image/jp2",
        ext: "j2k",
        desc: "JPEG 2000 codestream",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"RIFF",
        offset: 0,
        mime: "image/webp",
        ext: "webp",
        desc: "WebP image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63,
        ],
        offset: 0,
        mime: "image/heic",
        ext: "heic",
        desc: "HEIC image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66,
        ],
        offset: 0,
        mime: "image/avif",
        ext: "avif",
        desc: "AVIF image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0xFF, 0x0A],
        offset: 0,
        mime: "image/jxl",
        ext: "jxl",
        desc: "JPEG XL",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20],
        offset: 0,
        mime: "image/jxl",
        ext: "jxl",
        desc: "JPEG XL (container)",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"DDS ",
        offset: 0,
        mime: "image/vnd-ms.dds",
        ext: "dds",
        desc: "DirectDraw Surface",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x76, 0x2F, 0x31, 0x01],
        offset: 0,
        mime: "image/openexr",
        ext: "exr",
        desc: "OpenEXR image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"#?RADIANCE",
        offset: 0,
        mime: "image/vnd.radiance",
        ext: "hdr",
        desc: "Radiance HDR",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P1",
        offset: 0,
        mime: "image/x-portable-bitmap",
        ext: "pbm",
        desc: "PBM ASCII",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P2",
        offset: 0,
        mime: "image/x-portable-graymap",
        ext: "pgm",
        desc: "PGM ASCII",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P3",
        offset: 0,
        mime: "image/x-portable-pixmap",
        ext: "ppm",
        desc: "PPM ASCII",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P4",
        offset: 0,
        mime: "image/x-portable-bitmap",
        ext: "pbm",
        desc: "PBM binary",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P5",
        offset: 0,
        mime: "image/x-portable-graymap",
        ext: "pgm",
        desc: "PGM binary",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P6",
        offset: 0,
        mime: "image/x-portable-pixmap",
        ext: "ppm",
        desc: "PPM binary",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"P7",
        offset: 0,
        mime: "image/x-portable-anymap",
        ext: "pam",
        desc: "PAM image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x59, 0xA6, 0x6A, 0x95],
        offset: 0,
        mime: "image/x-sun-raster",
        ext: "ras",
        desc: "Sun Raster",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x01, 0xDA],
        offset: 0,
        mime: "image/x-rgb",
        ext: "rgb",
        desc: "SGI RGB image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"SIMPLE",
        offset: 0,
        mime: "image/fits",
        ext: "fits",
        desc: "FITS image",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x49, 0x49, 0x55, 0x00],
        offset: 0,
        mime: "image/x-canon-cr2",
        ext: "cr2",
        desc: "Canon CR2 RAW",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: &[0x49, 0x49, 0x52, 0x4F],
        offset: 0,
        mime: "image/x-olympus-orf",
        ext: "orf",
        desc: "Olympus ORF RAW",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"FUJIFILMCCD-RAW",
        offset: 0,
        mime: "image/x-fuji-raf",
        ext: "raf",
        desc: "Fuji RAF RAW",
        category: FileCategory::Image,
    },
    MagicDef {
        magic: b"IIU\x00\x08\x00\x00\x00",
        offset: 0,
        mime: "image/x-panasonic-rw2",
        ext: "rw2",
        desc: "Panasonic RW2 RAW",
        category: FileCategory::Image,
    },
    // 压缩包格式 (35种)
    MagicDef {
        magic: &[0x50, 0x4B, 0x03, 0x04],
        offset: 0,
        mime: "application/zip",
        ext: "zip",
        desc: "ZIP archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x50, 0x4B, 0x05, 0x06],
        offset: 0,
        mime: "application/zip",
        ext: "zip",
        desc: "ZIP archive (empty)",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x50, 0x4B, 0x07, 0x08],
        offset: 0,
        mime: "application/zip",
        ext: "zip",
        desc: "ZIP archive (spanned)",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
        offset: 0,
        mime: "application/x-rar-compressed",
        ext: "rar",
        desc: "RAR archive v1.5-4.x",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00],
        offset: 0,
        mime: "application/x-rar-compressed",
        ext: "rar",
        desc: "RAR archive v5+",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        offset: 0,
        mime: "application/x-7z-compressed",
        ext: "7z",
        desc: "7-Zip archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1F, 0x8B],
        offset: 0,
        mime: "application/gzip",
        ext: "gz",
        desc: "Gzip compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x42, 0x5A, 0x68],
        offset: 0,
        mime: "application/x-bzip2",
        ext: "bz2",
        desc: "Bzip2 compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
        offset: 0,
        mime: "application/x-xz",
        ext: "xz",
        desc: "XZ compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"ustar",
        offset: 257,
        mime: "application/x-tar",
        ext: "tar",
        desc: "TAR archive (POSIX)",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x28, 0xB5, 0x2F, 0xFD],
        offset: 0,
        mime: "application/zstd",
        ext: "zst",
        desc: "Zstandard compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x04, 0x22, 0x4D, 0x18],
        offset: 0,
        mime: "application/x-lz4",
        ext: "lz4",
        desc: "LZ4 compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1F, 0x9D],
        offset: 0,
        mime: "application/x-compress",
        ext: "Z",
        desc: "Unix compress",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1F, 0xA0],
        offset: 0,
        mime: "application/x-compress",
        ext: "Z",
        desc: "Unix compress (LZH)",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"LZIP",
        offset: 0,
        mime: "application/x-lzip",
        ext: "lz",
        desc: "Lzip compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A],
        offset: 0,
        mime: "application/x-lzop",
        ext: "lzo",
        desc: "LZOP compressed",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"MSCF",
        offset: 0,
        mime: "application/vnd.ms-cab-compressed",
        ext: "cab",
        desc: "Microsoft Cabinet",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x60, 0xEA],
        offset: 0,
        mime: "application/x-arj",
        ext: "arj",
        desc: "ARJ archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1A, 0x0B],
        offset: 0,
        mime: "application/x-pak",
        ext: "pak",
        desc: "Quake PAK archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"-lh",
        offset: 2,
        mime: "application/x-lzh-compressed",
        ext: "lzh",
        desc: "LZH archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"**ACE**",
        offset: 7,
        mime: "application/x-ace-compressed",
        ext: "ace",
        desc: "ACE archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"!<arch>",
        offset: 0,
        mime: "application/x-archive",
        ext: "a",
        desc: "Unix ar archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"<ar>",
        offset: 0,
        mime: "application/x-archive",
        ext: "ar",
        desc: "Unix ar archive (BSD)",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1A, 0x02],
        offset: 0,
        mime: "application/x-arc",
        ext: "arc",
        desc: "ARC archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1A, 0x03],
        offset: 0,
        mime: "application/x-arc",
        ext: "arc",
        desc: "ARC archive v2",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1A, 0x08],
        offset: 0,
        mime: "application/x-arc",
        ext: "arc",
        desc: "ARC archive v3",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0x1A, 0x09],
        offset: 0,
        mime: "application/x-arc",
        ext: "arc",
        desc: "ARC archive v4",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"ZOO",
        offset: 0,
        mime: "application/x-zoo",
        ext: "zoo",
        desc: "ZOO archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"SQSH",
        offset: 0,
        mime: "application/x-squashfs",
        ext: "sqsh",
        desc: "SquashFS",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"hsqs",
        offset: 0,
        mime: "application/x-squashfs",
        ext: "sqsh",
        desc: "SquashFS (little-endian)",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0xED, 0xAB, 0xEE, 0xDB],
        offset: 0,
        mime: "application/x-rpm",
        ext: "rpm",
        desc: "RPM package",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"!<debian-binary>",
        offset: 0,
        mime: "application/vnd.debian.binary-package",
        ext: "deb",
        desc: "Debian package",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: &[0xD0, 0xCF, 0x11, 0xE0],
        offset: 0,
        mime: "application/x-msi",
        ext: "msi",
        desc: "Microsoft Installer",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"xar!",
        offset: 0,
        mime: "application/x-xar",
        ext: "xar",
        desc: "XAR archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"CPIO",
        offset: 0,
        mime: "application/x-cpio",
        ext: "cpio",
        desc: "CPIO archive",
        category: FileCategory::Archive,
    },
    // 可执行文件格式 (25种)
    MagicDef {
        magic: &[0x7F, 0x45, 0x4C, 0x46],
        offset: 0,
        mime: "application/x-executable",
        ext: "elf",
        desc: "ELF executable",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"MZ",
        offset: 0,
        mime: "application/x-dosexec",
        ext: "exe",
        desc: "DOS/Windows executable",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0xCF, 0xFA, 0xED, 0xFE],
        offset: 0,
        mime: "application/x-mach-binary",
        ext: "macho",
        desc: "Mach-O 64-bit",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0xCE, 0xFA, 0xED, 0xFE],
        offset: 0,
        mime: "application/x-mach-binary",
        ext: "macho",
        desc: "Mach-O 32-bit",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0xFE, 0xED, 0xFA, 0xCF],
        offset: 0,
        mime: "application/x-mach-binary",
        ext: "macho",
        desc: "Mach-O 64-bit (BE)",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0xFE, 0xED, 0xFA, 0xCE],
        offset: 0,
        mime: "application/x-mach-binary",
        ext: "macho",
        desc: "Mach-O 32-bit (BE)",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0xCA, 0xFE, 0xBA, 0xBE],
        offset: 0,
        mime: "application/x-mach-binary",
        ext: "macho",
        desc: "Mach-O Universal Binary",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0xBE, 0xBA, 0xFE, 0xCA],
        offset: 0,
        mime: "application/x-mach-binary",
        ext: "macho",
        desc: "Mach-O Universal (BE)",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"dex\n",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "dex",
        desc: "Android DEX",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"dey\n",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "odex",
        desc: "Android ODEX",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"\x00asm",
        offset: 0,
        mime: "application/wasm",
        ext: "wasm",
        desc: "WebAssembly binary",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00],
        offset: 0,
        mime: "application/x-dosexec",
        ext: "exe",
        desc: "DOS executable",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x5A, 0x4D],
        offset: 0,
        mime: "application/x-dosexec",
        ext: "exe",
        desc: "DOS executable (ZM)",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"#!",
        offset: 0,
        mime: "application/x-shellscript",
        ext: "sh",
        desc: "Shell script",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x7F, 0x45, 0x4C, 0x46, 0x01],
        offset: 0,
        mime: "application/x-executable",
        ext: "elf32",
        desc: "ELF 32-bit",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x7F, 0x45, 0x4C, 0x46, 0x02],
        offset: 0,
        mime: "application/x-executable",
        ext: "elf64",
        desc: "ELF 64-bit",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x00, 0x61, 0x73, 0x6D],
        offset: 0,
        mime: "application/wasm",
        ext: "wasm",
        desc: "WebAssembly (BE)",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"Joy!",
        offset: 0,
        mime: "application/x-pef",
        ext: "pef",
        desc: "PEF executable",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x01, 0x0B],
        offset: 0,
        mime: "application/x-executable",
        ext: "o",
        desc: "VAX demand paged",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x01, 0x07],
        offset: 0,
        mime: "application/x-executable",
        ext: "o",
        desc: "PDP-11 executable",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x01, 0x08],
        offset: 0,
        mime: "application/x-executable",
        ext: "o",
        desc: "PDP-11 pure executable",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x01, 0x11],
        offset: 0,
        mime: "application/x-executable",
        ext: "o",
        desc: "PDP-11 separate I&D",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: &[0x01, 0x14],
        offset: 0,
        mime: "application/x-executable",
        ext: "o",
        desc: "PDP-11 overlay",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"LLVM",
        offset: 0,
        mime: "application/x-llvm",
        ext: "bc",
        desc: "LLVM bitcode",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"BC\xC0\xDE",
        offset: 0,
        mime: "application/x-llvm",
        ext: "bc",
        desc: "LLVM bitcode (wrapper)",
        category: FileCategory::Executable,
    },
    // 音频格式 (30种)
    MagicDef {
        magic: b"ID3",
        offset: 0,
        mime: "audio/mpeg",
        ext: "mp3",
        desc: "MP3 audio (ID3)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0xFF, 0xFB],
        offset: 0,
        mime: "audio/mpeg",
        ext: "mp3",
        desc: "MP3 audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0xFF, 0xF3],
        offset: 0,
        mime: "audio/mpeg",
        ext: "mp3",
        desc: "MP3 audio (MPEG2)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0xFF, 0xF2],
        offset: 0,
        mime: "audio/mpeg",
        ext: "mp3",
        desc: "MP3 audio (MPEG2.5)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0xFF, 0xFA],
        offset: 0,
        mime: "audio/mpeg",
        ext: "mp3",
        desc: "MP3 audio (MPEG1 L3)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"OggS",
        offset: 0,
        mime: "audio/ogg",
        ext: "ogg",
        desc: "Ogg container",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"fLaC",
        offset: 0,
        mime: "audio/flac",
        ext: "flac",
        desc: "FLAC audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"FORM",
        offset: 0,
        mime: "audio/aiff",
        ext: "aiff",
        desc: "AIFF audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"RIFF",
        offset: 0,
        mime: "audio/wav",
        ext: "wav",
        desc: "WAV audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"MThd",
        offset: 0,
        mime: "audio/midi",
        ext: "mid",
        desc: "MIDI audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11],
        offset: 0,
        mime: "audio/x-ms-wma",
        ext: "wma",
        desc: "Windows Media Audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"MAC ",
        offset: 0,
        mime: "audio/x-ape",
        ext: "ape",
        desc: "Monkey's Audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"wvpk",
        offset: 0,
        mime: "audio/x-wavpack",
        ext: "wv",
        desc: "WavPack audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"TTA1",
        offset: 0,
        mime: "audio/x-tta",
        ext: "tta",
        desc: "True Audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"MPCK",
        offset: 0,
        mime: "audio/x-musepack",
        ext: "mpc",
        desc: "Musepack SV8",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"MP+",
        offset: 0,
        mime: "audio/x-musepack",
        ext: "mpc",
        desc: "Musepack SV7",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0x2E, 0x73, 0x6E, 0x64],
        offset: 0,
        mime: "audio/basic",
        ext: "au",
        desc: "Sun AU audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0x64, 0x6E, 0x73, 0x2E],
        offset: 0,
        mime: "audio/basic",
        ext: "au",
        desc: "Sun AU audio (LE)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"CREATIVE",
        offset: 0,
        mime: "audio/x-voc",
        ext: "voc",
        desc: "Creative Voice",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x41,
        ],
        offset: 0,
        mime: "audio/mp4",
        ext: "m4a",
        desc: "M4A audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"OpusHead",
        offset: 28,
        mime: "audio/opus",
        ext: "opus",
        desc: "Opus audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"Speex",
        offset: 28,
        mime: "audio/speex",
        ext: "spx",
        desc: "Speex audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"#!AMR",
        offset: 0,
        mime: "audio/amr",
        ext: "amr",
        desc: "AMR audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"#!AMR-WB",
        offset: 0,
        mime: "audio/amr-wb",
        ext: "awb",
        desc: "AMR-WB audio",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"ADIF",
        offset: 0,
        mime: "audio/aac",
        ext: "aac",
        desc: "AAC audio (ADIF)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0xFF, 0xF1],
        offset: 0,
        mime: "audio/aac",
        ext: "aac",
        desc: "AAC audio (ADTS)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: &[0xFF, 0xF9],
        offset: 0,
        mime: "audio/aac",
        ext: "aac",
        desc: "AAC audio (ADTS v2)",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"IMPM",
        offset: 0,
        mime: "audio/x-it",
        ext: "it",
        desc: "Impulse Tracker",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"Extended Module:",
        offset: 0,
        mime: "audio/x-xm",
        ext: "xm",
        desc: "FastTracker XM",
        category: FileCategory::Audio,
    },
    MagicDef {
        magic: b"MTM",
        offset: 0,
        mime: "audio/x-mod",
        ext: "mtm",
        desc: "MultiTracker Module",
        category: FileCategory::Audio,
    },
    // 视频格式 (25种)
    MagicDef {
        magic: b"ftyp",
        offset: 4,
        mime: "video/mp4",
        ext: "mp4",
        desc: "MP4/M4V/MOV video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70],
        offset: 0,
        mime: "video/mp4",
        ext: "mp4",
        desc: "MP4 video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70],
        offset: 0,
        mime: "video/mp4",
        ext: "mp4",
        desc: "MP4 video (v2)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x1A, 0x45, 0xDF, 0xA3],
        offset: 0,
        mime: "video/webm",
        ext: "webm",
        desc: "WebM/MKV video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"FLV\x01",
        offset: 0,
        mime: "video/x-flv",
        ext: "flv",
        desc: "Flash video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11],
        offset: 0,
        mime: "video/x-ms-wmv",
        ext: "wmv",
        desc: "Windows Media Video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x01, 0xBA],
        offset: 0,
        mime: "video/mpeg",
        ext: "mpg",
        desc: "MPEG video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x01, 0xB3],
        offset: 0,
        mime: "video/mpeg",
        ext: "mpg",
        desc: "MPEG video (seq)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x47, 0x40],
        offset: 0,
        mime: "video/mp2t",
        ext: "ts",
        desc: "MPEG-TS video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"RIFF",
        offset: 0,
        mime: "video/x-msvideo",
        ext: "avi",
        desc: "AVI video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74],
        offset: 0,
        mime: "video/quicktime",
        ext: "mov",
        desc: "QuickTime MOV",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"moov",
        offset: 4,
        mime: "video/quicktime",
        ext: "mov",
        desc: "QuickTime MOV (moov)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"mdat",
        offset: 4,
        mime: "video/quicktime",
        ext: "mov",
        desc: "QuickTime MOV (mdat)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"wide",
        offset: 4,
        mime: "video/quicktime",
        ext: "mov",
        desc: "QuickTime MOV (wide)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"free",
        offset: 4,
        mime: "video/quicktime",
        ext: "mov",
        desc: "QuickTime MOV (free)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"skip",
        offset: 4,
        mime: "video/quicktime",
        ext: "mov",
        desc: "QuickTime MOV (skip)",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x70,
        ],
        offset: 0,
        mime: "video/3gpp",
        ext: "3gp",
        desc: "3GPP video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x70,
        ],
        offset: 0,
        mime: "video/3gpp2",
        ext: "3g2",
        desc: "3GPP2 video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"OggS\x00\x02",
        offset: 0,
        mime: "video/ogg",
        ext: "ogv",
        desc: "Ogg video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"DICM",
        offset: 128,
        mime: "application/dicom",
        ext: "dcm",
        desc: "DICOM medical",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0x01, 0x00],
        offset: 0,
        mime: "video/x-sgi-movie",
        ext: "movie",
        desc: "SGI movie",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"#EXTM3U",
        offset: 0,
        mime: "application/vnd.apple.mpegurl",
        ext: "m3u8",
        desc: "HLS playlist",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"YUV4MPEG2",
        offset: 0,
        mime: "video/x-raw-yuv",
        ext: "y4m",
        desc: "YUV4MPEG2 video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"DKIF",
        offset: 0,
        mime: "video/x-ivf",
        ext: "ivf",
        desc: "IVF video",
        category: FileCategory::Video,
    },
    MagicDef {
        magic: b"SMK2",
        offset: 0,
        mime: "video/x-smacker",
        ext: "smk",
        desc: "Smacker video",
        category: FileCategory::Video,
    },
    // 文档格式 (35种)
    MagicDef {
        magic: &[0x25, 0x50, 0x44, 0x46],
        offset: 0,
        mime: "application/pdf",
        ext: "pdf",
        desc: "PDF document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        offset: 0,
        mime: "application/msword",
        ext: "doc",
        desc: "Microsoft Office (OLE)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"{\rtf",
        offset: 0,
        mime: "application/rtf",
        ext: "rtf",
        desc: "Rich Text Format",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"PK\x03\x04\x14\x00\x06\x00",
        offset: 0,
        mime: "application/vnd.openxmlformats-officedocument",
        ext: "docx",
        desc: "Office Open XML",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"<?xml",
        offset: 0,
        mime: "application/xml",
        ext: "xml",
        desc: "XML document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[0xEF, 0xBB, 0xBF, 0x3C, 0x3F, 0x78, 0x6D, 0x6C],
        offset: 0,
        mime: "application/xml",
        ext: "xml",
        desc: "XML document (UTF-8 BOM)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"<!DOCTYPE html",
        offset: 0,
        mime: "text/html",
        ext: "html",
        desc: "HTML document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"<html",
        offset: 0,
        mime: "text/html",
        ext: "html",
        desc: "HTML document (no doctype)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"<HTML",
        offset: 0,
        mime: "text/html",
        ext: "html",
        desc: "HTML document (uppercase)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"<!doctype html",
        offset: 0,
        mime: "text/html",
        ext: "html",
        desc: "HTML5 document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[
            0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A,
            0x65, 0x74,
        ],
        offset: 0,
        mime: "application/x-msaccess",
        ext: "mdb",
        desc: "Microsoft Access",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[
            0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x41,
            0x43, 0x45,
        ],
        offset: 0,
        mime: "application/x-msaccess",
        ext: "accdb",
        desc: "Microsoft Access 2007+",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"wOFF",
        offset: 0,
        mime: "font/woff",
        ext: "woff",
        desc: "WOFF font",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"wOF2",
        offset: 0,
        mime: "font/woff2",
        ext: "woff2",
        desc: "WOFF2 font",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[0x00, 0x01, 0x00, 0x00],
        offset: 0,
        mime: "font/ttf",
        ext: "ttf",
        desc: "TrueType font",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"OTTO",
        offset: 0,
        mime: "font/otf",
        ext: "otf",
        desc: "OpenType font",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"true",
        offset: 0,
        mime: "font/ttf",
        ext: "ttf",
        desc: "TrueType font (Apple)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"typ1",
        offset: 0,
        mime: "font/ttf",
        ext: "ttf",
        desc: "TrueType font (typ1)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[0x80, 0x01],
        offset: 0,
        mime: "application/x-font-type1",
        ext: "pfb",
        desc: "PostScript Type 1",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"%!PS-AdobeFont",
        offset: 0,
        mime: "application/x-font-type1",
        ext: "pfa",
        desc: "PostScript Type 1 ASCII",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"%!PS",
        offset: 0,
        mime: "application/postscript",
        ext: "ps",
        desc: "PostScript",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[0xC5, 0xD0, 0xD3, 0xC6],
        offset: 0,
        mime: "application/postscript",
        ext: "eps",
        desc: "Encapsulated PostScript",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"StartFontMetrics",
        offset: 0,
        mime: "application/x-font-afm",
        ext: "afm",
        desc: "Adobe Font Metrics",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"BOOKMOBI",
        offset: 0,
        mime: "application/x-mobipocket-ebook",
        ext: "mobi",
        desc: "Mobipocket eBook",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"TPZ0",
        offset: 0,
        mime: "application/x-topaz-ebook",
        ext: "tpz",
        desc: "Topaz eBook",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x42, 0x4F, 0x4F, 0x4B, 0x4D, 0x4F, 0x42, 0x49,
        ],
        offset: 0,
        mime: "application/x-palm-database",
        ext: "pdb",
        desc: "Palm Database",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"DjVu",
        offset: 0,
        mime: "image/vnd.djvu",
        ext: "djvu",
        desc: "DjVu document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"AT&TFORM",
        offset: 0,
        mime: "image/vnd.djvu",
        ext: "djvu",
        desc: "DjVu document (AT&T)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"FORM",
        offset: 0,
        mime: "image/vnd.djvu",
        ext: "djvu",
        desc: "DjVu document (FORM)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: &[0x1F, 0x8B, 0x08],
        offset: 0,
        mime: "application/x-tex-tfm",
        ext: "tfm",
        desc: "TeX font metric",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"\\documentclass",
        offset: 0,
        mime: "application/x-latex",
        ext: "tex",
        desc: "LaTeX document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"\\document",
        offset: 0,
        mime: "application/x-latex",
        ext: "tex",
        desc: "LaTeX document (old)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"\\input",
        offset: 0,
        mime: "application/x-tex",
        ext: "tex",
        desc: "TeX document",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"\\begin{",
        offset: 0,
        mime: "application/x-latex",
        ext: "tex",
        desc: "LaTeX document (begin)",
        category: FileCategory::Document,
    },
    MagicDef {
        magic: b"\\chapter",
        offset: 0,
        mime: "application/x-latex",
        ext: "tex",
        desc: "LaTeX document (chapter)",
        category: FileCategory::Document,
    },
    // 数据库和数据格式 (25种)
    MagicDef {
        magic: b"SQLite format 3",
        offset: 0,
        mime: "application/x-sqlite3",
        ext: "db",
        desc: "SQLite database",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65],
        offset: 0,
        mime: "application/x-sqlite3",
        ext: "sqlite",
        desc: "SQLite database",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0xFE, 0xFF],
        offset: 0,
        mime: "application/x-msaccess",
        ext: "mdb",
        desc: "JET database",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x1A, 0x00, 0x00],
        offset: 0,
        mime: "application/x-dbf",
        ext: "dbf",
        desc: "dBASE III",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x03],
        offset: 0,
        mime: "application/x-dbf",
        ext: "dbf",
        desc: "dBASE III (no memo)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x83],
        offset: 0,
        mime: "application/x-dbf",
        ext: "dbf",
        desc: "dBASE III (with memo)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x8B],
        offset: 0,
        mime: "application/x-dbf",
        ext: "dbf",
        desc: "dBASE IV (with memo)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0xF5],
        offset: 0,
        mime: "application/x-dbf",
        ext: "dbf",
        desc: "FoxPro 2.x",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"PGDMP",
        offset: 0,
        mime: "application/x-postgresql-dump",
        ext: "dump",
        desc: "PostgreSQL dump",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"REDIS",
        offset: 0,
        mime: "application/x-redis",
        ext: "rdb",
        desc: "Redis RDB",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x00, 0x06, 0x15, 0x61],
        offset: 0,
        mime: "application/x-netcdf",
        ext: "nc",
        desc: "NetCDF classic",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x89, 0x48, 0x44, 0x46],
        offset: 0,
        mime: "application/x-hdf5",
        ext: "h5",
        desc: "HDF5 data",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x0E, 0x03, 0x13, 0x01],
        offset: 0,
        mime: "application/x-hdf4",
        ext: "hdf",
        desc: "HDF4 data",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"CDF",
        offset: 0,
        mime: "application/x-netcdf",
        ext: "cdf",
        desc: "CDF data",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"SIMPLE  =",
        offset: 0,
        mime: "application/fits",
        ext: "fits",
        desc: "FITS data",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x93, 0x4E, 0x55, 0x4D, 0x50, 0x59],
        offset: 0,
        mime: "application/x-numpy",
        ext: "npy",
        desc: "NumPy array",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"PK\x03\x04",
        offset: 0,
        mime: "application/x-numpy",
        ext: "npz",
        desc: "NumPy compressed",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"MATLAB",
        offset: 0,
        mime: "application/x-matlab-data",
        ext: "mat",
        desc: "MATLAB v4",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x41,
            0x54, 0x4C, 0x41, 0x42,
        ],
        offset: 0,
        mime: "application/x-matlab-data",
        ext: "mat",
        desc: "MATLAB v5+",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"Parquet",
        offset: 4,
        mime: "application/x-parquet",
        ext: "parquet",
        desc: "Apache Parquet",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"PAR1",
        offset: 0,
        mime: "application/x-parquet",
        ext: "parquet",
        desc: "Apache Parquet (v1)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ORC",
        offset: 0,
        mime: "application/x-orc",
        ext: "orc",
        desc: "Apache ORC",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"Obj\x01",
        offset: 0,
        mime: "application/x-avro",
        ext: "avro",
        desc: "Apache Avro",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ARROW1",
        offset: 0,
        mime: "application/x-arrow",
        ext: "arrow",
        desc: "Apache Arrow",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"FEATHER",
        offset: 0,
        mime: "application/x-feather",
        ext: "feather",
        desc: "Apache Feather",
        category: FileCategory::Data,
    },
    // 网络抓包格式 (10种)
    MagicDef {
        magic: &[0xD4, 0xC3, 0xB2, 0xA1],
        offset: 0,
        mime: "application/vnd.tcpdump.pcap",
        ext: "pcap",
        desc: "PCAP (little-endian)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0xA1, 0xB2, 0xC3, 0xD4],
        offset: 0,
        mime: "application/vnd.tcpdump.pcap",
        ext: "pcap",
        desc: "PCAP (big-endian)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x4D, 0x3C, 0xB2, 0xA1],
        offset: 0,
        mime: "application/vnd.tcpdump.pcap",
        ext: "pcap",
        desc: "PCAP (nanosecond LE)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0xA1, 0xB2, 0x3C, 0x4D],
        offset: 0,
        mime: "application/vnd.tcpdump.pcap",
        ext: "pcap",
        desc: "PCAP (nanosecond BE)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x0A, 0x0D, 0x0D, 0x0A],
        offset: 0,
        mime: "application/x-pcapng",
        ext: "pcapng",
        desc: "PCAPNG capture",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"XCP\x00",
        offset: 0,
        mime: "application/x-cap",
        ext: "cap",
        desc: "NetXRay capture",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x34, 0xCD, 0xB2, 0xA1],
        offset: 0,
        mime: "application/x-etherpeek",
        ext: "pkt",
        desc: "EtherPeek capture",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"iptrace",
        offset: 0,
        mime: "application/x-iptrace",
        ext: "tr",
        desc: "AIX iptrace",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"snoop",
        offset: 0,
        mime: "application/x-snoop",
        ext: "snoop",
        desc: "Solaris snoop",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x7F, 0xE8, 0x00, 0x00],
        offset: 0,
        mime: "application/x-netmon",
        ext: "cap",
        desc: "Microsoft NetMon",
        category: FileCategory::Data,
    },
    // 磁盘镜像格式 (15种)
    MagicDef {
        magic: b"CD001",
        offset: 32769,
        mime: "application/x-iso9660-image",
        ext: "iso",
        desc: "ISO 9660 image",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"CD001",
        offset: 34817,
        mime: "application/x-iso9660-image",
        ext: "iso",
        desc: "ISO 9660 (mode2)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ER\x02\x00",
        offset: 0,
        mime: "application/x-apple-diskimage",
        ext: "dmg",
        desc: "Apple DMG (raw)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"conectix",
        offset: 0,
        mime: "application/x-vhd",
        ext: "vhd",
        desc: "VHD disk image",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"vhdxfile",
        offset: 0,
        mime: "application/x-vhdx",
        ext: "vhdx",
        desc: "VHDX disk image",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"KDMV",
        offset: 0,
        mime: "application/x-vmdk",
        ext: "vmdk",
        desc: "VMware VMDK",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"# Disk DescriptorFile",
        offset: 0,
        mime: "application/x-vmdk",
        ext: "vmdk",
        desc: "VMware VMDK (sparse)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"<<<",
        offset: 0,
        mime: "application/x-virtualbox-vdi",
        ext: "vdi",
        desc: "VirtualBox VDI",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"QFI\xFB",
        offset: 0,
        mime: "application/x-qemu-disk",
        ext: "qcow2",
        desc: "QEMU QCOW2",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"QED\x00",
        offset: 0,
        mime: "application/x-qemu-disk",
        ext: "qed",
        desc: "QEMU QED",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0xEB, 0x3C, 0x90],
        offset: 0,
        mime: "application/x-fat",
        ext: "img",
        desc: "FAT boot sector",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0xEB, 0x58, 0x90],
        offset: 0,
        mime: "application/x-fat",
        ext: "img",
        desc: "FAT32 boot sector",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x53, 0xEF],
        offset: 1080,
        mime: "application/x-ext2",
        ext: "img",
        desc: "ext2/3/4 filesystem",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"NTFS    ",
        offset: 3,
        mime: "application/x-ntfs",
        ext: "img",
        desc: "NTFS filesystem",
        category: FileCategory::Data,
    },
    // 加密和安全格式 (15种)
    MagicDef {
        magic: b"-----BEGIN PGP",
        offset: 0,
        mime: "application/pgp-encrypted",
        ext: "pgp",
        desc: "PGP message",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"-----BEGIN CERTIFICATE",
        offset: 0,
        mime: "application/x-x509-ca-cert",
        ext: "crt",
        desc: "X.509 certificate (PEM)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"-----BEGIN RSA PRIVATE",
        offset: 0,
        mime: "application/x-pem-file",
        ext: "pem",
        desc: "RSA private key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"-----BEGIN PRIVATE KEY",
        offset: 0,
        mime: "application/x-pem-file",
        ext: "pem",
        desc: "Private key (PKCS#8)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"-----BEGIN PUBLIC KEY",
        offset: 0,
        mime: "application/x-pem-file",
        ext: "pem",
        desc: "Public key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"-----BEGIN OPENSSH",
        offset: 0,
        mime: "application/x-openssh-key",
        ext: "key",
        desc: "OpenSSH private key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ssh-rsa ",
        offset: 0,
        mime: "application/x-openssh-key",
        ext: "pub",
        desc: "SSH RSA public key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ssh-ed25519 ",
        offset: 0,
        mime: "application/x-openssh-key",
        ext: "pub",
        desc: "SSH Ed25519 public key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ssh-dss ",
        offset: 0,
        mime: "application/x-openssh-key",
        ext: "pub",
        desc: "SSH DSA public key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ecdsa-sha2-",
        offset: 0,
        mime: "application/x-openssh-key",
        ext: "pub",
        desc: "SSH ECDSA public key",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x30, 0x82],
        offset: 0,
        mime: "application/x-x509-ca-cert",
        ext: "der",
        desc: "DER certificate",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"Salted__",
        offset: 0,
        mime: "application/x-openssl-enc",
        ext: "enc",
        desc: "OpenSSL encrypted",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x62, 0x31, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00,
        ],
        offset: 0,
        mime: "application/x-keepass",
        ext: "kdbx",
        desc: "KeePass database",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x03, 0xD9, 0xA2, 0x9A],
        offset: 0,
        mime: "application/x-keepass",
        ext: "kdbx",
        desc: "KeePass 2.x database",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"LUKS\xBA\xBE",
        offset: 0,
        mime: "application/x-luks",
        ext: "luks",
        desc: "LUKS encrypted volume",
        category: FileCategory::Data,
    },
    // 3D和CAD格式 (15种)
    MagicDef {
        magic: b"solid ",
        offset: 0,
        mime: "model/stl",
        ext: "stl",
        desc: "STL ASCII",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"glTF",
        offset: 0,
        mime: "model/gltf-binary",
        ext: "glb",
        desc: "glTF binary",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"BLENDER",
        offset: 0,
        mime: "application/x-blender",
        ext: "blend",
        desc: "Blender file",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"3DMO",
        offset: 0,
        mime: "model/x-3dm",
        ext: "3dm",
        desc: "Rhino 3D model",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC10",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD DWG",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC1015",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD 2000",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC1018",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD 2004",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC1021",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD 2007",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC1024",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD 2010",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC1027",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD 2013",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"AC1032",
        offset: 0,
        mime: "application/x-autocad",
        ext: "dwg",
        desc: "AutoCAD 2018",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"FBX",
        offset: 0,
        mime: "application/x-fbx",
        ext: "fbx",
        desc: "Autodesk FBX",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"Kaydara FBX Binary",
        offset: 0,
        mime: "application/x-fbx",
        ext: "fbx",
        desc: "FBX binary",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"COLLADA",
        offset: 0,
        mime: "model/vnd.collada+xml",
        ext: "dae",
        desc: "COLLADA model",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"ply",
        offset: 0,
        mime: "model/x-ply",
        ext: "ply",
        desc: "PLY 3D model",
        category: FileCategory::Data,
    },
    // 游戏和ROM格式 (15种)
    MagicDef {
        magic: b"NES\x1A",
        offset: 0,
        mime: "application/x-nes-rom",
        ext: "nes",
        desc: "NES ROM",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x80, 0x37, 0x12, 0x40],
        offset: 0,
        mime: "application/x-n64-rom",
        ext: "z64",
        desc: "N64 ROM (big-endian)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x37, 0x80, 0x40, 0x12],
        offset: 0,
        mime: "application/x-n64-rom",
        ext: "v64",
        desc: "N64 ROM (byte-swapped)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x40, 0x12, 0x37, 0x80],
        offset: 0,
        mime: "application/x-n64-rom",
        ext: "n64",
        desc: "N64 ROM (little-endian)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"SEGA",
        offset: 0x100,
        mime: "application/x-genesis-rom",
        ext: "md",
        desc: "Sega Genesis ROM",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"SEGA MEGA DRIVE",
        offset: 0x100,
        mime: "application/x-genesis-rom",
        ext: "md",
        desc: "Sega Mega Drive ROM",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"SEGA GENESIS",
        offset: 0x100,
        mime: "application/x-genesis-rom",
        ext: "md",
        desc: "Sega Genesis ROM (US)",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[
            0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        ],
        offset: 0,
        mime: "application/x-snes-rom",
        ext: "sfc",
        desc: "SNES ROM",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"NINTENDO",
        offset: 0x104,
        mime: "application/x-gameboy-rom",
        ext: "gb",
        desc: "Game Boy ROM",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"PSF",
        offset: 0,
        mime: "application/x-psf",
        ext: "psf",
        desc: "PlayStation Sound",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"NCCH",
        offset: 0x100,
        mime: "application/x-3ds-rom",
        ext: "3ds",
        desc: "Nintendo 3DS ROM",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"PK11",
        offset: 0,
        mime: "application/x-switch-rom",
        ext: "nsp",
        desc: "Nintendo Switch NSP",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"WBFS",
        offset: 0,
        mime: "application/x-wii-rom",
        ext: "wbfs",
        desc: "Wii WBFS image",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x5D, 0x1C, 0x9E, 0xA3],
        offset: 0,
        mime: "application/x-wii-rom",
        ext: "wad",
        desc: "Wii WAD",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"NARC",
        offset: 0,
        mime: "application/x-nds-archive",
        ext: "narc",
        desc: "Nintendo DS archive",
        category: FileCategory::Data,
    },
    // Java和JVM格式 (10种)
    MagicDef {
        magic: &[0xCA, 0xFE, 0xBA, 0xBE],
        offset: 0,
        mime: "application/java-vm",
        ext: "class",
        desc: "Java class file",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"PK\x03\x04",
        offset: 0,
        mime: "application/java-archive",
        ext: "jar",
        desc: "Java JAR archive",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"PK\x03\x04",
        offset: 0,
        mime: "application/vnd.android.package-archive",
        ext: "apk",
        desc: "Android APK",
        category: FileCategory::Archive,
    },
    MagicDef {
        magic: b"dex\n035",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "dex",
        desc: "Android DEX 035",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"dex\n036",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "dex",
        desc: "Android DEX 036",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"dex\n037",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "dex",
        desc: "Android DEX 037",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"dex\n038",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "dex",
        desc: "Android DEX 038",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"dex\n039",
        offset: 0,
        mime: "application/vnd.android.dex",
        ext: "dex",
        desc: "Android DEX 039",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"vdex",
        offset: 0,
        mime: "application/vnd.android.vdex",
        ext: "vdex",
        desc: "Android VDEX",
        category: FileCategory::Executable,
    },
    MagicDef {
        magic: b"cdex",
        offset: 0,
        mime: "application/vnd.android.cdex",
        ext: "cdex",
        desc: "Android CDEX",
        category: FileCategory::Executable,
    },
    // 脚本和配置格式 (10种)
    MagicDef {
        magic: b"#!/bin/bash",
        offset: 0,
        mime: "application/x-shellscript",
        ext: "sh",
        desc: "Bash script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/bin/sh",
        offset: 0,
        mime: "application/x-shellscript",
        ext: "sh",
        desc: "Shell script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/env python",
        offset: 0,
        mime: "text/x-python",
        ext: "py",
        desc: "Python script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/python",
        offset: 0,
        mime: "text/x-python",
        ext: "py",
        desc: "Python script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/env perl",
        offset: 0,
        mime: "text/x-perl",
        ext: "pl",
        desc: "Perl script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/perl",
        offset: 0,
        mime: "text/x-perl",
        ext: "pl",
        desc: "Perl script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/env ruby",
        offset: 0,
        mime: "text/x-ruby",
        ext: "rb",
        desc: "Ruby script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/ruby",
        offset: 0,
        mime: "text/x-ruby",
        ext: "rb",
        desc: "Ruby script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/env node",
        offset: 0,
        mime: "application/javascript",
        ext: "js",
        desc: "Node.js script",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#!/usr/bin/env lua",
        offset: 0,
        mime: "text/x-lua",
        ext: "lua",
        desc: "Lua script",
        category: FileCategory::Text,
    },
    // 其他常见格式 (15种)
    MagicDef {
        magic: &[0xEF, 0xBB, 0xBF],
        offset: 0,
        mime: "text/plain",
        ext: "txt",
        desc: "UTF-8 BOM text",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: &[0xFF, 0xFE],
        offset: 0,
        mime: "text/plain",
        ext: "txt",
        desc: "UTF-16 LE BOM text",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: &[0xFE, 0xFF],
        offset: 0,
        mime: "text/plain",
        ext: "txt",
        desc: "UTF-16 BE BOM text",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: &[0xFF, 0xFE, 0x00, 0x00],
        offset: 0,
        mime: "text/plain",
        ext: "txt",
        desc: "UTF-32 LE BOM text",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: &[0x00, 0x00, 0xFE, 0xFF],
        offset: 0,
        mime: "text/plain",
        ext: "txt",
        desc: "UTF-32 BE BOM text",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"LREC",
        offset: 0,
        mime: "application/x-lnk",
        ext: "lnk",
        desc: "Windows shortcut",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00],
        offset: 0,
        mime: "application/x-ms-shortcut",
        ext: "lnk",
        desc: "Windows LNK",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"regf",
        offset: 0,
        mime: "application/x-ms-registry",
        ext: "reg",
        desc: "Windows Registry hive",
        category: FileCategory::Data,
    },
    MagicDef {
        magic: b"REGEDIT4",
        offset: 0,
        mime: "text/x-ms-regedit",
        ext: "reg",
        desc: "Windows Registry export",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"Windows Registry Editor",
        offset: 0,
        mime: "text/x-ms-regedit",
        ext: "reg",
        desc: "Windows Registry v5",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"[Desktop Entry]",
        offset: 0,
        mime: "application/x-desktop",
        ext: "desktop",
        desc: "Linux desktop entry",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"[InternetShortcut]",
        offset: 0,
        mime: "application/x-url",
        ext: "url",
        desc: "Internet shortcut",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"[playlist]",
        offset: 0,
        mime: "audio/x-scpls",
        ext: "pls",
        desc: "PLS playlist",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"#EXTM3U",
        offset: 0,
        mime: "audio/x-mpegurl",
        ext: "m3u",
        desc: "M3U playlist",
        category: FileCategory::Text,
    },
    MagicDef {
        magic: b"[ZoneTransfer]",
        offset: 0,
        mime: "application/x-zone-identifier",
        ext: "zone",
        desc: "Zone.Identifier",
        category: FileCategory::Text,
    },
];

/// 文件魔数检测器
#[derive(Clone)]
pub struct MagicDetector {
    /// 是否检测异常
    pub detect_anomalies: bool,
}

impl Default for MagicDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MagicDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detect_anomalies: true,
        }
    }

    /// 从文件路径检测
    ///
    /// # Errors
    ///
    /// 当文件无法打开或读取时返回错误。
    pub fn detect_file(
        &self,
        path: &Path,
    ) -> Result<FileMagic> {
        let mut file = File::open(path)?;
        let mut buf = vec![0u8; 512]; // 读取前512字节足够识别大多数格式
        let n = file.read(&mut buf)?;
        buf.truncate(n);

        let mut result = self.detect_bytes(&buf);

        // 检测异常：扩展名与实际类型不匹配
        if self.detect_anomalies {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_lowercase();
                if !result.extension.is_empty() && ext_lower != result.extension {
                    // 检查是否是已知的伪装
                    let anomaly = format!(
                        "Extension mismatch: file has .{} but content is {} ({})",
                        ext_lower, result.extension, result.description
                    );
                    result.anomalies.push(anomaly);
                }
            }

            // 检测隐藏的压缩包（如PNG后面藏ZIP）
            Self::detect_appended_data(&buf, &mut result);
        }

        Ok(result)
    }

    /// 从字节数组检测
    #[must_use]
    pub fn detect_bytes(
        &self,
        data: &[u8],
    ) -> FileMagic {
        if data.is_empty() {
            return FileMagic::default();
        }

        // 遍历魔数表匹配
        for def in MAGIC_TABLE {
            if data.len() >= def.offset + def.magic.len() {
                let slice = &data[def.offset..def.offset + def.magic.len()];
                if slice == def.magic {
                    return FileMagic {
                        mime_type: def.mime.to_string(),
                        extension: def.ext.to_string(),
                        description: def.desc.to_string(),
                        category: def.category,
                        is_archive: matches!(def.category, FileCategory::Archive),
                        is_image: matches!(def.category, FileCategory::Image),
                        is_executable: matches!(def.category, FileCategory::Executable),
                        anomalies: Vec::new(),
                        confidence: 1.0,
                    };
                }
            }
        }

        // 检测文本文件
        if Self::is_text(data) {
            return FileMagic {
                mime_type: "text/plain".to_string(),
                extension: "txt".to_string(),
                description: "Plain text".to_string(),
                category: FileCategory::Text,
                is_archive: false,
                is_image: false,
                is_executable: false,
                anomalies: Vec::new(),
                confidence: 0.8,
            };
        }

        FileMagic::default()
    }

    /// 检测是否为文本文件
    fn is_text(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        // 检查UTF-8 BOM
        if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
            return true;
        }

        // 检查是否大部分是可打印字符
        let printable = data
            .iter()
            .filter(|&&b| b == 0x09 || b == 0x0A || b == 0x0D || (0x20..=0x7E).contains(&b))
            .count();

        printable.saturating_mul(10) > data.len().saturating_mul(9)
    }

    /// 检测文件尾部附加数据
    fn detect_appended_data(
        data: &[u8],
        result: &mut FileMagic,
    ) {
        // PNG文件检测IEND后的数据
        if result.extension == "png" {
            if let Some(pos) = find_pattern(data, b"IEND") {
                let iend_end = pos + 8; // IEND chunk = 4 bytes length + 4 bytes type + 4 bytes CRC
                if iend_end < data.len() {
                    let trailing = &data[iend_end..];
                    // 检查是否有ZIP签名
                    if trailing.starts_with(b"PK\x03\x04") {
                        result
                            .anomalies
                            .push("Hidden ZIP archive after PNG IEND".to_string());
                    } else if !trailing.iter().all(|&b| b == 0) {
                        result.anomalies.push(format!(
                            "Trailing data after PNG IEND: {} bytes",
                            data.len() - iend_end
                        ));
                    }
                }
            }
        }

        // JPEG文件检测EOI后的数据
        if result.extension == "jpg" {
            // 查找JPEG EOI标记 (0xFF 0xD9)
            for i in (0..data.len().saturating_sub(1)).rev() {
                if data[i] == 0xFF && data[i + 1] == 0xD9 {
                    let eoi_end = i + 2;
                    if eoi_end < data.len() {
                        let trailing = &data[eoi_end..];
                        if trailing.starts_with(b"PK\x03\x04") {
                            result
                                .anomalies
                                .push("Hidden ZIP archive after JPEG EOI".to_string());
                        } else if trailing.len() > 10 && !trailing.iter().all(|&b| b == 0) {
                            result.anomalies.push(format!(
                                "Trailing data after JPEG EOI: {} bytes",
                                data.len() - eoi_end
                            ));
                        }
                    }
                    break;
                }
            }
        }
    }

    /// 快速检测是否为特定类型
    #[must_use]
    pub fn is_type(
        &self,
        data: &[u8],
        extension: &str,
    ) -> bool {
        let result = self.detect_bytes(data);
        result.extension == extension
    }

    /// 检测是否为压缩包
    #[must_use]
    pub fn is_archive(
        &self,
        data: &[u8],
    ) -> bool {
        let result = self.detect_bytes(data);
        result.is_archive
    }

    /// 检测是否为图片
    #[must_use]
    pub fn is_image(
        &self,
        data: &[u8],
    ) -> bool {
        let result = self.detect_bytes(data);
        result.is_image
    }

    /// 检测是否为可执行文件
    #[must_use]
    pub fn is_executable(
        &self,
        data: &[u8],
    ) -> bool {
        let result = self.detect_bytes(data);
        result.is_executable
    }

    /// 检测是否为PCAP文件
    #[must_use]
    pub fn is_pcap(
        &self,
        data: &[u8],
    ) -> bool {
        if data.len() < 4 {
            return false;
        }
        // PCAP magic numbers
        matches!(
            &data[0..4],
            [0xD4, 0xC3, 0xB2, 0xA1] | // little-endian
            [0xA1, 0xB2, 0xC3, 0xD4] | // big-endian
            [0x0A, 0x0D, 0x0D, 0x0A] // PCAPNG
        )
    }
}

/// 在数据中查找模式
fn find_pattern(
    data: &[u8],
    pattern: &[u8],
) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

/// 便捷函数：从文件检测
///
/// # Errors
///
/// 当文件无法打开或读取时返回错误。
pub fn detect_file(path: &Path) -> Result<FileMagic> {
    MagicDetector::new().detect_file(path)
}

/// 便捷函数：从字节检测
#[must_use]
pub fn detect_bytes(data: &[u8]) -> FileMagic {
    MagicDetector::new().detect_bytes(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_detection() {
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = detect_bytes(&png_header);
        assert_eq!(result.extension, "png");
        assert!(result.is_image);
    }

    #[test]
    fn test_zip_detection() {
        let zip_header = [0x50, 0x4B, 0x03, 0x04];
        let result = detect_bytes(&zip_header);
        assert_eq!(result.extension, "zip");
        assert!(result.is_archive);
    }

    #[test]
    fn test_elf_detection() {
        let elf_header = [0x7F, 0x45, 0x4C, 0x46];
        let result = detect_bytes(&elf_header);
        assert_eq!(result.extension, "elf");
        assert!(result.is_executable);
    }

    #[test]
    fn test_pcap_detection() {
        let detector = MagicDetector::new();
        for magic in [[0xD4, 0xC3, 0xB2, 0xA1], [0xA1, 0xB2, 0xC3, 0xD4]] {
            assert!(detector.is_pcap(&magic));
        }
    }
}

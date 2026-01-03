// NTH（Name-That-Hash）模式表（由脚本生成）。
// - 来源：reference/Name-That-Hash/name_that_hash/hashes.py
// - 请勿手工编辑；通过 `python tools/generate_nth_patterns.py` 重新生成

#[derive(Clone, Copy, Debug)]
pub(super) struct ModeDef {
    pub name: &'static str,
    pub hashcat: Option<u32>,
    pub john: Option<&'static str>,
    pub extended: bool,
    pub description: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PrototypeDef {
    pub pattern: &'static str,
    pub ignore_case: bool,
    pub modes: &'static [ModeDef],
}

pub(super) static NTH_PROTOTYPES: &[PrototypeDef] = &[
    PrototypeDef {
        pattern: r"^[a-f0-9]{4}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CRC-16", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"CRC-16-CCITT", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"FCS-16", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{8}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Adler-32", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"CRC-32B", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"FCS-32", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"GHash-32-3", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"GHash-32-5", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"FNV-132", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Fletcher-32", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Joaat", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"ELF-32", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"XOR-32", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{6}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CRC-24", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$crc32\$)?([a-f0-9]{8}.)?[a-f0-9]{8}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CRC-32", hashcat: Some(11500), john: Some(r"crc32"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\+[a-z0-9\/.]{12}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Eggdrop IRC Bot", hashcat: None, john: Some(r"bfegg"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9\/.]{12}[.26AEIMQUYcgkosw]{1}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"DES(Unix)", hashcat: Some(1500), john: Some(r"descrypt"), extended: false, description: None },
            ModeDef { name: r"Traditional DES", hashcat: Some(1500), john: Some(r"descrypt"), extended: false, description: None },
            ModeDef { name: r"DEScrypt", hashcat: Some(1500), john: Some(r"descrypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MySQL323", hashcat: Some(200), john: Some(r"mysql"), extended: false, description: None },
            ModeDef { name: r"Half MD5", hashcat: Some(5100), john: None, extended: false, description: None },
            ModeDef { name: r"FNV-164", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"CRC-64", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{16}:[a-f0-9]{0,30}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Oracle H: Type (Oracle 7+), DES(Oracle)", hashcat: Some(3100), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9\/.]{16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco-PIX(MD5)", hashcat: Some(2400), john: Some(r"pix-md5"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\([a-z0-9\/+]{20}\)$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Lotus Notes/Domino 6", hashcat: Some(8700), john: Some(r"dominosec"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^_[a-z0-9\/.]{19}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"BSDi Crypt", hashcat: Some(12400), john: Some(r"bsdicrypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{24}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CRC-96(ZIP)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"PKZIP Master Key", hashcat: Some(20500), john: None, extended: false, description: None },
            ModeDef { name: r"PKZIP Master Key (6 byte optimization)", hashcat: Some(20510), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*1\*50000\*(0|1)\*([a-f0-9]{32})\*([a-f0-9]{64})\*([a-f0-9]{32})\*([a-f0-9]{64})\*1\*(192|1360)\*([a-f0-9]{384})$",
        ignore_case: false,
        modes: &[
            ModeDef { name: r"Keepass 1 AES / without keyfile", hashcat: Some(13400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*1\*6000\*(0|1)\*([a-f0-9]{32})\*([a-f0-9]{64})\*([a-f0-9]{32})\*([a-f0-9]{64})\*1\*(192|1360)\*([a-f0-9]{2720})\*1\*64\*([a-f0-9]{64})$",
        ignore_case: false,
        modes: &[
            ModeDef { name: r"Keepass 1 Twofish / with keyfile", hashcat: Some(13400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*2\*6000\*222(\*[a-f0-9]{64}){2}(\*[a-f0-9]{32}){1}(\*[a-f0-9]{64}){2}\*1\*64(\*[a-f0-9]{64}){1}$",
        ignore_case: false,
        modes: &[
            ModeDef { name: r"Keepass 2 AES / with keyfile", hashcat: Some(13400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*2\*6000\*222\*(([a-f0-9]{32,64})(\*)?)+$",
        ignore_case: false,
        modes: &[
            ModeDef { name: r"Keepass 2 AES / without keyfile", hashcat: Some(13400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9\/.]{24}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Crypt16", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MD5", hashcat: Some(0), john: Some(r"raw-md5"), extended: false, description: Some(r"Used for Linux Shadow files.") },
            ModeDef { name: r"MD4", hashcat: Some(900), john: Some(r"raw-md4"), extended: false, description: None },
            ModeDef { name: r"Double MD5", hashcat: Some(2600), john: None, extended: false, description: None },
            ModeDef { name: r"Tiger-128", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-256(128)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-512(128)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Lotus Notes/Domino 5", hashcat: Some(8600), john: Some(r"lotus5"), extended: false, description: None },
            ModeDef { name: r"md5(md5(md5($pass)))", hashcat: Some(3500), john: None, extended: true, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
            ModeDef { name: r"md5(uppercase(md5($pass)))", hashcat: Some(4300), john: None, extended: true, description: None },
            ModeDef { name: r"md5(sha1($pass))", hashcat: Some(4400), john: None, extended: true, description: None },
            ModeDef { name: r"md5(utf16($pass))", hashcat: None, john: Some(r"dynamic_29"), extended: true, description: None },
            ModeDef { name: r"md4(utf16($pass))", hashcat: None, john: Some(r"dynamic_33"), extended: true, description: None },
            ModeDef { name: r"md5(md4($pass))", hashcat: None, john: Some(r"dynamic_34"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"(?:\$haval\$)?[a-f0-9]{32,64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Haval-128", hashcat: None, john: Some(r"haval-128-4"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"(?:\$ripemd\$)?[a-f0-9]{32,40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RIPEMD-128", hashcat: None, john: Some(r"ripemd-128"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"LM", hashcat: Some(3000), john: Some(r"lm"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"(?:\$dynamic_39\$)?[a-f0-9]{32}\$[a-z0-9]{1,32}\$?[a-z0-9]{1,500}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"net-md5", hashcat: None, john: Some(r"dynamic_39"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:[a-z0-9]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Skype", hashcat: Some(23), john: None, extended: false, description: None },
            ModeDef { name: r"ZipMonster", hashcat: None, john: None, extended: true, description: None },
            ModeDef { name: r"md5(md5(md5($pass)))", hashcat: Some(3500), john: None, extended: true, description: None },
            ModeDef { name: r"md5(uppercase(md5($pass)))", hashcat: Some(4300), john: None, extended: true, description: None },
            ModeDef { name: r"md5(sha1($pass))", hashcat: Some(4400), john: None, extended: true, description: None },
            ModeDef { name: r"md5($pass.$salt)", hashcat: Some(10), john: None, extended: true, description: None },
            ModeDef { name: r"md5($salt.$pass)", hashcat: Some(20), john: None, extended: true, description: None },
            ModeDef { name: r"md5(unicode($pass).$salt)", hashcat: Some(30), john: None, extended: true, description: None },
            ModeDef { name: r"md5($salt.unicode($pass))", hashcat: Some(40), john: None, extended: true, description: None },
            ModeDef { name: r"HMAC-MD5 (key = $pass)", hashcat: Some(50), john: Some(r"hmac-md5"), extended: true, description: None },
            ModeDef { name: r"HMAC-MD5 (key = $salt)", hashcat: Some(60), john: Some(r"hmac-md5"), extended: true, description: None },
            ModeDef { name: r"md5(md5($salt).$pass)", hashcat: Some(3610), john: None, extended: true, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
            ModeDef { name: r"md5($salt.md5($pass))", hashcat: Some(3710), john: None, extended: true, description: None },
            ModeDef { name: r"md5($pass.md5($salt))", hashcat: Some(3720), john: None, extended: true, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
            ModeDef { name: r"WebEdition CMS", hashcat: Some(3721), john: None, extended: false, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
            ModeDef { name: r"md5($username.0.$pass)", hashcat: Some(4210), john: None, extended: true, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
            ModeDef { name: r"md5($salt.$pass.$salt)", hashcat: Some(3800), john: None, extended: true, description: None },
            ModeDef { name: r"md5(md5($pass).md5($salt))", hashcat: Some(3910), john: None, extended: true, description: None },
            ModeDef { name: r"md5($salt.md5($salt.$pass))", hashcat: Some(4010), john: None, extended: true, description: None },
            ModeDef { name: r"md5($salt.md5($pass.$salt))", hashcat: Some(4110), john: None, extended: true, description: None },
            ModeDef { name: r"md4($salt.$pass)", hashcat: None, john: Some(r"dynamic_31"), extended: true, description: None },
            ModeDef { name: r"md4($pass.$salt)", hashcat: None, john: Some(r"dynamic_32"), extended: true, description: None },
            ModeDef { name: r"md5($salt.pad16($pass))", hashcat: None, john: Some(r"dynamic_39"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:[a-z0-9]{56}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PrestaShop", hashcat: Some(11000), john: None, extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$md2\$)?[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MD2", hashcat: None, john: Some(r"md2"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$snefru\$)?[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Snefru-128", hashcat: None, john: Some(r"snefru-128"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$NT\$)?[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"NTLM", hashcat: Some(1000), john: Some(r"nt"), extended: false, description: Some(r"Often used in Windows Active Directory.") },
        ],
    },
    PrototypeDef {
        pattern: r#"^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$"#,
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Domain Cached Credentials", hashcat: Some(1100), john: Some(r"mscash"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r#"^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$"#,
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Domain Cached Credentials 2", hashcat: Some(2100), john: Some(r"mscash2"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{SHA\}[a-z0-9\/+]{27}=$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-1(Base64)", hashcat: Some(101), john: Some(r"nsldap"), extended: false, description: None },
            ModeDef { name: r"Netscape LDAP SHA", hashcat: Some(101), john: Some(r"nsldap"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MD5 Crypt", hashcat: Some(500), john: Some(r"md5crypt"), extended: false, description: None },
            ModeDef { name: r"Cisco-IOS(MD5)", hashcat: Some(500), john: Some(r"md5crypt"), extended: false, description: None },
            ModeDef { name: r"FreeBSD MD5", hashcat: Some(500), john: Some(r"md5crypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^0x[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Lineage II C4", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$H\$[a-z0-9\/.]{31}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"phpBB v3.x", hashcat: Some(400), john: Some(r"phpass"), extended: false, description: None },
            ModeDef { name: r"Wordpress v2.6.0/2.6.1", hashcat: Some(400), john: Some(r"phpass"), extended: false, description: None },
            ModeDef { name: r"PHPass' Portable Hash", hashcat: Some(400), john: Some(r"phpass"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$P\$[a-z0-9\/.]{31}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Wordpress ≥ v2.6.2", hashcat: Some(400), john: Some(r"phpass"), extended: false, description: None },
            ModeDef { name: r"Joomla ≥ v2.5.18", hashcat: Some(400), john: Some(r"phpass"), extended: false, description: None },
            ModeDef { name: r"PHPass' Portable Hash", hashcat: Some(400), john: Some(r"phpass"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:[a-z0-9]{2}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"osCommerce", hashcat: Some(21), john: None, extended: false, description: None },
            ModeDef { name: r"xt:Commerce", hashcat: Some(21), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MD5(APR)", hashcat: Some(1600), john: None, extended: false, description: None },
            ModeDef { name: r"Apache MD5", hashcat: Some(1600), john: None, extended: false, description: None },
            ModeDef { name: r"md5apr1", hashcat: Some(1600), john: None, extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{smd5\}[a-z0-9$\/.]{31}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"AIX(smd5)", hashcat: Some(6300), john: Some(r"aix-smd5"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:.{5}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"IP.Board ≥ v2+", hashcat: Some(2811), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:.{8}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MyBB ≥ v1.2+", hashcat: Some(2811), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9]{34}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CryptoCurrency(Adress)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{40}(:.+)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-1", hashcat: Some(100), john: Some(r"raw-sha1"), extended: false, description: Some(r"Used for checksums.[link=https://en.wikipedia.org/wiki/SHA-1]See more[/link]") },
            ModeDef { name: r"Double SHA-1", hashcat: Some(4500), john: None, extended: false, description: None },
            ModeDef { name: r"RIPEMD-160", hashcat: Some(6000), john: Some(r"ripemd-160"), extended: false, description: None },
            ModeDef { name: r"Haval-160 (3 rounds)", hashcat: Some(6000), john: Some(r"dynamic_190"), extended: false, description: None },
            ModeDef { name: r"Haval-160 (4 rounds)", hashcat: Some(6000), john: Some(r"dynamic_200"), extended: false, description: None },
            ModeDef { name: r"Haval-160 (5 rounds)", hashcat: Some(6000), john: Some(r"dynamic_210"), extended: false, description: None },
            ModeDef { name: r"Haval-192 (3 rounds)", hashcat: Some(6000), john: Some(r"dynamic_220"), extended: false, description: None },
            ModeDef { name: r"Haval-192 (4 rounds)", hashcat: Some(6000), john: Some(r"dynamic_230"), extended: false, description: None },
            ModeDef { name: r"Haval-192 (5 rounds)", hashcat: Some(6000), john: Some(r"dynamic_240"), extended: false, description: None },
            ModeDef { name: r"Haval-224 (4 rounds)", hashcat: Some(6000), john: Some(r"dynamic_260"), extended: false, description: None },
            ModeDef { name: r"Haval-224 (5 rounds)", hashcat: Some(6000), john: Some(r"dynamic_270"), extended: false, description: None },
            ModeDef { name: r"Haval-160", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Tiger-160", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"HAS-160", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"LinkedIn", hashcat: Some(190), john: Some(r"raw-sha1-linkedin"), extended: false, description: Some(r"Hashcat mode is only supported in oclHashcat.") },
            ModeDef { name: r"Skein-256(160)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-512(160)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"MangosWeb Enhanced CMS", hashcat: None, john: None, extended: true, description: None },
            ModeDef { name: r"sha1(sha1(sha1($pass)))", hashcat: Some(4600), john: None, extended: true, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
            ModeDef { name: r"sha1(md5($pass))", hashcat: Some(4700), john: None, extended: true, description: None },
            ModeDef { name: r"sha1($pass.$salt)", hashcat: Some(110), john: None, extended: true, description: None },
            ModeDef { name: r"sha1($salt.$pass)", hashcat: Some(120), john: None, extended: true, description: None },
            ModeDef { name: r"sha1(unicode($pass).$salt)", hashcat: Some(130), john: None, extended: true, description: None },
            ModeDef { name: r"sha1($salt.unicode($pass))", hashcat: Some(140), john: None, extended: true, description: None },
            ModeDef { name: r"HMAC-SHA1 (key = $pass)", hashcat: Some(150), john: Some(r"hmac-sha1"), extended: true, description: None },
            ModeDef { name: r"HMAC-SHA1 (key = $salt)", hashcat: Some(160), john: Some(r"hmac-sha1"), extended: true, description: None },
            ModeDef { name: r"sha1($salt.$pass.$salt)", hashcat: Some(4710), john: None, extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MySQL5.x", hashcat: Some(300), john: Some(r"mysql-sha1"), extended: false, description: None },
            ModeDef { name: r"MySQL4.1", hashcat: Some(300), john: Some(r"mysql-sha1"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco-IOS(SHA-256)", hashcat: Some(5700), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{SSHA\}[a-z0-9\/+]{38}==$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SSHA-1(Base64)", hashcat: Some(111), john: Some(r"nsldaps"), extended: false, description: None },
            ModeDef { name: r"Netscape LDAP SSHA", hashcat: Some(111), john: Some(r"nsldaps"), extended: false, description: None },
            ModeDef { name: r"nsldaps", hashcat: Some(111), john: Some(r"nsldaps"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9=]{47}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Fortigate(FortiOS)", hashcat: Some(7000), john: Some(r"fortigate"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{48}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Haval-192", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Tiger-192", hashcat: None, john: Some(r"tiger"), extended: false, description: None },
            ModeDef { name: r"SHA-1(Oracle)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"OSX v10.4", hashcat: Some(122), john: Some(r"xsha"), extended: false, description: None },
            ModeDef { name: r"OSX v10.5", hashcat: Some(122), john: Some(r"xsha"), extended: false, description: None },
            ModeDef { name: r"OSX v10.6", hashcat: Some(122), john: Some(r"xsha"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{51}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Palshop CMS", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9]{51}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CryptoCurrency(PrivateKey)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{ssha1\}[0-9]{2}\$[a-z0-9$\/.]{44}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"AIX(ssha1)", hashcat: Some(6700), john: Some(r"aix-ssha1"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^0x0100[a-f0-9]{48}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MSSQL(2005)", hashcat: Some(132), john: Some(r"mssql05"), extended: false, description: None },
            ModeDef { name: r"MSSQL(2008)", hashcat: Some(132), john: Some(r"mssql05"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Sun MD5 Crypt", hashcat: Some(3300), john: Some(r"sunmd5"), extended: false, description: Some(r"Hashcat mode is only supported in hashcat-legacy.") },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{56}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-224", hashcat: Some(1300), john: Some(r"raw-sha224"), extended: false, description: None },
            ModeDef { name: r"sha224($salt.$pass)", hashcat: None, john: Some(r"dynamic_51"), extended: true, description: None },
            ModeDef { name: r"sha224($pass.$salt))", hashcat: None, john: Some(r"dynamic_52"), extended: true, description: None },
            ModeDef { name: r"sha224(sha224($pass))", hashcat: None, john: Some(r"dynamic_53"), extended: true, description: None },
            ModeDef { name: r"sha224(sha224_raw($pass))", hashcat: None, john: Some(r"dynamic_54"), extended: true, description: None },
            ModeDef { name: r"sha224(sha224($pass).$salt)", hashcat: None, john: Some(r"dynamic_55"), extended: true, description: None },
            ModeDef { name: r"sha224($salt.sha224($pass))", hashcat: None, john: Some(r"dynamic_56"), extended: true, description: None },
            ModeDef { name: r"sha224(sha224($salt).sha224($pass))", hashcat: None, john: Some(r"dynamic_57"), extended: true, description: None },
            ModeDef { name: r"sha224(sha224($pass).sha224($pass))", hashcat: None, john: Some(r"dynamic_58"), extended: true, description: None },
            ModeDef { name: r"Haval-224", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"SHA3-224", hashcat: Some(17300), john: None, extended: false, description: None },
            ModeDef { name: r"Skein-256(224)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-512(224)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-224", hashcat: None, john: Some(r"dynamic_330"), extended: false, description: None },
            ModeDef { name: r"Keccak-224", hashcat: Some(17700), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$2[abxy]?|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Blowfish(OpenBSD)", hashcat: Some(3200), john: Some(r"bcrypt"), extended: false, description: Some(r"Can be used in Linux Shadow Files.") },
            ModeDef { name: r"Woltlab Burning Board 4.x", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"bcrypt", hashcat: Some(3200), john: Some(r"bcrypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$y\$[.\/A-Za-z0-9]+\$[.\/a-zA-Z0-9]+\$[.\/A-Za-z0-9]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"yescrypt", hashcat: None, john: Some(r"On systems that use libxcrypt, you may use --format=crypt to use JtR in passthrough mode which uses the system's crypt function."), extended: false, description: Some(r"Can be used in Linux Shadow Files in modern Linux distributions like Ubuntu 22.04, Debian 11, Fedora 35. On hashcat this is not yet implemented, please vote (thumbs up) on this issue: https://github.com/hashcat/hashcat/issues/2816.") },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{40}:[a-f0-9]{16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Android PIN", hashcat: Some(5800), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Oracle 11g/12c", hashcat: Some(112), john: Some(r"oracle11"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"bcrypt(SHA-256)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:.{3}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"vBulletin < v3.8.5", hashcat: Some(2611), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:.{30}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"vBulletin ≥ v3.8.5", hashcat: Some(2711), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$snefru\$)?[a-f0-9]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Snefru-256", hashcat: None, john: Some(r"snefru-256"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{64}(:.+)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-256", hashcat: Some(1400), john: Some(r"raw-sha256"), extended: false, description: Some(r"256-bit key and is a good partner-function for AES. Can be used in Shadow files.") },
            ModeDef { name: r"RIPEMD-256", hashcat: None, john: Some(r"dynamic_140"), extended: false, description: None },
            ModeDef { name: r"Haval-256 (3 rounds)", hashcat: None, john: Some(r"dynamic_140"), extended: false, description: None },
            ModeDef { name: r"Haval-256 (4 rounds)", hashcat: None, john: Some(r"dynamic_290"), extended: false, description: None },
            ModeDef { name: r"Haval-256 (5 rounds)", hashcat: None, john: Some(r"dynamic_300"), extended: false, description: None },
            ModeDef { name: r"GOST R 34.11-94", hashcat: Some(6900), john: Some(r"gost"), extended: false, description: None },
            ModeDef { name: r"GOST CryptoPro S-Box", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Blake2b-256", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"SHA3-256", hashcat: Some(17400), john: Some(r"dynamic_380"), extended: false, description: None },
            ModeDef { name: r"PANAMA", hashcat: None, john: Some(r"dynamic_320"), extended: false, description: None },
            ModeDef { name: r"BLAKE2-256", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"BLAKE2-384", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-256", hashcat: None, john: Some(r"skein-256"), extended: false, description: None },
            ModeDef { name: r"Skein-512(256)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Ventrilo", hashcat: None, john: None, extended: true, description: None },
            ModeDef { name: r"sha256($pass.$salt)", hashcat: Some(1410), john: Some(r"dynamic_62"), extended: true, description: None },
            ModeDef { name: r"sha256($salt.$pass)", hashcat: Some(1420), john: Some(r"dynamic_61"), extended: true, description: None },
            ModeDef { name: r"sha256(sha256($pass))", hashcat: Some(1420), john: Some(r"dynamic_63"), extended: true, description: None },
            ModeDef { name: r"sha256(sha256_raw($pass)))", hashcat: Some(1420), john: Some(r"dynamic_64"), extended: true, description: None },
            ModeDef { name: r"sha256(sha256($pass).$salt)", hashcat: Some(1420), john: Some(r"dynamic_65"), extended: true, description: None },
            ModeDef { name: r"sha256($salt.sha256($pass))", hashcat: Some(1420), john: Some(r"dynamic_66"), extended: true, description: None },
            ModeDef { name: r"sha256(sha256($salt).sha256($pass))", hashcat: Some(1420), john: Some(r"dynamic_67"), extended: true, description: None },
            ModeDef { name: r"sha256(sha256($pass).sha256($pass))", hashcat: Some(1420), john: Some(r"dynamic_68"), extended: true, description: None },
            ModeDef { name: r"sha256(unicode($pass).$salt)", hashcat: Some(1430), john: None, extended: true, description: None },
            ModeDef { name: r"sha256($salt.unicode($pass))", hashcat: Some(1440), john: None, extended: true, description: None },
            ModeDef { name: r"HMAC-SHA256 (key = $pass)", hashcat: Some(1450), john: Some(r"hmac-sha256"), extended: true, description: None },
            ModeDef { name: r"HMAC-SHA256 (key = $salt)", hashcat: Some(1460), john: Some(r"hmac-sha256"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:[a-z0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Joomla < v2.5.18", hashcat: Some(11), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SAM(LM_Hash:NT_Hash)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MD5(Chap)", hashcat: Some(4800), john: Some(r"chap"), extended: false, description: None },
            ModeDef { name: r"iSCSI CHAP Authentication", hashcat: Some(4800), john: Some(r"chap"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"EPiServer 6.x < v4", hashcat: Some(141), john: Some(r"episerver"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{ssha256\}[0-9]{2}\$[a-z0-9$\/.]{60}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"AIX(ssha256)", hashcat: Some(6400), john: Some(r"aix-ssha256"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{80}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RIPEMD-320", hashcat: None, john: Some(r"dynamic_150"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"EPiServer 6.x ≥ v4", hashcat: Some(1441), john: Some(r"episerver"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^0x0100[a-f0-9]{88}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MSSQL(2000)", hashcat: Some(131), john: Some(r"mssql"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{96}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-384", hashcat: Some(10800), john: Some(r"raw-sha384"), extended: false, description: None },
            ModeDef { name: r"SHA3-384", hashcat: None, john: Some(r"dynamic_390"), extended: false, description: None },
            ModeDef { name: r"Skein-512(384)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"Skein-1024(384)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"sha384($salt.$pass)", hashcat: None, john: Some(r"dynamic_71"), extended: true, description: None },
            ModeDef { name: r"sha384($pass.$salt)", hashcat: None, john: Some(r"dynamic_72"), extended: true, description: None },
            ModeDef { name: r"sha384(sha384($pass))", hashcat: None, john: Some(r"dynamic_73"), extended: true, description: None },
            ModeDef { name: r"sha384(sha384_raw($pass))", hashcat: None, john: Some(r"dynamic_74"), extended: true, description: None },
            ModeDef { name: r"sha384(sha384($pass).$salt)", hashcat: None, john: Some(r"dynamic_75"), extended: true, description: None },
            ModeDef { name: r"sha384($salt.sha384($pass))", hashcat: None, john: Some(r"dynamic_76"), extended: true, description: None },
            ModeDef { name: r"sha384(sha384($salt).sha384($pass))", hashcat: None, john: Some(r"dynamic_77"), extended: true, description: None },
            ModeDef { name: r"sha384(sha384($pass).sha384($pass))", hashcat: None, john: Some(r"dynamic_78"), extended: true, description: None },
            ModeDef { name: r"Skein-384", hashcat: None, john: Some(r"dynamic_350"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{SSHA512\}[a-z0-9\/+]{96}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SSHA-512(Base64)", hashcat: Some(1711), john: Some(r"ssha512"), extended: false, description: None },
            ModeDef { name: r"LDAP(SSHA-512)", hashcat: Some(1711), john: Some(r"ssha512"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{ssha512\}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"AIX(ssha512)", hashcat: Some(6500), john: Some(r"aix-ssha512"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{128}(:.+)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-512", hashcat: Some(1700), john: Some(r"raw-sha512"), extended: false, description: Some(r"Used in Bitcoin Blockchain and Shadow Files.") },
            ModeDef { name: r"Keccak-512", hashcat: Some(1800), john: None, extended: false, description: None },
            ModeDef { name: r"Whirlpool", hashcat: Some(6100), john: Some(r"whirlpool"), extended: false, description: None },
            ModeDef { name: r"Salsa10", hashcat: None, john: None, extended: false, description: Some(r"Not considered a hash function.[link = https://bugs.php.net/bug.php?id=60783]See more[/link]") },
            ModeDef { name: r"Salsa20", hashcat: None, john: None, extended: false, description: Some(r"Not considered a hash function.[link = https://bugs.php.net/bug.php?id=60783]See more[/link]") },
            ModeDef { name: r"Blake2", hashcat: Some(600), john: Some(r"raw-blake2"), extended: false, description: Some(r"Used in Wireguard, Zcash, IPFS and more.[link = https://en.wikipedia.org/wiki/BLAKE_(hash_function)#Users_of_BLAKE2]See more[/link]") },
            ModeDef { name: r"SHA3-512", hashcat: Some(17600), john: Some(r"raw-sha3"), extended: false, description: None },
            ModeDef { name: r"Skein-512", hashcat: None, john: Some(r"skein-512"), extended: false, description: None },
            ModeDef { name: r"Skein-1024(512)", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"sha512($pass.$salt)", hashcat: Some(1710), john: None, extended: true, description: None },
            ModeDef { name: r"sha512($salt.$pass)", hashcat: Some(1720), john: None, extended: true, description: None },
            ModeDef { name: r"sha512(unicode($pass).$salt)", hashcat: Some(1730), john: None, extended: true, description: None },
            ModeDef { name: r"sha512($salt.unicode($pass))", hashcat: Some(1740), john: None, extended: true, description: None },
            ModeDef { name: r"HMAC-SHA512 (key = $pass)", hashcat: Some(1750), john: Some(r"hmac-sha512"), extended: true, description: None },
            ModeDef { name: r"BLAKE2-224", hashcat: None, john: None, extended: false, description: None },
            ModeDef { name: r"HMAC-SHA512 (key = $salt)", hashcat: Some(1760), john: Some(r"hmac-sha512"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Keccak-256", hashcat: Some(17800), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{96}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Keccak-384", hashcat: Some(17900), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{136}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"OSX v10.7", hashcat: Some(1722), john: Some(r"xsha512"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^0x0200[a-f0-9]{136}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MSSQL(2012)", hashcat: Some(1731), john: Some(r"mssql12"), extended: false, description: None },
            ModeDef { name: r"MSSQL(2014)", hashcat: Some(1731), john: Some(r"mssql12"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"OSX v10.8", hashcat: Some(7100), john: Some(r"pbkdf2-hmac-sha512"), extended: false, description: None },
            ModeDef { name: r"OSX v10.9", hashcat: Some(7100), john: Some(r"pbkdf2-hmac-sha512"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{256}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Skein-1024", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"GRUB 2", hashcat: Some(7200), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^sha1\$[a-z0-9]+\$[a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(SHA-1)", hashcat: Some(124), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{49}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Citrix Netscaler", hashcat: Some(8100), john: Some(r"citrix_ns10"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$S\$[a-z0-9\/.]{52}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Drupal > v7.x", hashcat: Some(7900), john: Some(r"drupal7"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-256 Crypt", hashcat: Some(7400), john: Some(r"sha256crypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Sybase ASE", hashcat: Some(8000), john: Some(r"sybasease"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-512 Crypt", hashcat: Some(1800), john: Some(r"sha512crypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Minecraft(AuthMe Reloaded)", hashcat: Some(20711), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^sha256\$[a-z0-9]+\$[a-f0-9]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(SHA-256)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^sha384\$[a-z0-9]+\$[a-f0-9]{96}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(SHA-384)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Clavister Secure Gateway", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{112}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco VPN Client(PCF-File)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{1329}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft MSTSC(RDP-File)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r#"^[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$"#,
        ignore_case: true,
        modes: &[
            ModeDef { name: r"NetNTLMv1-VANILLA / NetNTLMv1+ESS", hashcat: Some(5500), john: Some(r"netntlm"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r#"^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$"#,
        ignore_case: true,
        modes: &[
            ModeDef { name: r"NetNTLMv2", hashcat: Some(5600), john: Some(r"netntlmv2"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$(krb5pa|mskrb5)\$(23)?\$.+\$[a-f0-9]{1,}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5 AS-REQ Pre-Auth", hashcat: Some(7500), john: Some(r"krb5pa-md5"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SCRAM Hash", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{40}:[a-f0-9]{0,32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Redmine Project Management Web App", hashcat: Some(4521), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^([^$]+)?\$[a-f0-9]{16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SAP CODVN B (BCODE)", hashcat: Some(7700), john: Some(r"sapb"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(.+)?\$[a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SAP CODVN F/G (PASSCODE)", hashcat: Some(7800), john: Some(r"sapg"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Juniper Netscreen/SSG(ScreenOS)", hashcat: Some(22), john: Some(r"md5ns"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^0x(?:[a-f0-9]{60}|[a-f0-9]{40})$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"EPi", hashcat: Some(123), john: None, extended: false, description: Some(r"Hashcat mode is no longer supported.") },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{40}:[^*]{1,25}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SMF ≥ v1.1", hashcat: Some(121), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Woltlab Burning Board 3.x", hashcat: Some(8400), john: Some(r"wbb3"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{130}(:[a-f0-9]{40})?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"IPMI2 RAKP HMAC-SHA1", hashcat: Some(7300), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Lastpass", hashcat: Some(6800), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9\/.]{16}([:$].{1,})?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco-ASA(MD5)", hashcat: Some(2410), john: Some(r"asa-md5"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"VNC", hashcat: None, john: Some(r"vnc"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"DNSSEC(NSEC3)", hashcat: Some(8300), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RACF", hashcat: Some(8500), john: Some(r"racf"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$3\$\$[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"NTHash(FreeBSD Variant)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SHA-1 Crypt", hashcat: Some(15100), john: Some(r"sha1crypt"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{70}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"hMailServer", hashcat: Some(1421), john: Some(r"hmailserver"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MediaWiki", hashcat: Some(3711), john: Some(r"mediawiki"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{140}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Minecraft(xAuth)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2-SHA1(Generic)", hashcat: Some(20400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2-SHA256(Generic)", hashcat: Some(20300), john: Some(r"pbkdf2-hmac-sha256"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2-SHA512(Generic)", hashcat: Some(20200), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2(Cryptacular)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2(Dwayne Litzenberger)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{FSHP[0123]\|[0-9]+\|[0-9]+\}[a-z0-9\/+=]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Fairly Secure Hashed Password", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$PHPS\$.+\$[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PHPS", hashcat: Some(2612), john: Some(r"phps"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"1Password(Agile Keychain)", hashcat: Some(6600), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"1Password(Cloud Keychain)", hashcat: Some(8200), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"IKE-PSK MD5", hashcat: Some(5300), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"IKE-PSK SHA1", hashcat: Some(5400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9\/+]{27}=$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PeopleSoft", hashcat: Some(133), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(DES Crypt Wrapper)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(PBKDF2-HMAC-SHA256)", hashcat: Some(10000), john: Some(r"django"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(PBKDF2-HMAC-SHA1)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(bcrypt)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^md5\$[a-f0-9]+\$[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(MD5)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{PKCS5S2\}[a-z0-9\/+]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2(Atlassian)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^md5[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PostgreSQL MD5", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\([a-z0-9\/+]{49}\)$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Lotus Notes/Domino 8", hashcat: Some(9100), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"scrypt", hashcat: Some(8900), john: None, extended: false, description: Some(r"Used in Dogecoin and Litecoin.") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco Type 8", hashcat: Some(9200), john: Some(r"cisco8"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco Type 9", hashcat: Some(9300), john: Some(r"cisco9"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Office 2007", hashcat: Some(9400), john: Some(r"office"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Office 2010", hashcat: Some(9500), john: Some(r"office"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\\$office\\$2016\\$[0-9]\\$[0-9]{6}\\$[^$]{24}\\$[^$]{88}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Office 2016 - SheetProtection", hashcat: Some(25300), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Office 2013", hashcat: Some(9600), john: Some(r"office"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Android FDE ≤ 4.3", hashcat: Some(8800), john: Some(r"fde"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$krb5tgs\$23\$\*[^*]*\*\$[a-f0-9]{32}\$[a-f0-9]{64,40960}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5 TGS-REP etype 23", hashcat: Some(13100), john: Some(r"krb5tgs"), extended: false, description: Some(r"Used in Windows Active Directory.") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Office ≤ 2003 (MD5+RC4)", hashcat: Some(9700), john: Some(r"oldoffice"), extended: false, description: None },
            ModeDef { name: r"Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1", hashcat: Some(9710), john: Some(r"oldoffice"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Office ≤ 2003 (SHA1+RC4)", hashcat: Some(9800), john: Some(r"oldoffice"), extended: false, description: None },
            ModeDef { name: r"Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1", hashcat: Some(9810), john: Some(r"oldoffice"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}:[a-f0-9]{10}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MS Office ⇐ 2003 $3, SHA1 + RC4, collider #2", hashcat: Some(9820), john: Some(r"oldoffice"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$radmin2\$)?[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RAdmin v2.x", hashcat: Some(9900), john: Some(r"radmin"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\{x-issha,\s[0-9]{4}\}[a-z0-9\/+=]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SAP CODVN H (PWDSALTEDHASH) iSSHA-1", hashcat: Some(10300), john: Some(r"saph"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"CRAM-MD5", hashcat: Some(10200), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{16}:2:4:[a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SipHash", hashcat: Some(10100), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-f0-9]{4,}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco Type 7", hashcat: None, john: None, extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[a-z0-9\/.]{13,}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"BigCrypt", hashcat: None, john: Some(r"bcrypt"), extended: true, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$cisco4\$)?[a-z0-9\/.]{43}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Cisco Type 4", hashcat: None, john: Some(r"cisco4"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Django(bcrypt-SHA256)", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PostgreSQL Challenge-Response Authentication (MD5)", hashcat: Some(11100), john: Some(r"postgres"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Siemens-S7", hashcat: None, john: Some(r"siemens-s7"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$pst\$)?[a-f0-9]{8}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Microsoft Outlook PST", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^sha256[:$][0-9]+[:$][a-z0-9\/+=]+[:$][a-z0-9\/+]{32,128}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PBKDF2-HMAC-SHA256(PHP)", hashcat: Some(10900), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^(\$dahua\$)?[a-z0-9]{8}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Dahua", hashcat: None, john: Some(r"dahua"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MySQL Challenge-Response Authentication (SHA1)", hashcat: Some(11200), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$pdf\$1\*[2|3]\*[0-9]{2}\*[-0-9]{1,6}\*[0-9]\*[0-9]{2}\*[a-f0-9]{32,32}\*[0-9]{2}\*[a-f0-9]{64}\*[0-9]{2}\*[a-f0-9]{64}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PDF 1.1 - 1.3 (Acrobat 2 - 4)", hashcat: Some(10400), john: Some(r"pdf"), extended: false, description: None },
            ModeDef { name: r"PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1", hashcat: Some(10410), john: Some(r"pdf"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$pdf\$1\*[2|3]\*[0-9]{2}\*[-0-9]{1,6}\*[0-9]\*[0-9]{2}\*[a-f0-9]{32}\*[0-9]{2}\*[a-f0-9]{64}\*[0-9]{2}\*[a-f0-9]{64}:[a-f0-9]{10}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2", hashcat: Some(10420), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PDF 1.4 - 1.6 (Acrobat 5 - 8)", hashcat: Some(10500), john: Some(r"pdf"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$pdf\$5\*[5|6]\*[0-9]{3}\*[-0-9]{1,6}\*[0-9]\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PDF 1.7 Level 3 (Acrobat 9)", hashcat: Some(10600), john: Some(r"pdf"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$pdf\$5\*[5|6]\*[0-9]{3}\*[-0-9]{1,6}\*[0-9]\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}\*[0-9]{1,4}\*[a-f0-9]{0,1024}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PDF 1.7 Level 8 (Acrobat 10 - 11)", hashcat: Some(10700), john: Some(r"pdf"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5asrep\$23\$[^:]+:[a-f0-9]{32,32}\$[a-f0-9]{64,40960}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5 AS-REP etype 23", hashcat: Some(18200), john: Some(r"krb5pa-sha1"), extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5tgs\$17\$[^$]{1,512}\$[^$]{1,512}\$[^$]{1,4}?\$?[a-f0-9]{1,32}\$[a-f0-9]{64,40960}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)", hashcat: Some(19600), john: None, extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5tgs\$18\$[^$]{1,512}\$[^$]{1,512}\$[^$]{1,4}?\$?[a-f0-9]{1,32}\$[a-f0-9]{64,40960}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)", hashcat: Some(19700), john: None, extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5pa\$17\$[^$]{1,512}\$[^$]{1,512}\$[a-f0-9]{104,112}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5, etype 17, Pre-Auth", hashcat: Some(19800), john: None, extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5pa\$17\$[^$]{1,512}\$[^$]{1,512}\$[^$]{0,512}\$[a-f0-9]{104,112}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5, etype 17, Pre-Auth (with salt)", hashcat: None, john: Some(r"krb5pa-sha1"), extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5pa\$18\$[^$]{1,512}\$[^$]{1,512}\$[^$]{0,512}\$[a-f0-9]{104,112}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5, etype 18, Pre-Auth (with salt)", hashcat: None, john: Some(r"krb5pa-sha1"), extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$krb5pa\$18\$[^$]{1,512}\$[^$]{1,512}\$[a-f0-9]{104,112}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Kerberos 5, etype 18, Pre-Auth", hashcat: Some(19900), john: None, extended: false, description: Some(r"Used for Windows Active Directory") },
        ],
    },
    PrototypeDef {
        pattern: r"\$bitcoin\$[0-9]{2,4}\$[a-f0-9$]{250,350}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Bitcoin / Litecoin", hashcat: Some(11300), john: Some(r"bitcoin"), extended: false, description: Some(r"Use Bitcoin2John.py to extract the hash for cracking.") },
        ],
    },
    PrototypeDef {
        pattern: r"\$ethereum\$[a-z0-9*]{150,250}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Ethereum Wallet, PBKDF2-HMAC-SHA256", hashcat: Some(15600), john: Some(r"ethereum-opencl"), extended: false, description: Some(r"Use ethereum2john.py to crack.") },
            ModeDef { name: r"Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256", hashcat: Some(16300), john: Some(r"ethereum-presale-opencl"), extended: false, description: Some(r"Use ethereum2john.py to crack.") },
        ],
    },
    PrototypeDef {
        pattern: r"\$monero\$(0)\*[a-f0-9]{32,3196}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Monero", hashcat: None, john: Some(r"monero"), extended: false, description: Some(r"Use monero2john.py to crack.") },
        ],
    },
    PrototypeDef {
        pattern: r"^\$electrum\$[1-3]\*[a-f0-9]{32,32}\*[a-f0-9]{32,32}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Electrum Wallet (Salt-Type 1-3)", hashcat: Some(16600), john: Some(r"electrum"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$electrum\$4\*[a-f0-9]{1,66}\*[a-f0-9]{128,32768}\*[a-f0-9]{64,64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Electrum Wallet (Salt-Type 4)", hashcat: Some(21700), john: Some(r"electrum"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$electrum\$5\*[a-f0-9]{66,66}\*[a-f0-9]{2048,2048}\*[a-f0-9]{64,64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Electrum Wallet (Salt-Type 5)", hashcat: Some(21800), john: Some(r"electrum"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$ab\$[0-9]{1}\*[0-9]{1}\*[0-9]{1,6}\*[a-f0-9]{128}\*[a-f0-9]{128}\*[a-f0-9]{32}\*[a-f0-9]{192}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Android Backup", hashcat: Some(18900), john: Some(r"androidbackup"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$zip2\$\*[0-9]{1}\*[0-9]{1}\*[0-9]{1}\*[a-f0-9]{16,32}\*[a-f0-9]{1,6}\*[a-f0-9]{1,6}\*[a-f0-9]+\*[a-f0-9]{20}\*\$\/zip2\$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"WinZip", hashcat: Some(13600), john: Some(r"zip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$itunes_backup\$\*[0-9]{1,2}\*[a-f0-9]{80}\*[0-9]{1,6}\*[a-f0-9]{40}\*[0-9]{0,10}\*[a-f0-9]{0,40}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"iTunes backup >= 10.0", hashcat: Some(14800), john: Some(r"itunes-backup"), extended: false, description: None },
            ModeDef { name: r"iTunes backup < 10.0", hashcat: Some(14700), john: Some(r"itunes-backup"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$telegram\$[a-f0-9*]{99}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Telegram Mobile App Passcode (SHA256)", hashcat: Some(22301), john: Some(r"Telegram"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\\$telegram\\$1\\*4000\\*[a-f0-9]{64}\\*[a-f0-9]{576}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Telegram Desktop 1.3.9", hashcat: None, john: Some(r"telegram"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\\$telegram\\$2\\*100000\\*[a-f0-9]{64}\\*[a-f0-9]{576}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Telegram Desktop >= 2.1.14-beta / 2.2.0", hashcat: None, john: Some(r"telegram"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$BLAKE2\$[a-f0-9]{128}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"BLAKE2b-512", hashcat: Some(600), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$oldoffice\$[a-f0-9*]{100}:[a-f0-9]{10}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MS Office ⇐ 2003 $0/$1, MD5 + RC4, collider #2", hashcat: Some(9720), john: Some(r"oldoffice"), extended: false, description: Some(r"Use office2john.py to grab the hash.") },
        ],
    },
    PrototypeDef {
        pattern: r"\$office\$2016\$[0-9]\$[0-9]{6}\$[^$]{24}\$[^$]{88}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"MS Office 2016 - SheetProtection", hashcat: Some(25300), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$7z\$[0-9]\$[0-9]{1,2}\$[0-9]{1}\$[^$]{0,64}\$[0-9]{1,2}\$[a-f0-9]{32}\$[0-9]{1,10}\$[0-9]{1,6}\$[0-9]{1,6}\$[a-f0-9]{2,}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"7-zip", hashcat: Some(11600), john: Some(r"7z"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$zip3\$\*[0-9]\*[0-9]\*256\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SecureZIP AES-256", hashcat: Some(23003), john: Some(r"securezip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$zip3\$\*[0-9]\*[0-9]\*192\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SecureZIP AES-192", hashcat: Some(23002), john: Some(r"securezip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$zip3\$\*[0-9]\*[0-9]\*128\*[0-9]\*[a-f0-9]{0,32}\*[a-f0-9]{288}\*[0-9]\*[0-9]\*[0-9]\*[^\s]{0,64}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"SecureZIP AES-128", hashcat: Some(23001), john: Some(r"securezip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pkzip2?\$(1)\*[0-9]{1}\*[0-9]{1}\*[0-9a-f]{1,3}\*[0-9a-f]{1,8}\*[0-9a-f]{1,4}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*(8)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PKZIP (Compressed)", hashcat: Some(17200), john: Some(r"pkzip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pkzip2?\$(1)\*[0-9]{1}\*[0-9]{1}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}\*(0)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PKZIP (Uncompressed)", hashcat: Some(17210), john: Some(r"pkzip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,3}\*([^0*][0-9a-f]{0,2})\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*(8)\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PKZIP (Compressed Multi-File)", hashcat: Some(17220), john: Some(r"pkzip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,8}\*([0-9a-f]{1,8})\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*([08])\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[a-f0-9]+\*\$\/pkzip2?\$$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PKZIP (Mixed Multi-File)", hashcat: Some(17225), john: Some(r"pkzip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$pkzip2?\$([2-8])\*[0-9]{1}(\*[0-9]{1}\*[0-9a-f]{1,3}\*[0-9a-f]{1,8}\*[0-9a-f]{1,8}(\*[0-9a-f]{1,8})?\*[0-9a-f]{1,8}\*[0-9a-f]+)+\*\$\/pkzip2?\$$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"PKZIP (Mixed Multi-File Checksum-Only)", hashcat: Some(17230), john: Some(r"pkzip"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$argon2i\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Argon2i", hashcat: None, john: Some(r"argon2"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$argon2id\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Argon2id", hashcat: None, john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$argon2d\$v=19\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\$[^$]+\$[^\s]{6,134}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Argon2d", hashcat: None, john: Some(r"argon2"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$bitlocker\$[0-9]\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{7}\$[a-f0-9]{2}\$[a-f0-9]{24}\$[a-f0-9]{2}\$[a-f0-9]{120}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"BitLocker", hashcat: Some(22100), john: Some(r"bitlocker"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"\$racf\$\*.{1,}\*[A-F0-9]{16}",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RACF", hashcat: Some(8500), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$sshng\$4\$16\$[0-9]{32}\$1232\$[a-f0-9]{2464}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RSA/DSA/EC/OpenSSH Private Keys ($4$)", hashcat: Some(22941), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$RAR3\$\*(1)\*[0-9a-f]{1,16}\*[0-9a-f]{1,8}\*[0-9a-f]{1,16}\*[0-9a-f]{1,16}\*[01]\*([0-9a-f]+|[^*]{1,64}\*[0-9a-f]{1,16})\*30$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RAR3-p (Uncompressed)", hashcat: Some(23700), john: Some(r"rar"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$RAR3\$\*(1)\*[0-9a-f]{1,16}\*[0-9a-f]{1,8}\*[0-9a-f]{1,16}\*[0-9a-f]{1,16}\*[01]\*([0-9a-f]+|[^*]{1,64}\*[0-9a-f]{1,16})\*(31|32|33|34|35)$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RAR3-p (Compressed)", hashcat: Some(23800), john: Some(r"rar"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$RAR3\$\*0\*[0-9a-f]{1,16}\*[0-9a-f]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RAR3-hp", hashcat: Some(12500), john: Some(r"rar"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$rar5\$[0-9a-f]{1,2}\$[0-9a-f]{1,32}\$[0-9a-f]{1,2}\$[0-9a-f]{1,32}\$[0-9a-f]{1,2}\$[0-9a-f]{1,16}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"RAR5", hashcat: Some(13000), john: Some(r"rar5"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*1\*\d+\*\d\*[0-9a-f]{32}\*[0-9a-f]{64}\*[0-9a-f]{32}\*[0-9a-f]{64}\*\d\*[^*]*(\*[0-9a-f]+)?$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"KeePass 1 AES (without keyfile)", hashcat: Some(13400), john: Some(r"KeePass"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*1\*\d+\*\d\*[0-9a-f]{32}\*[0-9a-f]{64}\*[0-9a-f]{32}\*[0-9a-f]{64}\*\d\*[^*]*(\*[0-9a-f]+)?\*\d+\*\d+\*[0-9a-f]{64}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"KeePass 1 TwoFish (with keyfile)", hashcat: Some(13400), john: Some(r"KeePass"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*2\*\d+\*\d+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"KeePass 2 AES (without keyfile)", hashcat: Some(13400), john: Some(r"KeePass"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$keepass\$\*2\*\d+\*\d+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*[0-9a-f]+\*\d+\*\d+\*[0-9a-f]+$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"KeePass 2 AES (with keyfile)", hashcat: Some(13400), john: Some(r"KeePass"), extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^\$odf\$\*1\*1\*100000\*32\*[a-f0-9]{64}\*16\*[a-f0-9]{32}\*16\*[a-f0-9]{32}\*0\*[a-f0-9]{2048}$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"Open Document Format (ODF) 1.2 (SHA-256, AES)", hashcat: Some(18400), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"JWT (JSON Web Token)", hashcat: Some(16500), john: None, extended: false, description: None },
        ],
    },
    PrototypeDef {
        pattern: r"WPA\*0[12]\*([0-9a-fA-F]+)\*",
        ignore_case: true,
        modes: &[
            ModeDef { name: r"WPA-PBKDF2-PMKID+EAPOL", hashcat: Some(22000), john: None, extended: false, description: None },
        ],
    },
];


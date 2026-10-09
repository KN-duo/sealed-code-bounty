//! Strict shared manifest. The committed hash covers sorted, compact JSON bytes.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u8,
    pub name: String,
    pub image_tarball: ImageTarball,
    pub target: Target,
    pub limits: Limits,
    pub determinism: Determinism,
    pub flag_placeholder: String,
    pub entrypoint: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageTarball {
    pub url: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    TcpService {
        host: String,
        port: u16,
    },
    Binary {
        exec: String,
        io: String,
        argv: Vec<String>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub timeout_seconds: u64,
    pub memory_mb: u64,
    pub cpus: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Determinism {
    pub aslr: String,
    pub seed: u32,
}

fn text(s: &str) -> bool {
    s.len() <= 4096 && s.bytes().all(|b| (32..=126).contains(&b))
}

impl Manifest {
    pub fn parse(bytes: &[u8], environment_hash: &str) -> Result<Self, &'static str> {
        let m: Self = serde_json::from_slice(bytes).map_err(|_| "invalid manifest schema")?;
        // Conversion through Value sorts keys recursively with serde_json's default map.
        let canonical =
            serde_json::to_vec(&serde_json::to_value(&m).map_err(|_| "invalid manifest")?)
                .map_err(|_| "invalid manifest")?;
        if canonical != bytes {
            return Err("manifest must use canonical JSON bytes");
        }
        if m.format_version != 2
            || m.name.is_empty()
            || !text(&m.name)
            || m.image_tarball.url.is_empty()
            || !text(&m.image_tarball.url)
            || !crate::submission_store::valid_receipt(&m.image_tarball.sha256)
            || m.image_tarball.sha256 != environment_hash
            || m.flag_placeholder != "{{FLAG}}"
            || !(1..=60).contains(&m.limits.timeout_seconds)
            || !(16..=512).contains(&m.limits.memory_mb)
            || m.limits.cpus != 1
            || !matches!(m.determinism.aslr.as_str(), "on" | "off")
            || m.entrypoint.is_empty()
            || m.entrypoint.len() > 64
            || m.entrypoint[0].is_empty()
            || !m.entrypoint.iter().all(|s| text(s))
        {
            return Err("invalid manifest values or environment hash");
        }
        match &m.target {
            Target::TcpService { host, port } if host == "target" && *port > 0 => {}
            Target::Binary { exec, io, argv }
                if !exec.is_empty()
                    && text(exec)
                    && io == "stdio"
                    && argv.len() <= 64
                    && argv.iter().all(|s| text(s))
                    && m.entrypoint.first() == Some(exec)
                    && m.entrypoint[1..] == argv[..] => {}
            _ => return Err("invalid manifest target"),
        }
        Ok(m)
    }
}

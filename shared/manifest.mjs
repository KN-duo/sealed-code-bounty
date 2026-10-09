// Manifest v2 wire contract shared by browser and CLI. The enclave independently
// validates these same bytes. URLs are metadata; retrieval uses committed hashes.
export const FLAG_PLACEHOLDER = "{{FLAG}}";
export const MANIFEST_FORMAT_VERSION = 2;

function object(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== [...fields].sort().join(",")) {
    throw new Error(`${label} has missing or unknown fields`);
  }
}

function ascii(value, label, nonempty = true) {
  if (typeof value !== "string" || value.length > 4096 || (nonempty && !value.length) || /[^\x20-\x7e]/.test(value)) {
    throw new Error(`${label} must contain printable ASCII characters`);
  }
}

function integer(value, min, max, label) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${label} must be an integer from ${min} to ${max}`);
  }
}

function tokens(value, label, nonempty) {
  if (!Array.isArray(value) || value.length > 64 || (nonempty && value.length === 0)) {
    throw new Error(`${label} must be ${nonempty ? "a nonempty" : "an"} argument array`);
  }
  value.forEach((token, i) => ascii(token, `${label}[${i}]`, nonempty && i === 0));
}

export function validateManifest(m) {
  object(m, ["format_version", "name", "image_tarball", "target", "limits", "determinism", "flag_placeholder", "entrypoint"], "manifest");
  if (m.format_version !== MANIFEST_FORMAT_VERSION) throw new Error("Unsupported manifest format_version");
  ascii(m.name, "name");
  object(m.image_tarball, ["url", "sha256"], "image_tarball");
  ascii(m.image_tarball.url, "image_tarball.url");
  if (typeof m.image_tarball.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(m.image_tarball.sha256)) {
    throw new Error("image_tarball.sha256 must be 64 lowercase hex characters");
  }
  if (m.target?.kind === "tcp_service") {
    object(m.target, ["kind", "host", "port"], "target");
    ascii(m.target.host, "target.host");
    if (m.target.host !== "target") throw new Error("target.host must be target");
    integer(m.target.port, 1, 65535, "target.port");
  } else if (m.target?.kind === "binary") {
    object(m.target, ["kind", "exec", "io", "argv"], "target");
    ascii(m.target.exec, "target.exec");
    if (m.target.io !== "stdio") throw new Error("target.io must be stdio");
    tokens(m.target.argv, "target.argv", false);
  } else {
    throw new Error("target.kind must be tcp_service or binary");
  }
  object(m.limits, ["timeout_seconds", "memory_mb", "cpus"], "limits");
  integer(m.limits.timeout_seconds, 1, 60, "limits.timeout_seconds");
  integer(m.limits.memory_mb, 16, 512, "limits.memory_mb");
  integer(m.limits.cpus, 1, 1, "limits.cpus");
  object(m.determinism, ["aslr", "seed"], "determinism");
  if (!["on", "off"].includes(m.determinism.aslr)) throw new Error("determinism.aslr must be on or off");
  integer(m.determinism.seed, 0, 4294967295, "determinism.seed");
  if (m.flag_placeholder !== FLAG_PLACEHOLDER) throw new Error("flag_placeholder must be {{FLAG}}");
  tokens(m.entrypoint, "entrypoint", true);
  if (m.target.kind === "binary" && JSON.stringify(m.entrypoint) !== JSON.stringify([m.target.exec, ...m.target.argv])) {
    throw new Error("binary entrypoint must equal [target.exec, ...target.argv]");
  }
  return m;
}

function sortedJson(value) {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${sortedJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function manifestCanonicalJson(manifest) {
  return sortedJson(validateManifest(manifest));
}

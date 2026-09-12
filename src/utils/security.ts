import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import child_process from "node:child_process";

/**
 * Safely masks sensitive tokens, passwords, and private keys for console and log output.
 * Guarantees that short secrets are never exposed via overlapping prefixes/suffixes.
 * Example: sample_secure_token_value_here -> samp...here
 */
export function redactSecret(secret: string): string {
  if (!secret || typeof secret !== "string") return "";
  const trimmed = secret.trim();
  if (trimmed.length < 16) {
    return "********";
  }
  const prefix = trimmed.slice(0, 7);
  const suffix = trimmed.slice(-4);
  return `${prefix}...${suffix}`;
}

/**
 * Sanitizes input strings to prevent CRLF injection and control character injection
 * into SSH config and Git config files.
 */
export function sanitizeConfigString(val: string): string {
  if (!val || typeof val !== "string") return "";
  // Strip carriage returns, newlines, null bytes, and non-printable control characters
  return val.replace(/[\r\n\0\x00-\x1F\x7F]/g, "").trim();
}

/**
 * Sanitizes SSH key paths to prevent shell command execution or argument injection.
 */
export function sanitizeSshKeyPath(pathStr: string): string {
  if (!pathStr || typeof pathStr !== "string") return "";
  const cleaned = sanitizeConfigString(pathStr);
  return cleaned.replace(/["'`$\\;&|><]/g, "");
}

/**
 * Redact userinfo from a remote URL so PATs are never printed to the terminal.
 * https://user:ghp_xxx@host/repo -> https://user:********@host/repo
 */
export function redactRemoteUrl(url: string): string {
  if (!url || typeof url !== "string") return "";
  return url.replace(/^(https?:\/\/)([^/@:]+)(:[^@]*)?@/i, (_m, proto: string, user: string, pass?: string) => {
    if (pass) return `${proto}${user}:********@`;
    return `${proto}********@`;
  });
}

/** Host / account-id tokens allowed in SSH `Host` / `HostName` lines. */
export function isSafeSshHostToken(value: string): boolean {
  return typeof value === "string" && /^[A-Za-z0-9._-]+$/.test(value);
}

/** IdentityFile paths: no quotes, wildcards, or shell metacharacters. */
export function isSafeSshIdentityFile(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const cleaned = sanitizeConfigString(value);
  if (cleaned !== value.trim()) return false;
  if (/["'`$\\;&|<>*?[\]]/.test(cleaned)) return false;
  return cleaned.length > 0;
}

/** SSH key file basename (no path separators or traversal). */
export function isSafeSshKeyBasename(name: string): boolean {
  return typeof name === "string" && /^[A-Za-z0-9._-]+$/.test(name) && !name.includes("..");
}

/**
 * Real git executable path embedded into shims. Basename must be git/git.exe
 * and the path must not contain shell metacharacters.
 */
export function isSafeGitExecutablePath(filePath: string): boolean {
  if (!filePath || typeof filePath !== "string") return false;
  if (/[\0\r\n`$;&|<>!"]/.test(filePath)) return false;
  const base = path.basename(filePath).toLowerCase();
  return base === "git" || base === "git.exe";
}

export function unixSingleQuote(value: string): string {
  // POSIX-safe: 'foo'"'"'bar'  →  foo'bar
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

/** Git config / includeIf path: strip quotes and brackets that can close sections. */
export function sanitizeGitConfigPath(value: string): string {
  return sanitizeConfigString(value).replace(/["[\]]/g, "");
}

/**
 * Retrieves a machine fingerprint for vault key derivation (not a hardware secret).
 * Falls back gracefully to system info if restricted.
 */
export function getMachineHardwareId(): string {
  const platform = process.platform;

  try {
    if (platform === "linux") {
      // 1. /etc/machine-id
      if (fs.existsSync("/etc/machine-id")) {
        const id = fs.readFileSync("/etc/machine-id", "utf-8").trim();
        if (id) return `linux-machine-id:${id}`;
      }
      // 2. /var/lib/dbus/machine-id
      if (fs.existsSync("/var/lib/dbus/machine-id")) {
        const id = fs.readFileSync("/var/lib/dbus/machine-id", "utf-8").trim();
        if (id) return `linux-dbus-id:${id}`;
      }
    } else if (platform === "darwin") {
      // macOS IOPlatformUUID
      try {
        const out = child_process.execSync("ioreg -rd1 -c IOPlatformExpertDevice", {
          encoding: "utf-8",
          stdio: ["ignore", "pipe", "ignore"],
        });
        const match = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
        if (match && match[1]) {
          return `darwin-uuid:${match[1]}`;
        }
      } catch {
        // fall through
      }
    } else if (platform === "win32") {
      // Windows MachineGuid via reg query
      try {
        const out = child_process.execSync(
          'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
          { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }
        );
        const match = out.match(/MachineGuid\s+REG_SZ\s+([a-fA-F0-9-]+)/);
        if (match && match[1]) {
          return `win-guid:${match[1]}`;
        }
      } catch {
        // fall through
      }
    }
  } catch {
    // fall through to fallback
  }

  // Fallback to combined machine characteristics
  const host = os.hostname();
  const user = os.userInfo().username;
  const home = os.homedir();
  const cpus = os.cpus();
  const cpuModel = cpus.length > 0 ? cpus[0].model : "unknown-cpu";
  return `fallback-machine:${host}:${user}:${home}:${cpuModel}`;
}

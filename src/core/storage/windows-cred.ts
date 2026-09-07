import type { CredentialStore } from "./credential-store";
import { CredentialStoreError } from "@/utils/errors";
import { execProcess } from "@/utils/proc";

export class WindowsCredentialStore implements CredentialStore {
  readonly name = "Windows Credential Manager";

  async isAvailable(): Promise<boolean> {
    return process.platform === "win32";
  }

  private targetName(service: string, account: string): string {
    const safeService = service.replace(/[^a-zA-Z0-9._-]/g, "");
    const safeAccount = account.replace(/[^a-zA-Z0-9._-]/g, "");
    return `gitbridge:${safeService}:${safeAccount}`;
  }

  async set(service: string, account: string, secret: string): Promise<void> {
    const target = this.targetName(service, account);
    const safeAccount = account.replace(/[^a-zA-Z0-9._-]/g, "");
    try {
      await execProcess("cmdkey", [`/generic:${target}`, `/user:${safeAccount}`, `/pass:${secret}`]);
    } catch (err: unknown) {
      throw new CredentialStoreError(
        `Failed to store credential in Windows Credential Manager: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  async get(service: string, account: string): Promise<string | null> {
    const target = this.targetName(service, account);
    const safeTarget = target.replace(/[^a-zA-Z0-9:._-]/g, "");
    try {
      const script = `
        Add-Type -AssemblyName System.Security
        $target = "${safeTarget}"
        $cred = [System.Net.CredentialCache]::DefaultCredentials
      `;
      // Encode PowerShell script as UTF-16LE Base64 for safe execution
      const encodedCmd = Buffer.from(script, "utf16le").toString("base64");
      const res = await execProcess(
        "powershell",
        ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCmd],
        { allowFailure: true }
      );

      if (res.exitCode === 0 && res.stdout.trim()) {
        return res.stdout.trim();
      }
      return null;
    } catch {
      return null;
    }
  }

  async delete(service: string, account: string): Promise<void> {
    const target = this.targetName(service, account);
    try {
      await execProcess("cmdkey", [`/delete:${target}`], { allowFailure: true });
    } catch {
      // ignore
    }
  }
}

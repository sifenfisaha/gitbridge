import fs from "node:fs";
import path from "node:path";
import { ConfigStore } from "../config/config-store";
import { SshConfigGenerator } from "./ssh-config-generator";
import { collapseTilde } from "@/utils/platform";
import { replaceManagedBlock, removeManagedBlock } from "@/utils/managed-block";

export const SSH_BLOCK_START = "# --- BEGIN GITBRIDGE MANAGED BLOCK ---";
export const SSH_BLOCK_END = "# --- END GITBRIDGE MANAGED BLOCK ---";

export class SshInjector {
  private store: ConfigStore;

  constructor(store: ConfigStore) {
    this.store = store;
  }

  isInstalled(targetFile?: string): boolean {
    const sshConfigFile = targetFile || this.store.getPathResolver().getUserSshConfigFile();
    if (!fs.existsSync(sshConfigFile)) return false;
    const content = fs.readFileSync(sshConfigFile, "utf-8");
    return content.includes(SSH_BLOCK_START) && content.includes(SSH_BLOCK_END);
  }

  private createBackup(sshConfigFile: string): string | null {
    if (!fs.existsSync(sshConfigFile)) return null;

    const backupsDir = this.store.getPathResolver().getBackupsDir();
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupFile = path.join(backupsDir, `ssh_config.${timestamp}.bak`);
    fs.copyFileSync(sshConfigFile, backupFile);

    const primaryBak = `${sshConfigFile}.gitbridge.bak`;
    if (!fs.existsSync(primaryBak)) {
      fs.copyFileSync(sshConfigFile, primaryBak);
    }

    return backupFile;
  }

  inject(targetFile?: string): { success: boolean; backupPath: string | null } {
    const generator = new SshConfigGenerator(this.store);
    const generatedPath = generator.generate();

    const sshConfigFile = targetFile || this.store.getPathResolver().getUserSshConfigFile();
    const sshDir = path.dirname(sshConfigFile);
    if (!fs.existsSync(sshDir)) {
      fs.mkdirSync(sshDir, { recursive: true, mode: 0o700 });
    }

    const backupPath = this.createBackup(sshConfigFile);

    let originalContent = "";
    if (fs.existsSync(sshConfigFile)) {
      originalContent = fs.readFileSync(sshConfigFile, "utf-8");
    }

    const includePath = collapseTilde(generatedPath);
    const blockContent = [
      SSH_BLOCK_START,
      `# Do not edit this block directly. Manage via: gitbridge / gb`,
      `Include ${includePath}`,
      SSH_BLOCK_END,
    ].join("\n");

    let newContent: string;

    if (originalContent.includes(SSH_BLOCK_START)) {
      const replaced = replaceManagedBlock(originalContent, SSH_BLOCK_START, SSH_BLOCK_END, `${blockContent}\n`);
      if (!replaced.ok || replaced.content === undefined) {
        return { success: false, backupPath };
      }
      newContent = replaced.content;
    } else {
      // Put Include block at the very top of SSH config so aliases have precedence
      newContent = `${blockContent}\n\n${originalContent.trim()}`.trim() + "\n";
    }

    fs.writeFileSync(sshConfigFile, newContent, { encoding: "utf-8", mode: 0o600 });
    return { success: true, backupPath };
  }

  remove(targetFile?: string): boolean {
    const sshConfigFile = targetFile || this.store.getPathResolver().getUserSshConfigFile();
    if (!fs.existsSync(sshConfigFile)) return true;

    const originalContent = fs.readFileSync(sshConfigFile, "utf-8");
    if (!originalContent.includes(SSH_BLOCK_START)) return true;

    const removed = removeManagedBlock(originalContent, SSH_BLOCK_START, SSH_BLOCK_END);
    if (!removed.ok || removed.content === undefined) {
      return false;
    }
    fs.writeFileSync(sshConfigFile, removed.content, { encoding: "utf-8", mode: 0o600 });

    return true;
  }
}

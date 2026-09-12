import fs from "node:fs";
import path from "node:path";
import { ConfigStore } from "../config/config-store";
import { GitConfigGenerator } from "./config-generator";
import { replaceManagedBlock, removeManagedBlock } from "@/utils/managed-block";

export const GITCONFIG_BLOCK_START = "# --- BEGIN GITBRIDGE MANAGED BLOCK ---";
export const GITCONFIG_BLOCK_END = "# --- END GITBRIDGE MANAGED BLOCK ---";

export class GitConfigInjector {
  private store: ConfigStore;

  constructor(store: ConfigStore) {
    this.store = store;
  }

  isInstalled(targetFile?: string): boolean {
    const gitConfigFile = targetFile || this.store.getPathResolver().getUserGitConfigFile();
    if (!fs.existsSync(gitConfigFile)) return false;
    const content = fs.readFileSync(gitConfigFile, "utf-8");
    return content.includes(GITCONFIG_BLOCK_START) && content.includes(GITCONFIG_BLOCK_END);
  }

  private createBackup(gitConfigFile: string): string | null {
    if (!fs.existsSync(gitConfigFile)) return null;

    const backupsDir = this.store.getPathResolver().getBackupsDir();
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupFile = path.join(backupsDir, `gitconfig.${timestamp}.bak`);
    fs.copyFileSync(gitConfigFile, backupFile);

    // Also maintain primary .bak
    const primaryBak = `${gitConfigFile}.gitbridge.bak`;
    if (!fs.existsSync(primaryBak)) {
      fs.copyFileSync(gitConfigFile, primaryBak);
    }

    return backupFile;
  }

  inject(targetFile?: string): { success: boolean; backupPath: string | null } {
    const generator = new GitConfigGenerator(this.store);
    const { mainConfigPath } = generator.generate();

    const gitConfigFile = targetFile || this.store.getPathResolver().getUserGitConfigFile();
    const backupPath = this.createBackup(gitConfigFile);

    let originalContent = "";
    if (fs.existsSync(gitConfigFile)) {
      originalContent = fs.readFileSync(gitConfigFile, "utf-8");
    }

    const blockContent = [
      GITCONFIG_BLOCK_START,
      `# Do not edit this block directly. Manage via: gitbridge / gb`,
      `[include]`,
      `    path = ${mainConfigPath}`,
      GITCONFIG_BLOCK_END,
    ].join("\n");

    let newContent: string;

    if (originalContent.includes(GITCONFIG_BLOCK_START)) {
      const replaced = replaceManagedBlock(originalContent, GITCONFIG_BLOCK_START, GITCONFIG_BLOCK_END, `${blockContent}\n`);
      if (!replaced.ok || replaced.content === undefined) {
        return { success: false, backupPath };
      }
      newContent = replaced.content;
    } else {
      newContent = `${originalContent.trimEnd()}\n\n${blockContent}\n`.trimStart();
    }

    fs.writeFileSync(gitConfigFile, newContent, { encoding: "utf-8", mode: 0o644 });
    return { success: true, backupPath };
  }

  remove(targetFile?: string): boolean {
    const gitConfigFile = targetFile || this.store.getPathResolver().getUserGitConfigFile();
    if (!fs.existsSync(gitConfigFile)) return true;

    const originalContent = fs.readFileSync(gitConfigFile, "utf-8");
    if (!originalContent.includes(GITCONFIG_BLOCK_START)) return true;

    const removed = removeManagedBlock(originalContent, GITCONFIG_BLOCK_START, GITCONFIG_BLOCK_END);
    if (!removed.ok || removed.content === undefined) {
      return false;
    }
    fs.writeFileSync(gitConfigFile, removed.content, { encoding: "utf-8", mode: 0o644 });

    return true;
  }
}

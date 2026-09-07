import path from "node:path";
import { IdentityResolver } from "@/core/identity/identity-resolver";
import { ConfigStore, defaultConfigStore } from "@/core/config/config-store";
import { GitOverrideManager } from "@/core/git/override-manager";
import { IdeSyncManager } from "@/core/ide/ide-sync-manager";
import pc from "picocolors";

export interface SuggestionItem {
  category: "IDENTITY" | "BINDING" | "SECURITY" | "INTEGRATION" | "GENERAL";
  priority: "HIGH" | "MEDIUM" | "LOW";
  title: string;
  description: string;
  command: string;
}

export async function handleSuggestCommand(store: ConfigStore = defaultConfigStore) {
  const resolver = new IdentityResolver(store);
  const ctx = await resolver.resolve();
  const overrideManager = new GitOverrideManager(store);
  const ideManager = new IdeSyncManager(store);

  const suggestions: SuggestionItem[] = [];

  if (!ctx.isGitRepo) {
    // Check if directory matches a rule
    if (ctx.matchedRule) {
      suggestions.push({
        category: "GENERAL",
        priority: "LOW",
        title: `Matched directory rule: ${ctx.matchedRule.id}`,
        description: `This folder matches rule for identity '${ctx.identity?.id}'. Any repository initialized or cloned here will use this identity.`,
        command: "gb rules list",
      });
    }

    suggestions.push({
      category: "GENERAL",
      priority: "MEDIUM",
      title: "Clone a repository with smart account routing",
      description: "Clone an existing repository and automatically bind it to the correct identity and provider account.",
      command: "gb clone <repository-url>",
    });

    suggestions.push({
      category: "GENERAL",
      priority: "LOW",
      title: "Initialize a new repository",
      description: "Create a new Git repository in this folder and configure GitBridge.",
      command: "git init && gb init",
    });
  } else {
    // We ARE in a Git repository
    const repoName = ctx.repoRoot ? path.basename(ctx.repoRoot) : "current repo";

    // 1. Check Identity Binding
    const repos = store.loadRepositories();
    const hasRepoBinding = ctx.repoRoot && repos.some((r) => r.path === ctx.repoRoot);
    const hasLocalFile = ctx.source === "repo_profile" && ctx.identity;

    if (!hasRepoBinding && !hasLocalFile) {
      const defaultId = ctx.identity ? ctx.identity.id : "personal";
      suggestions.push({
        category: "BINDING",
        priority: "HIGH",
        title: `Permanently bind '${repoName}' to identity '${defaultId}'`,
        description: "Save a persistent binding in this repository so GitBridge remembers your identity forever without guessing.",
        command: `gb repo set . --identity ${defaultId}`,
      });
    }

    // 2. Check Mismatch
    if (ctx.isMismatched) {
      const expectedEmail = ctx.identity?.email || "expected-email";
      suggestions.push({
        category: "IDENTITY",
        priority: "HIGH",
        title: `Resolve author email mismatch (${ctx.localGitEmail} ≠ ${expectedEmail})`,
        description: "Your local Git config does not match the active GitBridge identity. Synchronize it now.",
        command: ctx.identity ? `gb switch ${ctx.identity.id}` : `gb repo set . -e ${expectedEmail}`,
      });
    }

    // 3. Check Lazy Discovery for Unconfigured Remote Providers
    if (ctx.detectedRemoteProvider && !ctx.detectedRemoteProvider.isConfigured) {
      suggestions.push({
        category: "IDENTITY",
        priority: "HIGH",
        title: `Authenticate with ${ctx.detectedRemoteProvider.name}`,
        description: `This repository connects to ${ctx.detectedRemoteProvider.host}, which has no authenticated account in GitBridge.`,
        command: `gb auth login ${ctx.detectedRemoteProvider.id}`,
      });
    }

    // 4. Check Native Override
    const overrideStatus = overrideManager.getOverrideStatus();
    if (!overrideStatus.enabled) {
      suggestions.push({
        category: "INTEGRATION",
        priority: "MEDIUM",
        title: "Enable native Git command override",
        description: "Transparently route standard 'git' commands through GitBridge shims with zero wrapper friction.",
        command: "gb override enable",
      });
    }

    // 5. Check IDE Sync
    const ideStatus = ideManager.getIdeStatus();
    const hasUnsyncedIde = ideStatus.some((ide) => ide.installed && !ide.synced);
    if (hasUnsyncedIde) {
      suggestions.push({
        category: "INTEGRATION",
        priority: "LOW",
        title: "Synchronize installed IDEs (VS Code, Cursor, Antigravity)",
        description: "Configure your editor's internal Git client to respect GitBridge identities automatically.",
        command: "gb ide sync",
      });
    }

    // 6. Check Safety & Pre-Commit Protection
    suggestions.push({
      category: "SECURITY",
      priority: "LOW",
      title: "Verify security audit & install pre-commit guards",
      description: "Audit permissions, scrub plaintext credentials, and verify identity protection hooks.",
      command: "gb security check",
    });
  }

  // Display Suggestions
  console.log(pc.bold("\n  GitBridge Proactive Suggestions"));
  console.log("  ──────────────────────────────────────────────────");

  if (ctx.isGitRepo) {
    const repoName = ctx.repoRoot ? path.basename(ctx.repoRoot) : "unknown";
    console.log(`  Target: ${pc.cyan(repoName)} ${pc.gray(`(${ctx.repoRoot})`)}`);
    if (ctx.identity) {
      console.log(`  Active: ${pc.bold(ctx.identity.name)} <${pc.green(ctx.identity.email)}> ${pc.gray(`[${ctx.identity.id}]`)}`);
    }
  } else {
    console.log(`  Directory: ${pc.blue(ctx.cwd)} ${pc.gray("(outside Git repository)")}`);
  }

  console.log("");

  if (suggestions.length === 0) {
    console.log(pc.green("  ✔ Everything is perfectly configured! No actions needed."));
    console.log("");
    return;
  }

  suggestions.forEach((item, index) => {
    let tag = pc.gray("[INFO]");
    if (item.priority === "HIGH") tag = pc.red("[CRITICAL]");
    else if (item.priority === "MEDIUM") tag = pc.yellow("[RECOMMENDED]");

    console.log(`  ${pc.bold(`${index + 1}.`)} ${tag} ${pc.bold(item.title)}`);
    console.log(`     ${pc.gray(item.description)}`);
    console.log(`     ${pc.cyan(pc.bold(item.command))}\n`);
  });

  console.log(pc.gray("  Run any recommended command above to apply the suggested changes.\n"));
}

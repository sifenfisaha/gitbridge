import { ConfigStore, defaultConfigStore } from "@/core/config/config-store";
import { IdentityResolver } from "@/core/identity/identity-resolver";
import { sanitizeSshKeyPath } from "@/utils/security";

function escapeShellArg(val: string): string {
  return val.replace(/["\\$`]/g, "\\$&");
}

export async function handleEnvCommand(store: ConfigStore = defaultConfigStore) {
  const resolver = new IdentityResolver(store);
  const ctx = await resolver.resolve();

  if (ctx.identity) {
    console.log(`export GIT_AUTHOR_NAME="${escapeShellArg(ctx.identity.name)}"`);
    console.log(`export GIT_AUTHOR_EMAIL="${escapeShellArg(ctx.identity.email)}"`);
    console.log(`export GIT_COMMITTER_NAME="${escapeShellArg(ctx.identity.name)}"`);
    console.log(`export GIT_COMMITTER_EMAIL="${escapeShellArg(ctx.identity.email)}"`);
  }

  if (ctx.account?.sshKeyPath) {
    const safeSsh = sanitizeSshKeyPath(ctx.account.sshKeyPath);
    console.log(`export GIT_SSH_COMMAND="ssh -i \\"${safeSsh}\\" -o IdentitiesOnly=yes"`);
  }
}

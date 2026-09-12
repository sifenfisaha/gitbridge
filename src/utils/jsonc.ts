/**
 * Minimal JSONC parser for editor settings.json (comments + trailing commas).
 * Returns null on failure — callers must not overwrite the file.
 */
export function parseJsonc(text: string): Record<string, unknown> | null {
  if (!text || typeof text !== "string") return null;
  const stripped = text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/,\s*([}\]])/g, "$1")
    .trim();
  if (!stripped) return {};
  try {
    const parsed = JSON.parse(stripped);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

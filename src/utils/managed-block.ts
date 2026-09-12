export interface ManagedBlockResult {
  ok: boolean;
  content?: string;
  reason?: string;
}

/**
 * Replace a START/END managed block. END is searched only after START so a
 * stray end marker earlier in the file cannot wipe user config.
 * Unpaired markers refuse to modify the file.
 */
export function replaceManagedBlock(
  original: string,
  startMarker: string,
  endMarker: string,
  newBlock: string
): ManagedBlockResult {
  const startIdx = original.indexOf(startMarker);
  if (startIdx === -1) {
    return { ok: false, reason: "start marker not found" };
  }
  const endIdx = original.indexOf(endMarker, startIdx + startMarker.length);
  if (endIdx === -1) {
    return { ok: false, reason: "unpaired managed-block start marker; refusing to modify file" };
  }

  const before = original.slice(0, startIdx);
  const after = original.slice(endIdx + endMarker.length);
  return { ok: true, content: `${before}${newBlock}${after}` };
}

export function removeManagedBlock(
  original: string,
  startMarker: string,
  endMarker: string
): ManagedBlockResult {
  if (!original.includes(startMarker)) {
    return { ok: true, content: original };
  }
  const replaced = replaceManagedBlock(original, startMarker, endMarker, "");
  if (!replaced.ok || replaced.content === undefined) {
    return replaced;
  }
  const cleaned = replaced.content.replace(/\n{3,}/g, "\n\n").trim();
  return { ok: true, content: cleaned.length === 0 ? "" : `${cleaned}\n` };
}

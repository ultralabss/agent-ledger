/** Stable per-repo color dot: hash the slug into one of 8 palette hues so the
 *  same repo always gets the same dot, across sessions and reloads. */
export function repoColorVar(slug: string): string {
  let h = 0;
  for (let i = 0; i < slug.length; i++) {
    h = (h * 31 + slug.charCodeAt(i)) >>> 0;
  }
  return `var(--repo-${h % 8})`;
}

// Pure JS — importable from both server (getStaticProps) and client (Link href).
// Canonical slug for tag URLs: lowercase, hyphenated, ASCII-only.
export function slugifyTag(name) {
  return String(name)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

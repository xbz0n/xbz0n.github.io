#!/usr/bin/env node
// Generates sitemap.xml, rss.xml, and llms.txt from posts/ at build time.
// Replaces hand-maintained feed files so new posts are auto-indexed.

const fs = require('fs');
const path = require('path');
const matter = require('gray-matter');

const SITE_URL = 'https://xbz0n.sh';
const ROOT = path.join(__dirname, '..');
const POSTS_DIR = path.join(ROOT, 'posts');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');

// Canonical tag slug — must stay in sync with lib/tags.js.
function slugifyTag(name) {
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

const STATIC_PAGES = [
  { url: '/',      priority: '1.0', changefreq: 'weekly',  lastmod: null },   // null => newest post
  { url: '/blog',  priority: '0.9', changefreq: 'weekly',  lastmod: null },
  { url: '/tools', priority: '0.8', changefreq: 'monthly', lastmod: '2025-06-04' },
  { url: '/cves',  priority: '0.8', changefreq: 'monthly', lastmod: '2025-08-24' },
  { url: '/about', priority: '0.7', changefreq: 'monthly', lastmod: '2025-06-04' },
];

const CVE_LIST = [
  'CVE-2025-50674: Privilege escalation in OpenMediaVault 7.4.17',
  'CVE-2024-32136: SQL injection vulnerability',
  'CVE-2024-33911: Security configuration vulnerability',
  'CVE-2024-31370: Injection vulnerability allowing arbitrary code execution',
  'CVE-2024-30240: SQL injection allowing authentication bypass',
  'CVE-2024-0566: SQL injection allowing data exfiltration',
  'CVE-2024-0405: Input validation vulnerability leading to RCE',
  'CVE-2024-0399: Data integrity and confidentiality vulnerability',
  'CVE-2024-0365: Privilege escalation vulnerability',
  'CVE-2023-0830: Command injection in EasyNAS',
];

const TOOLS_LIST = [
  ['InterceptReady', 'https://github.com/xbz0n/InterceptReady', 'Automated toolkit for configuring Android emulators with Frida and Burp Suite for mobile security testing.'],
  ['AspXVenom', 'https://github.com/xbz0n/AspXVenom', 'Generates encoded shellcode and embeds it into ASPX webshells for penetration testing.'],
  ['MacroPhantom', 'https://github.com/xbz0n/MacroPhantom', 'Generates XOR+Caesar encrypted shellcode and embeds it into VBA macros for Office documents.'],
  ['GoPhish Deploy', 'https://github.com/xbz0n/gophish-deploy', 'Automates deployment and configuration of the GoPhish phishing framework.'],
  ['AutoMSF', 'https://github.com/xbz0n/AutoMSF', 'Automates generation of multiple reverse_https payloads using msfvenom with Metasploit handler setup.'],
];

function loadPosts() {
  const files = fs.readdirSync(POSTS_DIR).filter(f => f.endsWith('.md') && !f.startsWith('.'));
  const posts = files.map(f => {
    const full = path.join(POSTS_DIR, f);
    const { data, content } = matter(fs.readFileSync(full, 'utf8'));
    return {
      slug: f.replace(/\.md$/, ''),
      title: data.title || f,
      date: data.date,
      tags: data.tags || [],
      description: data.description || null,
      // Prefer explicit `updated:` frontmatter; fall back to publish date.
      // Git mtime is unreliable here (history was wiped — every file's last
      // commit is the same day).
      updated: data.updated || data.date,
      content,
    };
  }).filter(p => p.date && !isNaN(new Date(p.date)));
  posts.sort((a, b) => new Date(b.date) - new Date(a.date));
  return posts;
}

function collectTagSlugs(posts) {
  const counts = new Map();
  for (const p of posts) {
    for (const t of p.tags) {
      const s = slugifyTag(t);
      if (!s) continue;
      counts.set(s, (counts.get(s) || 0) + 1);
    }
  }
  return counts;
}

function generateExcerpt(post) {
  if (post.description) return post.description;
  const stripped = post.content.replace(/^---[\s\S]*?---/m, '').trim();
  const paragraphs = stripped.split(/\n{2,}/).map(p => p.trim()).filter(p => {
    if (!p) return false;
    if (p.startsWith('#')) return false;
    if (p.startsWith('![') || p.startsWith('<img')) return false;
    return true;
  });
  let ex = paragraphs[0] || '';
  ex = ex
    .replace(/!\[[^\]]*\]\([^)]+\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    .replace(/~~(.*?)~~/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
  if (ex.length > 200) {
    const cut = ex.slice(0, 200).lastIndexOf(' ');
    ex = ex.slice(0, cut > 0 ? cut : 197) + '...';
  }
  return ex;
}

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function isoDate(d) {
  return new Date(d).toISOString().slice(0, 10);
}

function generateSitemap(posts, tagCounts) {
  const newest = posts[0] ? isoDate(posts[0].updated || posts[0].date) : isoDate(new Date());
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  for (const p of STATIC_PAGES) {
    const lastmod = p.lastmod || newest;
    xml += '  <url>\n';
    xml += `    <loc>${SITE_URL}${p.url}</loc>\n`;
    xml += `    <lastmod>${lastmod}</lastmod>\n`;
    xml += `    <changefreq>${p.changefreq}</changefreq>\n`;
    xml += `    <priority>${p.priority}</priority>\n`;
    xml += '  </url>\n';
  }
  for (const post of posts) {
    const lastmod = isoDate(post.updated || post.date);
    xml += '  <url>\n';
    xml += `    <loc>${SITE_URL}/blog/${post.slug}</loc>\n`;
    xml += `    <lastmod>${lastmod}</lastmod>\n`;
    xml += '    <changefreq>yearly</changefreq>\n';
    xml += '    <priority>0.7</priority>\n';
    xml += '  </url>\n';
  }
  // Tag archive pages — only index tags with 2+ posts (skip thin pages).
  for (const [slug, count] of tagCounts.entries()) {
    if (count < 2) continue;
    xml += '  <url>\n';
    xml += `    <loc>${SITE_URL}/blog/tag/${slug}</loc>\n`;
    xml += `    <lastmod>${newest}</lastmod>\n`;
    xml += '    <changefreq>monthly</changefreq>\n';
    xml += '    <priority>0.5</priority>\n';
    xml += '  </url>\n';
  }
  xml += '</urlset>\n';
  return xml;
}

function generateRSS(posts) {
  const lastBuild = new Date().toUTCString();
  let rss = '<?xml version="1.0" encoding="UTF-8"?>\n';
  rss += '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n';
  rss += '  <channel>\n';
  rss += '    <title>xbz0n | Security Research Blog</title>\n';
  rss += `    <link>${SITE_URL}/blog</link>\n`;
  rss += '    <description>Security research articles covering penetration testing, exploit development, red team operations, Active Directory attacks, and CVE disclosures by Ivan Spiridonov (xbz0n).</description>\n';
  rss += '    <language>en</language>\n';
  rss += `    <lastBuildDate>${lastBuild}</lastBuildDate>\n`;
  rss += '    <managingEditor>ivanspiridonov@gmail.com (Ivan Spiridonov)</managingEditor>\n';
  rss += `    <atom:link href="${SITE_URL}/rss.xml" rel="self" type="application/rss+xml"/>\n`;
  for (const post of posts) {
    rss += '  <item>\n';
    rss += `    <title>${xmlEscape(post.title)}</title>\n`;
    rss += `    <link>${SITE_URL}/blog/${post.slug}</link>\n`;
    rss += `    <guid isPermaLink="true">${SITE_URL}/blog/${post.slug}</guid>\n`;
    rss += `    <pubDate>${new Date(post.date).toUTCString()}</pubDate>\n`;
    rss += '    <author>ivanspiridonov@gmail.com (Ivan Spiridonov)</author>\n';
    for (const tag of post.tags) rss += `    <category>${xmlEscape(tag)}</category>\n`;
    rss += '  </item>\n';
  }
  rss += '  </channel>\n</rss>\n';
  return rss;
}

function generateLlmsTxt(posts) {
  let out = '';
  out += '# xbz0n.sh\n\n';
  out += '> Personal website of Ivan Spiridonov (xbz0n) — Offensive Security Consultant specializing in penetration testing, red teaming, vulnerability research, and exploit development.\n\n';
  out += '## About\n\n';
  out += 'Ivan Spiridonov is a professional penetration tester and security researcher based in Europe. He holds OSCP, OSEP, OSWE, OSED, and OSCE3 certifications from Offensive Security. He has published multiple CVEs and develops open-source security tools.\n\n';
  out += `- Website: ${SITE_URL}\n`;
  out += '- GitHub: https://github.com/xbz0n\n';
  out += '- Twitter: https://twitter.com/xbz0n\n';
  out += '- LinkedIn: https://www.linkedin.com/in/ivanspiridonov/\n\n';
  out += '## Pages\n\n';
  out += `- [Home](${SITE_URL}/)\n`;
  out += `- [About](${SITE_URL}/about)\n`;
  out += `- [Blog](${SITE_URL}/blog)\n`;
  out += `- [Tools](${SITE_URL}/tools)\n`;
  out += `- [CVEs](${SITE_URL}/cves)\n\n`;
  out += '## Blog Posts\n\n';
  for (const post of posts) {
    const ex = generateExcerpt(post);
    out += `- [${post.title}](${SITE_URL}/blog/${post.slug}): ${ex}\n`;
  }
  out += '\n## Published CVEs\n\n';
  for (const c of CVE_LIST) out += `- ${c}\n`;
  out += '\n## Open-Source Tools\n\n';
  for (const [name, url, desc] of TOOLS_LIST) out += `- [${name}](${url}): ${desc}\n`;
  return out;
}

function generateJSONFeed(posts) {
  return {
    version: 'https://jsonfeed.org/version/1.1',
    title: 'xbz0n | Security Research Blog',
    home_page_url: `${SITE_URL}/blog`,
    feed_url: `${SITE_URL}/feed.json`,
    description: 'Security research articles covering penetration testing, exploit development, red team operations, Active Directory attacks, and CVE disclosures by Ivan Spiridonov (xbz0n).',
    language: 'en',
    authors: [
      {
        name: 'Ivan Spiridonov',
        url: SITE_URL,
        avatar: `${SITE_URL}/apple-touch-icon.png`,
      },
    ],
    items: posts.map(post => ({
      id: `${SITE_URL}/blog/${post.slug}`,
      url: `${SITE_URL}/blog/${post.slug}`,
      title: post.title,
      summary: generateExcerpt(post),
      content_text: generateExcerpt(post),
      date_published: new Date(post.date).toISOString(),
      ...(post.updated && post.updated !== post.date
        ? { date_modified: new Date(post.updated).toISOString() }
        : {}),
      tags: post.tags,
      authors: [{ name: 'Ivan Spiridonov', url: SITE_URL }],
    })),
  };
}

function generateSiteData(posts, tagCounts) {
  const recentPosts = posts.slice(0, 5).map(p => ({
    slug: p.slug,
    title: p.title,
    date: p.date,
  }));
  // Popular topics: tags with 2+ posts, ordered by count then alpha, capped at 10.
  const popularTags = [...tagCounts.entries()]
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 10)
    .map(([slug, count]) => ({ slug, count }));
  return { recentPosts, popularTags };
}

function main() {
  const posts = loadPosts();
  const tagCounts = collectTagSlugs(posts);
  const indexedTagCount = [...tagCounts.values()].filter(c => c >= 2).length;
  console.log(`[generate-feeds] Found ${posts.length} posts, ${tagCounts.size} tag slugs (${indexedTagCount} indexed)`);

  const sitemap = generateSitemap(posts, tagCounts);
  const rss = generateRSS(posts);
  const llms = generateLlmsTxt(posts);
  const jsonFeed = generateJSONFeed(posts);
  const siteData = generateSiteData(posts, tagCounts);

  fs.writeFileSync(path.join(PUBLIC_DIR, 'sitemap.xml'), sitemap);
  fs.writeFileSync(path.join(PUBLIC_DIR, 'rss.xml'), rss);
  fs.writeFileSync(path.join(PUBLIC_DIR, 'llms.txt'), llms);
  fs.writeFileSync(path.join(PUBLIC_DIR, 'feed.json'), JSON.stringify(jsonFeed, null, 2) + '\n');

  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(path.join(DATA_DIR, 'site-data.json'), JSON.stringify(siteData, null, 2) + '\n');

  console.log('[generate-feeds] Wrote sitemap.xml, rss.xml, llms.txt, feed.json, data/site-data.json');
}

main();

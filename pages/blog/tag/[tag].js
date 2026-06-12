import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import Link from 'next/link';
import Head from 'next/head';
import { format } from 'date-fns';
import { slugifyTag } from '../../../lib/tags';

export default function TagPage({ tag, displayName, posts }) {
  const siteUrl = 'https://xbz0n.sh';
  const canonical = `${siteUrl}/blog/tag/${tag}`;
  const description = `${posts.length} ${posts.length === 1 ? 'article' : 'articles'} tagged ${displayName} on xbz0n.sh — security research and write-ups by Ivan Spiridonov.`;
  const shouldNoindex = posts.length < 2;

  return (
    <>
      <Head>
        <title>{`xbz0n@sh:~# Tag: ${displayName}`}</title>
        <meta name="description" content={description} />
        <link rel="canonical" href={canonical} />
        {shouldNoindex && <meta name="robots" content="noindex, follow" />}

        <meta property="og:type" content="website" />
        <meta property="og:url" content={canonical} />
        <meta property="og:title" content={`xbz0n | Tag: ${displayName}`} />
        <meta property="og:description" content={description} />
        <meta property="og:image" content={`${siteUrl}/images/dep-bypass.jpeg`} />

        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:site" content="@xbz0n" />
        <meta name="twitter:title" content={`xbz0n | Tag: ${displayName}`} />
        <meta name="twitter:description" content={description} />
        <meta name="twitter:image" content={`${siteUrl}/images/dep-bypass.jpeg`} />

        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "BreadcrumbList",
              "itemListElement": [
                { "@type": "ListItem", "position": 1, "name": "Home", "item": `${siteUrl}/` },
                { "@type": "ListItem", "position": 2, "name": "Blog", "item": `${siteUrl}/blog` },
                { "@type": "ListItem", "position": 3, "name": displayName, "item": canonical }
              ]
            })
          }}
        />

        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "CollectionPage",
              "url": canonical,
              "name": `Tag: ${displayName}`,
              "description": description,
              "hasPart": posts.map(p => ({
                "@type": "BlogPosting",
                "headline": p.title,
                "url": `${siteUrl}/blog/${p.slug}`,
                "datePublished": p.date,
                ...(p.tags ? { "keywords": p.tags.join(', ') } : {})
              }))
            })
          }}
        />
      </Head>

      <div className="space-y-8">
        <div>
          <Link href="/blog" className="text-accent hover:text-accent/80 mb-4 inline-block">
            ← Back to all posts
          </Link>
          <h1 className="text-3xl font-bold mb-2">
            <span className="font-mono text-accent">#</span>{displayName}
          </h1>
          <p className="text-gray-400">
            {posts.length} {posts.length === 1 ? 'article' : 'articles'} tagged{' '}
            <span className="font-mono text-accent">{displayName}</span>
          </p>
        </div>

        <div className="space-y-4">
          {posts.map(post => (
            <article
              key={post.slug}
              className="bg-secondary/30 rounded-lg p-5 border border-gray-700 hover:border-accent/60 transition-colors"
            >
              <Link href={`/blog/${post.slug}`}>
                <h2 className="text-xl font-semibold hover:text-accent mb-2">{post.title}</h2>
              </Link>
              <div className="text-sm text-gray-500 mb-2">
                <time dateTime={post.date}>{format(new Date(post.date), 'MMM d, yyyy')}</time>
              </div>
              {post.excerpt && <p className="text-gray-400 text-sm mb-3">{post.excerpt}</p>}
              {post.tags && post.tags.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {post.tags.map(t => {
                    const tSlug = slugifyTag(t);
                    return (
                      <Link key={t} href={`/blog/tag/${tSlug}`} className="inline-block">
                        <span
                          className={`badge text-xs ${
                            tSlug === tag ? 'badge-cve' : 'badge-certification'
                          } hover:opacity-80`}
                        >
                          {t}
                        </span>
                      </Link>
                    );
                  })}
                </div>
              )}
            </article>
          ))}
        </div>
      </div>
    </>
  );
}

export async function getStaticPaths() {
  const postsDir = path.join(process.cwd(), 'posts');
  const files = fs.readdirSync(postsDir).filter(f => f.endsWith('.md') && !f.startsWith('.'));
  const tagSlugs = new Set();
  for (const f of files) {
    try {
      const { data } = matter(fs.readFileSync(path.join(postsDir, f), 'utf8'));
      (data.tags || []).forEach(t => {
        const s = slugifyTag(t);
        if (s) tagSlugs.add(s);
      });
    } catch (_) {}
  }
  return {
    paths: [...tagSlugs].map(tag => ({ params: { tag } })),
    fallback: false,
  };
}

function buildExcerpt(data, content) {
  if (data.description) return data.description;
  const stripped = content.replace(/^---[\s\S]*?---/m, '').trim();
  const paragraphs = stripped
    .split(/\n{2,}/)
    .map(p => p.trim())
    .filter(p => p && !p.startsWith('#') && !p.startsWith('![') && !p.startsWith('<img'));
  let ex = (paragraphs[0] || '')
    .replace(/!\[[^\]]*\]\([^)]+\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    .replace(/\s+/g, ' ')
    .trim();
  if (ex.length > 200) {
    const cut = ex.slice(0, 200).lastIndexOf(' ');
    ex = ex.slice(0, cut > 0 ? cut : 197) + '...';
  }
  return ex;
}

export async function getStaticProps({ params }) {
  const postsDir = path.join(process.cwd(), 'posts');
  const files = fs.readdirSync(postsDir).filter(f => f.endsWith('.md') && !f.startsWith('.'));
  const matching = [];
  let displayName = params.tag;

  for (const f of files) {
    try {
      const { data, content } = matter(fs.readFileSync(path.join(postsDir, f), 'utf8'));
      const matchedTag = (data.tags || []).find(t => slugifyTag(t) === params.tag);
      if (!matchedTag) continue;
      displayName = matchedTag;
      matching.push({
        slug: f.replace(/\.md$/, ''),
        title: data.title || f,
        date: data.date || null,
        tags: data.tags || [],
        excerpt: buildExcerpt(data, content),
      });
    } catch (_) {}
  }

  const sorted = matching
    .filter(p => p.date)
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  return {
    props: {
      tag: params.tag,
      displayName,
      posts: sorted,
    },
  };
}

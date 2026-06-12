import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { remark } from 'remark';
import remarkGfm from 'remark-gfm';
import html from 'remark-html';
import { format } from 'date-fns';
import Link from 'next/link';
import Head from 'next/head';
import { useEffect, useState } from 'react';
import Prism from 'prismjs';
import { FaTwitter, FaLinkedinIn, FaLink, FaCheck } from 'react-icons/fa';
import TableOfContents from '../../components/TableOfContents';
import RelatedPosts from '../../components/RelatedPosts';
import AuthorBio from '../../components/AuthorBio';
import ReadingProgress from '../../components/ReadingProgress';
import { slugifyTag } from '../../lib/tags';

export default function BlogPost({ postData }) {
  const [copied, setCopied] = useState(false);
  const postUrl = `https://xbz0n.sh/blog/${postData.slug}`;

  const shareOnTwitter = () => {
    window.open(`https://twitter.com/intent/tweet?url=${encodeURIComponent(postUrl)}&text=${encodeURIComponent(postData.title)}`, '_blank', 'noopener,noreferrer');
  };

  const shareOnLinkedIn = () => {
    window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(postUrl)}`, '_blank', 'noopener,noreferrer');
  };

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(postUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy link:', err);
    }
  };

  useEffect(() => {
    // Re-highlight code blocks when content changes
    if (typeof window !== 'undefined') {
      Prism.highlightAll();
      addCopyButtons();
      openExternalLinksInNewTab();
    }
  }, [postData]);

  // Function to add copy buttons to code blocks
  const addCopyButtons = () => {
    const codeBlocks = document.querySelectorAll('pre[class*="language-"]');
    codeBlocks.forEach(block => {
      // Skip if button already exists
      if (block.querySelector('.copy-button')) {
        return;
      }

      // Create copy button
      const button = document.createElement('button');
      button.className = 'copy-button';
      button.textContent = 'Copy';

      // Add click handler
      button.addEventListener('click', async () => {
        const code = block.querySelector('code').textContent;
        try {
          await navigator.clipboard.writeText(code);
          button.textContent = 'Copied!';
          setTimeout(() => {
            button.textContent = 'Copy';
          }, 2000);
        } catch (err) {
          console.error('Failed to copy text: ', err);
          button.textContent = 'Failed';
          setTimeout(() => {
            button.textContent = 'Copy';
          }, 2000);
        }
      });

      // Add button to block
      block.appendChild(button);
    });
  };

  // Make external links open in new tab
  const openExternalLinksInNewTab = () => {
    const blogContent = document.querySelector('.blog-content');
    if (!blogContent) return;
    blogContent.querySelectorAll('a').forEach(link => {
      if (link.hostname && link.hostname !== window.location.hostname) {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
      }
    });
  };

  // Extract the first raster image from the post content (skip SVG —
  // most social previewers won't render SVG og:image)
  const getFirstImage = (html) => {
    const imgRegex = /<img[^>]+src=["']([^"']+)["']/gi;
    let match;
    while ((match = imgRegex.exec(html)) !== null) {
      let imagePath = match[1];
      if (!imagePath.startsWith('http') && !imagePath.startsWith('/')) {
        imagePath = '/' + imagePath;
      }
      if (!imagePath.toLowerCase().endsWith('.svg')) {
        return imagePath;
      }
    }
    return null;
  };

  const firstImage = getFirstImage(postData.contentHtml) || '/images/dep-bypass.jpeg';
  const ogImageWidth = postData.heroDimensions?.width || 1200;
  const ogImageHeight = postData.heroDimensions?.height || 630;
  const siteUrl = 'https://xbz0n.sh';
  const absoluteOgImage = firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}`;
  const dateModified = postData.updated || postData.date;

  return (
    <>
      <Head>
        <title>{`xbz0n@sh:~# ${postData.title}`}</title>
        <meta name="description" content={postData.excerpt} />
        {postData.tags && <meta name="keywords" content={postData.tags.join(', ')} />}

        {/* Preload hero so it counts as LCP candidate */}
        {firstImage && !firstImage.startsWith('http') && (
          <link rel="preload" as="image" href={firstImage} fetchpriority="high" />
        )}

        {/* Open Graph / Facebook */}
        <meta property="og:type" content="article" />
        <meta property="og:url" content={`${siteUrl}/blog/${postData.slug}`} />
        <meta property="og:title" content={postData.title} />
        <meta property="og:description" content={postData.excerpt} />
        {firstImage && <meta property="og:image" content={absoluteOgImage} />}
        {firstImage && <meta property="og:image:width" content={String(ogImageWidth)} />}
        {firstImage && <meta property="og:image:height" content={String(ogImageHeight)} />}
        {firstImage && <meta property="og:image:alt" content={postData.title} />}
        <meta property="article:published_time" content={postData.date} />
        <meta property="article:modified_time" content={dateModified} />
        <meta property="article:author" content="Ivan Spiridonov" />
        {postData.tags && postData.tags.map(tag => (
          <meta key={tag} property="article:tag" content={tag} />
        ))}

        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:site" content="@xbz0n" />
        <meta name="twitter:creator" content="@xbz0n" />
        <meta name="twitter:title" content={postData.title} />
        <meta name="twitter:description" content={postData.excerpt} />
        {firstImage && <meta name="twitter:image" content={absoluteOgImage} />}

        {/* Canonical URL */}
        <link rel="canonical" href={`${siteUrl}/blog/${postData.slug}`} />

        {/* Article Schema.org */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "Article",
              "mainEntityOfPage": {
                "@type": "WebPage",
                "@id": `${siteUrl}/blog/${postData.slug}`
              },
              "headline": postData.title,
              "description": postData.excerpt,
              "author": {
                "@type": "Person",
                "name": "Ivan Spiridonov",
                "url": "https://xbz0n.sh/about",
                "sameAs": [
                  "https://github.com/xbz0n",
                  "https://twitter.com/xbz0n",
                  "https://www.linkedin.com/in/ivanspiridonov/"
                ]
              },
              "datePublished": postData.date,
              "dateModified": dateModified,
              "url": `${siteUrl}/blog/${postData.slug}`,
              "publisher": {
                "@type": "Person",
                "name": "Ivan Spiridonov",
                "url": "https://xbz0n.sh"
              },
              ...(postData.tags ? { "keywords": postData.tags.join(', ') } : {}),
              ...(postData.wordCount ? { "wordCount": postData.wordCount } : {}),
              ...(firstImage ? { "image": absoluteOgImage } : {})
            })
          }}
        />

        {/* Breadcrumb Schema.org */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "BreadcrumbList",
              "itemListElement": [
                { "@type": "ListItem", "position": 1, "name": "Home", "item": `${siteUrl}/` },
                { "@type": "ListItem", "position": 2, "name": "Blog", "item": `${siteUrl}/blog` },
                { "@type": "ListItem", "position": 3, "name": postData.title, "item": `${siteUrl}/blog/${postData.slug}` }
              ]
            })
          }}
        />
      </Head>

      <ReadingProgress />

      <article className="max-w-3xl mx-auto" data-pagefind-body data-pagefind-meta={`date:${postData.date}`}>
        <Link href="/blog" className="text-accent hover:text-accent/80 mb-8 inline-block">
          ← Back to all posts
        </Link>

        <div className="mb-8">
          <h1 className="text-3xl md:text-4xl font-bold mb-4">{postData.title}</h1>
          <div className="flex items-center text-sm text-gray-400 gap-4 mb-3">
            <time dateTime={postData.date}>
              {format(new Date(postData.date), 'MMMM d, yyyy')}
            </time>
            {postData.wordCount && (
              <span className="text-gray-500">·  {Math.max(1, Math.round(postData.wordCount / 200))} min read</span>
            )}
          </div>
          {postData.tags && postData.tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {postData.tags.map(t => (
                <Link key={t} href={`/blog/tag/${slugifyTag(t)}`} className="inline-block">
                  <span
                    className={`badge text-xs ${
                      t.toLowerCase().includes('cve') ? 'badge-cve' : 'badge-certification'
                    } hover:opacity-80`}
                  >
                    {t}
                  </span>
                </Link>
              ))}
            </div>
          )}
        </div>

        {postData.headings && <TableOfContents headings={postData.headings} />}

        <div className="blog-content" dangerouslySetInnerHTML={{ __html: postData.contentHtml }} />

        <AuthorBio />

        {postData.relatedPosts && <RelatedPosts posts={postData.relatedPosts} />}

        <div className="mt-12 pt-8 border-t border-gray-700">
          <span className="text-gray-400 text-sm mr-4">Share this post:</span>
          <div className="inline-flex gap-3 mt-2">
            <button
              onClick={shareOnTwitter}
              className="flex items-center gap-2 px-4 py-2 bg-secondary/30 border border-gray-700 rounded hover:border-accent/50 hover:text-accent transition-colors text-sm text-gray-300"
              aria-label="Share on Twitter"
            >
              <FaTwitter /> Twitter
            </button>
            <button
              onClick={shareOnLinkedIn}
              className="flex items-center gap-2 px-4 py-2 bg-secondary/30 border border-gray-700 rounded hover:border-accent/50 hover:text-accent transition-colors text-sm text-gray-300"
              aria-label="Share on LinkedIn"
            >
              <FaLinkedinIn /> LinkedIn
            </button>
            <button
              onClick={copyLink}
              className="flex items-center gap-2 px-4 py-2 bg-secondary/30 border border-gray-700 rounded hover:border-accent/50 hover:text-accent transition-colors text-sm text-gray-300"
              aria-label="Copy link"
            >
              {copied ? <><FaCheck /> Copied!</> : <><FaLink /> Copy Link</>}
            </button>
          </div>
        </div>
      </article>
    </>
  );
}

export async function getStaticPaths() {
  try {
    const postsDirectory = path.join(process.cwd(), 'posts');
    const fileNames = fs.readdirSync(postsDirectory);
    
    // Filter out non-markdown files and system files
    const markdownFiles = fileNames.filter(fileName => 
      fileName.endsWith('.md') && 
      !fileName.startsWith('.') &&
      !fileName.includes('.DS_Store')
    );
    
    const paths = markdownFiles.map((fileName) => {
      return {
        params: {
          slug: fileName.replace(/\.md$/, ''),
        },
      };
    });
    
    return {
      paths,
      fallback: false,
    };
  } catch (error) {
    console.error('Error generating static paths:', error);
    return {
      paths: [],
      fallback: false,
    };
  }
}

// Function to clean up the rendered HTML content
function cleanHtml(html) {
  let cleaned = html;
  
  // Fix fenced code blocks with language specifiers that weren't properly transformed
  cleaned = cleaned.replace(
    /<pre><code>```(\w+)\s*([\s\S]*?)```<\/code><\/pre>/g,
    function(match, lang, code) {
      // Remove extra backticks that might appear in the rendered output
      code = code.replace(/^```|```$/gm, '');
      return `<pre class="language-${lang}"><code class="language-${lang}">${code}</code></pre>`;
    }
  );
  
  // Fix fenced code blocks without language specifiers
  cleaned = cleaned.replace(
    /<pre><code>```\s*([\s\S]*?)```<\/code><\/pre>/g,
    function(match, code) {
      // Remove extra backticks that might appear in the rendered output
      code = code.replace(/^```|```$/gm, '');
      return `<pre class="language-none"><code class="language-none">${code}</code></pre>`;
    }
  );
  
  // Make sure code blocks with language classes have the class on both pre and code elements
  cleaned = cleaned.replace(
    /<pre><code class="language-(\w+)">([\s\S]*?)<\/code><\/pre>/g,
    '<pre class="language-$1"><code class="language-$1">$2</code></pre>'
  );

  // Handle any remaining standard code blocks
  cleaned = cleaned.replace(
    /<pre><code>([\s\S]*?)<\/code><\/pre>/g,
    function(match, code) {
      if (!code.includes('<pre class="language-')) {
        return `<pre class="language-none"><code class="language-none">${code}</code></pre>`;
      }
      return match;
    }
  );
  
  // Handle inline code formatting with backticks
  // First, let's split the HTML into "code block" parts and "non-code block" parts
  const parts = [];
  let lastIndex = 0;
  
  // Find all pre tags
  const preRegex = /<pre[\s\S]*?<\/pre>/g;
  let preMatch;
  
  while ((preMatch = preRegex.exec(cleaned)) !== null) {
    // Add text before this pre tag
    if (preMatch.index > lastIndex) {
      parts.push({
        type: 'text',
        content: cleaned.substring(lastIndex, preMatch.index)
      });
    }
    
    // Add the pre tag itself
    parts.push({
      type: 'pre',
      content: preMatch[0]
    });
    
    lastIndex = preMatch.index + preMatch[0].length;
  }
  
  // Add any remaining text
  if (lastIndex < cleaned.length) {
    parts.push({
      type: 'text',
      content: cleaned.substring(lastIndex)
    });
  }
  
  // Now process each part
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].type === 'text') {
      // Replace backticks with code tags in text parts only
      // First, temporarily replace any existing <code> tags to prevent conflicts
      let content = parts[i].content;
      content = content.replace(/<code/g, '%%CODE_START%%');
      content = content.replace(/<\/code>/g, '%%CODE_END%%');
      
      // More aggressive backtick replacement - handles both inline and any stray backticks
      // This looks for standalone backticks that aren't part of triple backticks
      content = content.replace(/`([^`]+?)`/g, function(match, p1) {
        // Skip if this appears to be part of a code block
        if (match.indexOf('\n') !== -1) return match;
        return '<code>' + p1 + '</code>';
      });
      
      // A safer way to clean up any remaining standalone backticks
      content = content.split('`').join('');
      
      // Restore original code tags
      content = content.replace(/%%CODE_START%%/g, '<code');
      content = content.replace(/%%CODE_END%%/g, '</code>');
      
      parts[i].content = content;
    }
  }
  
  // Join everything back together
  cleaned = parts.map(part => part.content).join('');
  
  return cleaned;
}

export async function getStaticProps({ params }) {
  try {
    const postsDirectory = path.join(process.cwd(), 'posts');
    const fullPath = path.join(postsDirectory, `${params.slug}.md`);
    const fileContents = fs.readFileSync(fullPath, 'utf8');
    
    const { data, content } = matter(fileContents);
    
    // Better excerpt generation - find the second paragraph of actual text
    // Skip title, image references, and headings
    const getProperExcerpt = (mdContent) => {
      // Remove front matter if it exists
      const contentWithoutFrontMatter = mdContent.replace(/^---[\s\S]*?---/m, '').trim();
      
      // Split by lines
      const lines = contentWithoutFrontMatter.split('\n');
      
      // Filter out empty lines, headings, and image references
      const textLines = lines.filter(line => {
        const trimmedLine = line.trim();
        return trimmedLine.length > 0 && 
               !trimmedLine.startsWith('#') && 
               !trimmedLine.startsWith('![') &&
               !trimmedLine.startsWith('<img');
      });
      
      // Group into paragraphs (consecutive non-empty lines)
      const paragraphs = [];
      let currentParagraph = [];
      
      for (const line of textLines) {
        if (line.trim().length === 0 && currentParagraph.length > 0) {
          paragraphs.push(currentParagraph.join(' '));
          currentParagraph = [];
        } else if (line.trim().length > 0) {
          currentParagraph.push(line.trim());
        }
      }
      
      // Add the last paragraph if there's content
      if (currentParagraph.length > 0) {
        paragraphs.push(currentParagraph.join(' '));
      }
      
      // Get the second paragraph if available, otherwise the first
      let excerpt = paragraphs.length > 1 ? paragraphs[1] : (paragraphs.length > 0 ? paragraphs[0] : '');

      // Strip markdown so it doesn't leak into <meta description> / og:description
      excerpt = excerpt
        .replace(/!\[[^\]]*\]\([^)]+\)/g, '')           // images
        .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')         // links → text
        .replace(/`([^`]+)`/g, '$1')                      // inline code
        .replace(/(\*\*|__)(.*?)\1/g, '$2')               // bold
        .replace(/(\*|_)(.*?)\1/g, '$2')                  // italic
        .replace(/~~(.*?)~~/g, '$1')                      // strikethrough
        .replace(/\s+/g, ' ')
        .trim();

      // Truncate if too long
      return excerpt.length > 160 ? excerpt.slice(0, 157) + '...' : excerpt;
    };
    
    // Prefer explicit frontmatter `description:` over auto-generated excerpt.
    const excerpt = data.description || getProperExcerpt(content);
    
    // Process the content to convert markdown to HTML
    const processedContent = await remark()
      .use(remarkGfm)
      .use(html, { sanitize: false })
      .process(content);
    
    // Get the HTML as a string
    let contentHtml = processedContent.toString();
    
    // Clean up the HTML content (fix code blocks and inline code)
    contentHtml = cleanHtml(contentHtml);

    // Remove the first h1 header from the content to avoid duplicate titles
    contentHtml = contentHtml.replace(/<h1[^>]*>.*?<\/h1>/, '');

    // Inject id="..." into h2/h3 so TOC anchors and Google "jump to" links work
    const headings = [];
    const slugify = (s) => s
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[̀-ͯ]/g, '')
      .replace(/[^\p{L}\p{N}\s-]/gu, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
    const idCounts = {};
    contentHtml = contentHtml.replace(/<(h[23])>([\s\S]*?)<\/\1>/g, (match, tag, inner) => {
      const text = inner.replace(/<[^>]+>/g, '').trim();
      let id = slugify(text);
      if (!id) return match;
      if (idCounts[id]) {
        idCounts[id] += 1;
        id = `${id}-${idCounts[id]}`;
      } else {
        idCounts[id] = 1;
      }
      headings.push({ level: parseInt(tag[1], 10), text, id });
      return `<${tag} id="${id}">${inner}</${tag}>`;
    });

    // Mark the first non-svg <img> as the LCP candidate
    let lcpInjected = false;
    contentHtml = contentHtml.replace(/<img\b([^>]*)>/g, (match, attrs) => {
      if (lcpInjected) return match;
      const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
      if (!srcMatch) return match;
      if (/\.svg(\?|$)/i.test(srcMatch[1])) return match;
      lcpInjected = true;
      let newAttrs = attrs;
      if (!/fetchpriority=/i.test(newAttrs)) newAttrs += ' fetchpriority="high"';
      if (!/loading=/i.test(newAttrs)) newAttrs += ' loading="eager"';
      else newAttrs = newAttrs.replace(/loading=["']lazy["']/i, 'loading="eager"');
      if (!/decoding=/i.test(newAttrs)) newAttrs += ' decoding="async"';
      return `<img${newAttrs}>`;
    });

    // Calculate word count
    const wordCount = content.split(/\s+/).filter(w => w.length > 0).length;

    // Read real dimensions of the first non-SVG image so og:image:width/height
    // reflect the actual hero rather than hardcoded values.
    let heroDimensions = null;
    const imgMatches = [...contentHtml.matchAll(/<img[^>]+src=["']([^"']+)["']/gi)];
    for (const m of imgMatches) {
      let p = m[1];
      if (p.startsWith('http') || p.toLowerCase().endsWith('.svg')) continue;
      if (!p.startsWith('/')) p = '/' + p;
      const filePath = path.join(process.cwd(), 'public', p);
      try {
        const sharp = (await import('sharp')).default;
        const meta = await sharp(filePath).metadata();
        if (meta.width && meta.height) {
          heroDimensions = { width: meta.width, height: meta.height };
          break;
        }
      } catch (_) {}
    }

    // Build related posts list by tag overlap (top 3 by # shared tags)
    const relatedPosts = (() => {
      const postsDir = path.join(process.cwd(), 'posts');
      const currentTags = new Set((data.tags || []).map(t => t.toLowerCase()));
      const all = fs.readdirSync(postsDir)
        .filter(f => f.endsWith('.md') && !f.startsWith('.') && f !== `${params.slug}.md`)
        .map(f => {
          try {
            const { data: d } = matter(fs.readFileSync(path.join(postsDir, f), 'utf8'));
            const tags = (d.tags || []);
            const shared = tags.filter(t => currentTags.has(t.toLowerCase()));
            return {
              slug: f.replace(/\.md$/, ''),
              title: d.title || f,
              date: d.date || null,
              sharedTags: shared,
              score: shared.length,
            };
          } catch (_) { return null; }
        })
        .filter(p => p && p.date && p.score > 0)
        .sort((a, b) => b.score - a.score || new Date(b.date) - new Date(a.date))
        .slice(0, 3);
      return all;
    })();

    return {
      props: {
        postData: {
          slug: params.slug,
          contentHtml,
          excerpt,
          wordCount,
          headings,
          relatedPosts,
          ...(heroDimensions ? { heroDimensions } : {}),
          ...data,
        },
      },
    };
  } catch (error) {
    console.error('Error getting static props:', error);
    return {
      notFound: true,
    };
  }
} 
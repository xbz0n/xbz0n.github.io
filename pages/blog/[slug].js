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

  // Extract the first image from the post content
  const getFirstImage = (html) => {
    // Improved regex that handles both relative and absolute paths
    const imgRegex = /<img[^>]+src=["']([^"']+)["']/i;
    const match = html.match(imgRegex);
    
    if (!match) return null;
    
    let imagePath = match[1];
    
    // Ensure the path starts with a slash if it's a relative path
    if (!imagePath.startsWith('http') && !imagePath.startsWith('/')) {
      imagePath = '/' + imagePath;
    }
    
    return imagePath;
  };

  const firstImage = getFirstImage(postData.contentHtml) || '/images/dep-bypass.jpeg';
  const siteUrl = 'https://xbz0n.sh';

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# {postData.title}</title>
        <meta name="description" content={postData.excerpt} />
        {postData.tags && <meta name="keywords" content={postData.tags.join(', ')} />}

        {/* Open Graph / Facebook */}
        <meta property="og:type" content="article" />
        <meta property="og:url" content={`${siteUrl}/blog/${postData.slug}`} />
        <meta property="og:title" content={postData.title} />
        <meta property="og:description" content={postData.excerpt} />
        {firstImage && <meta property="og:image" content={firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}`} />}
        {firstImage && <meta property="og:image:width" content="1200" />}
        {firstImage && <meta property="og:image:height" content="800" />}
        {firstImage && <meta property="og:image:alt" content={postData.title} />}
        
        {/* Twitter */}
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:site" content="@xbz0n" />
        <meta name="twitter:creator" content="@xbz0n" />
        <meta name="twitter:title" content={postData.title} />
        <meta name="twitter:description" content={postData.excerpt} />
        {firstImage && <meta name="twitter:image" content={firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}`} />}

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
              "author": {
                "@type": "Person",
                "name": "Ivan Spiridonov",
                "url": "https://xbz0n.sh/about"
              },
              "datePublished": postData.date,
              "dateModified": postData.date,
              "url": `${siteUrl}/blog/${postData.slug}`,
              "publisher": {
                "@type": "Person",
                "name": "Ivan Spiridonov"
              },
              ...(postData.tags ? { "keywords": postData.tags.join(', ') } : {}),
              ...(postData.wordCount ? { "wordCount": postData.wordCount } : {}),
              ...(firstImage ? { "image": firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}` } : {})
            })
          }}
        />
      </Head>
      
      <article className="max-w-3xl mx-auto">
        <Link href="/blog" className="text-accent hover:text-accent/80 mb-8 inline-block">
          ← Back to all posts
        </Link>
        
        <div className="mb-8">
          <h1 className="text-3xl md:text-4xl font-bold mb-4">{postData.title}</h1>
          <div className="flex items-center text-sm text-gray-400">
            <time dateTime={postData.date}>
              {format(new Date(postData.date), 'MMMM d, yyyy')}
            </time>
          </div>
        </div>
        
        <div className="blog-content" dangerouslySetInnerHTML={{ __html: postData.contentHtml }} />

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
      const excerpt = paragraphs.length > 1 ? paragraphs[1] : (paragraphs.length > 0 ? paragraphs[0] : '');
      
      // Truncate if too long
      return excerpt.length > 160 ? excerpt.slice(0, 157) + '...' : excerpt;
    };
    
    const excerpt = getProperExcerpt(content);
    
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
    
    // Calculate word count
    const wordCount = content.split(/\s+/).filter(w => w.length > 0).length;

    return {
      props: {
        postData: {
          slug: params.slug,
          contentHtml,
          excerpt,
          wordCount,
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
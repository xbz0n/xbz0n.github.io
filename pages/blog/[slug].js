import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { remark } from 'remark';
import html from 'remark-html';
import { format } from 'date-fns';
import Link from 'next/link';
import Head from 'next/head';
import { useEffect } from 'react';
import Prism from 'prismjs';

export default function BlogPost({ postData }) {
  useEffect(() => {
    // Re-highlight code blocks when content changes
    if (typeof window !== 'undefined') {
      Prism.highlightAll();
    }
  }, [postData]);

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

  const firstImage = getFirstImage(postData.contentHtml);
  const siteUrl = 'https://xbz0n.sh'; // Update site URL

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# {postData.title}</title>
        <meta name="description" content="Ivan Spiridonov (xbz0n) - Offensive security professional specializing in Red Teaming, Web/Mobile/AD Pentesting, and vulnerability research. Discover pentesting insights, exploit techniques, and security tools." />
        
        {/* Open Graph / Facebook */}
        <meta property="og:type" content="article" />
        <meta property="og:url" content={`${siteUrl}/blog/${postData.slug}`} />
        <meta property="og:title" content={postData.title} />
        <meta property="og:description" content={postData.excerpt} />
        {firstImage && <meta property="og:image" content={firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}`} />}
        {firstImage && <meta property="og:image:width" content="1200" />}
        {firstImage && <meta property="og:image:height" content="630" />}
        {firstImage && <meta property="og:image:alt" content={postData.title} />}
        
        {/* Twitter */}
        <meta property="twitter:card" content="summary_large_image" />
        <meta property="twitter:url" content={`${siteUrl}/blog/${postData.slug}`} />
        <meta property="twitter:title" content={postData.title} />
        <meta property="twitter:description" content={postData.excerpt} />
        {firstImage && <meta property="twitter:image" content={firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}`} />}
        
        {/* LinkedIn specific */}
        {firstImage && <meta property="image" content={firstImage.startsWith('http') ? firstImage : `${siteUrl}${firstImage}`} />}
        <meta property="author" content="Ivan Spiridonov" />
        
        {/* Canonical URL */}
        <link rel="canonical" href={`${siteUrl}/blog/${postData.slug}`} />
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
      </article>
    </>
  );
}

export async function getStaticPaths() {
  try {
    const postsDirectory = path.join(process.cwd(), 'posts');
    const fileNames = fs.readdirSync(postsDirectory);
    
    const paths = fileNames.map((fileName) => {
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
  
  // Apply language-specific syntax highlighting to code blocks
  // First transformation: Add language class based on info string
  cleaned = cleaned.replace(
    /<pre><code>```(\w+)([\s\S]*?)```<\/code><\/pre>/g,
    function(match, lang, code) {
      return `<pre class="language-${lang}"><code class="language-${lang}">${code}</code></pre>`;
    }
  );
  
  // Second transformation: Fix properly formatted code blocks with language classes
  cleaned = cleaned.replace(
    /<pre><code class="language-(\w+)">([\s\S]*?)<\/code><\/pre>/g,
    '<pre class="language-$1"><code class="language-$1">$2</code></pre>'
  );

  // Third transformation: Handle remaining code blocks without specified language
  cleaned = cleaned.replace(
    /<pre><code>([\s\S]*?)<\/code><\/pre>/g,
    function(match, code) {
      if (!code.startsWith('<pre class="language-')) {
        return `<pre class="language-none"><code class="language-none">${code}</code></pre>`;
      }
      return match;
    }
  );
  
  // Fix the issue with backtick symbols showing in rendered inline code
  // This replaces any remaining visible backticks with proper inline code formatting
  cleaned = cleaned.replace(/`([^`]+)`/g, '<code>$1</code>');
  
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
      .use(html, { sanitize: false })
      .process(content);
    
    // Get the HTML as a string
    let contentHtml = processedContent.toString();
    
    // Clean up the HTML content (fix code blocks and inline code)
    contentHtml = cleanHtml(contentHtml);
    
    // Remove the first h1 header from the content to avoid duplicate titles
    contentHtml = contentHtml.replace(/<h1[^>]*>.*?<\/h1>/, '');
    
    return {
      props: {
        postData: {
          slug: params.slug,
          contentHtml,
          excerpt,
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
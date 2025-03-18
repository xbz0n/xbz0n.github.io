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

  return (
    <>
      <Head>
        <title>{postData.title} | Ivan Spiridonov</title>
        <meta name="description" content={postData.excerpt} />
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
    
    // Filter out the part2 and part3 redirector posts
    const filteredFileNames = fileNames.filter(fileName => 
      fileName !== 'c2-redirectors-part2.md' && 
      fileName !== 'c2-redirectors-part3.md'
    );
    
    const paths = filteredFileNames.map((fileName) => {
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
    
    const excerpt = content.slice(0, 160).trim() + '...';
    
    // Process the content to convert markdown to HTML
    const processedContent = await remark()
      .use(html, { sanitize: false })
      .process(content);
    
    // Get the HTML as a string
    let contentHtml = processedContent.toString();
    
    // Clean up the HTML content (fix code blocks and inline code)
    contentHtml = cleanHtml(contentHtml);
    
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
import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import Link from 'next/link';
import { format } from 'date-fns';
import Head from 'next/head';

export default function Blog({ posts }) {
  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Blog</title>
        <meta name="description" content="Ivan Spiridonov (xbz0n) - Offensive security professional specializing in Red Teaming, Web/Mobile/AD Pentesting, and vulnerability research. Discover pentesting insights, exploit techniques, and security tools." />
        <link rel="canonical" href="https://xbz0n.sh/blog" />
      </Head>
      
      <div className="space-y-8">
        <h1 className="text-3xl font-bold">Blog</h1>
        <p className="text-gray-400">
          Security research, exploit development, and technical write-ups covering various aspects of offensive security and penetration testing.
        </p>
        
        <div className="space-y-8">
          {posts.map((post) => (
            <article key={post.slug} className="bg-secondary/50 rounded-lg border border-gray-700 p-5 transition-all hover:border-accent/40">
              <Link href={`/blog/${post.slug}`}>
                <h2 className="text-xl font-semibold mb-2 hover:text-accent">{post.title}</h2>
              </Link>
              
              <div className="mb-3">
                {post.tags && post.tags.map(tag => (
                  <span key={tag} className={`badge ${tag.toLowerCase().includes('cve') ? 'badge-cve' : 'badge-certification'} mr-2`}>
                    {tag}
                  </span>
                ))}
                <time className="text-sm text-gray-400 ml-2" dateTime={post.date}>
                  {format(new Date(post.date), 'MMMM d, yyyy')}
                </time>
              </div>
              
              <p className="text-gray-300">{post.excerpt}</p>
              
              <Link href={`/blog/${post.slug}`} className="inline-block mt-4 text-accent hover:text-accent/80">
                Read full post →
              </Link>
            </article>
          ))}
        </div>
      </div>
    </>
  );
}

// Function to clean markdown formatting from excerpt
function cleanExcerpt(content) {
  // Remove headers (any number of # followed by a space)
  let clean = content.replace(/^#+\s.*$/gm, '');
  
  // Remove entire lines that contain image markdown
  clean = clean.replace(/^.*!\[.*\].*$/gm, '');
  
  // Also remove any remaining image markdown
  clean = clean.replace(/!\[.*?\]\(.*?\)/g, '');
  
  // Remove inline code formatting (backticks)
  clean = clean.replace(/`([^`]+)`/g, '$1');
  
  // Remove bold/italic formatting
  clean = clean.replace(/\*\*([^*]+)\*\*/g, '$1'); // Bold
  clean = clean.replace(/\*([^*]+)\*/g, '$1');     // Italic
  clean = clean.replace(/__([^_]+)__/g, '$1');     // Bold
  clean = clean.replace(/_([^_]+)_/g, '$1');       // Italic
  
  // Remove links
  clean = clean.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
  
  // Remove blockquotes
  clean = clean.replace(/^>\s(.*)$/gm, '$1');
  
  // Remove horizontal rules
  clean = clean.replace(/^---$|^\*\*\*$|^___$/gm, '');
  
  return clean;
}

// New function to extract a meaningful excerpt
function generateExcerpt(content) {
  // First clean the markdown syntax
  let cleaned = cleanExcerpt(content);
  
  // Split into paragraphs (sequences of non-empty lines)
  const paragraphs = cleaned.split(/\n{2,}/)
    .map(p => p.trim())
    .filter(p => p.length > 0 && !p.includes('!['));
  
  // Skip the first paragraph for shellcode article as it's empty due to image
  // Start from second actual paragraph for more meaningful text
  let startParagraph = 1;
  
  // If we don't have enough paragraphs, use the first non-empty one
  if (paragraphs.length <= 1) {
    startParagraph = 0;
  }
  
  // Safety check - make sure we have a paragraph
  if (startParagraph >= paragraphs.length) {
    startParagraph = 0;
  }
  
  // Get the selected paragraph
  let excerpt = paragraphs[startParagraph] || 'Read more...';
  
  // Make sure excerpt isn't too short
  if (excerpt.length < 40 && paragraphs.length > startParagraph + 1) {
    excerpt = paragraphs[startParagraph + 1];
  }
  
  // Truncate if necessary and add ellipsis
  if (excerpt.length > 200) {
    // Try to truncate at a sentence boundary
    const sentenceEnd = excerpt.slice(150, 200).search(/[.!?]\s/);
    if (sentenceEnd !== -1) {
      excerpt = excerpt.slice(0, 150 + sentenceEnd + 1) + '...';
    } else {
      // If no sentence boundary found, truncate at a word boundary
      const lastSpace = excerpt.slice(0, 200).lastIndexOf(' ');
      excerpt = excerpt.slice(0, lastSpace || 200) + '...';
    }
  }
  
  return excerpt;
}

export async function getStaticProps() {
  const postsDirectory = path.join(process.cwd(), 'posts');
  let posts = [];
  
  try {
    const fileNames = fs.readdirSync(postsDirectory);
    
    posts = fileNames.map((fileName) => {
      const slug = fileName.replace(/\.md$/, '');
      const fullPath = path.join(postsDirectory, fileName);
      const fileContents = fs.readFileSync(fullPath, 'utf8');
      const { data, content } = matter(fileContents);
      
      // Generate a meaningful excerpt
      const excerpt = generateExcerpt(content);
      
      return {
        slug,
        excerpt,
        ...data,
      };
    });
    
    posts = posts.sort((a, b) => {
      if (a.date < b.date) {
        return 1;
      } else {
        return -1;
      }
    });
  } catch (error) {
    console.error('Error loading posts:', error);
    posts = [];
  }
  
  return {
    props: {
      posts,
    },
  };
}
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
        <meta name="description" content="Security research, exploit development, and technical write-ups by Ivan Spiridonov" />
      </Head>
      
      <div className="space-y-8">
        <h1 className="text-3xl font-bold">Blog</h1>
        
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
  
  // Remove inline code formatting (backticks)
  clean = clean.replace(/`([^`]+)`/g, '$1');
  
  // Remove bold/italic formatting
  clean = clean.replace(/\*\*([^*]+)\*\*/g, '$1'); // Bold
  clean = clean.replace(/\*([^*]+)\*/g, '$1');     // Italic
  clean = clean.replace(/__([^_]+)__/g, '$1');     // Bold
  clean = clean.replace(/_([^_]+)_/g, '$1');       // Italic
  
  // Remove links
  clean = clean.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
  
  // Remove images - fix the regex to match both with and without alt text
  clean = clean.replace(/!\[[^\]]*\]\([^)]+\)/g, '');
  
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
  const paragraphs = cleaned.split(/\n{2,}/).map(p => p.trim()).filter(p => p.length > 0);
  
  // Find the first real paragraph (skip potential titles and short phrases)
  let startParagraph = 0;
  // Skip paragraphs that are likely titles or just image captions
  while (startParagraph < paragraphs.length && 
         (paragraphs[startParagraph].length < 40 || 
          paragraphs[startParagraph].includes('# ') || 
          paragraphs[startParagraph].includes('## '))) {
    startParagraph++;
  }
  
  // If we've gone through all paragraphs, go back to the longest one we found
  if (startParagraph >= paragraphs.length) {
    const lengths = paragraphs.map(p => p.length);
    startParagraph = lengths.indexOf(Math.max(...lengths));
  }
  
  // Get the selected paragraph and ensure it's not too long for an excerpt
  let excerpt = paragraphs[startParagraph] || '';
  
  // Truncate if necessary and add ellipsis
  if (excerpt.length > 200) {
    // Try to truncate at a sentence boundary
    const sentenceEnd = excerpt.slice(150, 200).search(/[.!?]\s/);
    if (sentenceEnd !== -1) {
      excerpt = excerpt.slice(0, 150 + sentenceEnd + 1) + '...';
    } else {
      // If no sentence boundary found, truncate at a word boundary
      const lastSpace = excerpt.slice(0, 200).lastIndexOf(' ');
      excerpt = excerpt.slice(0, lastSpace) + '...';
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
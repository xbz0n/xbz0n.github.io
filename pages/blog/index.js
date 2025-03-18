import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import BlogPostCard from '../../components/BlogPostCard';

export default function Blog({ posts }) {
  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <h1 className="text-3xl font-bold">Security Research Blog</h1>
        <p className="text-gray-400">
          Articles, tutorials, and insights on penetration testing, vulnerability research, 
          and offensive security techniques.
        </p>
      </div>
      
      <div className="grid grid-cols-1 gap-6">
        {posts.map((post) => (
          <BlogPostCard
            key={post.slug}
            title={post.title}
            excerpt={post.excerpt}
            date={post.date}
            slug={post.slug}
          />
        ))}
      </div>
    </div>
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
  
  // Remove images
  clean = clean.replace(/!\[([^\]]+)\]\([^)]+\)/g, '');
  
  // Remove blockquotes
  clean = clean.replace(/^>\s(.*)$/gm, '$1');
  
  // Remove horizontal rules
  clean = clean.replace(/^---$|^\*\*\*$|^___$/gm, '');
  
  // Normalize whitespace
  clean = clean.replace(/\n+/g, ' ').trim();
  
  return clean;
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
      
      // Clean the content of markdown formatting
      const cleanContent = cleanExcerpt(content);
      
      // Create the excerpt
      const excerpt = cleanContent.slice(0, 200) + '...';
      
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
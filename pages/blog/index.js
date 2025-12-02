import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import Link from 'next/link';
import { format } from 'date-fns';
import Head from 'next/head';

export default function Blog({ posts }) {
  // Function to determine category from tags for glow effect
  const getCategoryGlow = (tags) => {
    if (!tags) return 'hover:shadow-accent/20';

    const tagStr = tags.join(' ').toLowerCase();
    if (tagStr.includes('cve')) return 'hover:shadow-red-500/30';
    if (tagStr.includes('red team') || tagStr.includes('post-exploitation')) return 'hover:shadow-green-500/30';
    if (tagStr.includes('web') || tagStr.includes('xss') || tagStr.includes('graphql')) return 'hover:shadow-blue-500/30';
    if (tagStr.includes('exploit') || tagStr.includes('shellcode')) return 'hover:shadow-purple-500/30';

    return 'hover:shadow-accent/30';
  };

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Blog</title>
        <meta name="description" content="Security research articles covering penetration testing, exploit development, red team operations, Active Directory attacks, web application security, and CVE disclosures by Ivan Spiridonov (xbz0n)." />
        <link rel="canonical" href="https://xbz0n.sh/blog" />
      </Head>

      <div className="space-y-8">
        <div className="space-y-4">
          <h1 className="text-3xl font-bold">Blog</h1>
          <p className="text-gray-400">
            Security research, exploit development, and technical write-ups covering various aspects of offensive security and penetration testing.
          </p>
          <div className="text-sm text-gray-500 font-mono">
            <span className="text-accent">[xbz0n@blog]$</span> ls -la articles/ | wc -l
            <br />
            <span className="text-gray-400">{posts.length} articles published</span>
          </div>
        </div>

        {/* 2-column grid layout */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {posts.map((post) => (
            <article
              key={post.slug}
              className={`bg-secondary/50 rounded-lg border border-gray-700 overflow-hidden transition-all hover:border-accent/60 ${getCategoryGlow(post.tags)} hover:shadow-lg group`}
            >
              {/* Terminal window title bar */}
              <div className="bg-gray-800/80 px-4 py-2 flex items-center space-x-2 border-b border-gray-700">
                <div className="flex space-x-2">
                  <div className="w-3 h-3 rounded-full bg-red-500"></div>
                  <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                  <div className="w-3 h-3 rounded-full bg-green-500"></div>
                </div>
                <div className="text-xs text-gray-400 font-mono ml-2">
                  {post.slug}.md
                </div>
              </div>

              {/* Article thumbnail */}
              {post.thumbnail && (
                <div className="relative h-48 overflow-hidden bg-gray-900">
                  <img
                    src={post.thumbnail}
                    alt={post.title}
                    className="w-full h-full object-cover opacity-80 group-hover:opacity-100 transition-opacity"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-secondary/90 to-transparent"></div>
                </div>
              )}

              {/* Content */}
              <div className="p-5 space-y-3">
                <Link href={`/blog/${post.slug}`}>
                  <h2 className="text-xl font-semibold hover:text-accent transition-colors line-clamp-2">
                    {post.title}
                  </h2>
                </Link>

                {/* Tags and metadata */}
                <div className="flex flex-wrap items-center gap-2">
                  {post.tags && post.tags.slice(0, 3).map(tag => (
                    <span
                      key={tag}
                      className={`badge ${
                        tag.toLowerCase().includes('cve')
                          ? 'badge-cve'
                          : tag.toLowerCase().includes('red team') || tag.toLowerCase().includes('post-exploitation')
                          ? 'badge-tool'
                          : 'badge-certification'
                      } text-xs`}
                    >
                      {tag}
                    </span>
                  ))}
                  {post.tags && post.tags.length > 3 && (
                    <span className="text-xs text-gray-500">+{post.tags.length - 3}</span>
                  )}
                </div>

                {/* Date and reading time */}
                <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
                  <time dateTime={post.date}>
                    📅 {format(new Date(post.date), 'MMM d, yyyy')}
                  </time>
                  <span className="text-accent">
                    ⏱ {post.readingTime} min read
                  </span>
                </div>

                {/* Excerpt */}
                <p className="text-gray-300 text-sm line-clamp-3">
                  {post.excerpt}
                </p>

                {/* Read more link */}
                <Link
                  href={`/blog/${post.slug}`}
                  className="inline-flex items-center text-accent hover:text-accent/80 text-sm font-mono group-hover:translate-x-1 transition-transform"
                >
                  <span className="text-gray-500">&gt;</span> cat {post.slug}.md
                </Link>
              </div>
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

// Function to extract a meaningful excerpt
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

// Function to extract first image from markdown
function extractFirstImage(content) {
  const imgRegex = /!\[.*?\]\((\/images\/[^)]+)\)/;
  const match = content.match(imgRegex);
  return match ? match[1] : null;
}

// Function to calculate reading time
function calculateReadingTime(content) {
  const wordsPerMinute = 200;
  const words = content.split(/\s+/).length;
  const readingTime = Math.ceil(words / wordsPerMinute);
  return readingTime;
}

export async function getStaticProps() {
  const postsDirectory = path.join(process.cwd(), 'posts');
  let posts = [];

  try {
    const fileNames = fs.readdirSync(postsDirectory);

    // Filter out non-markdown files and system files
    const markdownFiles = fileNames.filter(fileName =>
      fileName.endsWith('.md') &&
      !fileName.startsWith('.') &&
      !fileName.includes('.DS_Store')
    );

    posts = markdownFiles.map((fileName) => {
      const slug = fileName.replace(/\.md$/, '');
      const fullPath = path.join(postsDirectory, fileName);
      const fileContents = fs.readFileSync(fullPath, 'utf8');
      const { data, content } = matter(fileContents);

      // Generate a meaningful excerpt
      const excerpt = generateExcerpt(content);

      // Extract first image as thumbnail
      const thumbnail = extractFirstImage(content);

      // Calculate reading time
      const readingTime = calculateReadingTime(content);

      return {
        slug,
        excerpt,
        thumbnail,
        readingTime,
        ...data,
      };
    });

    // Filter out posts with invalid dates and sort
    posts = posts
      .filter(post => post.date && !isNaN(new Date(post.date)))
      .sort((a, b) => {
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

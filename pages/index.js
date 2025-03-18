import Link from 'next/link';
import { FaShieldAlt, FaCode, FaBug, FaFileAlt } from 'react-icons/fa';
import TerminalHero from '../components/TerminalHero';
import path from 'path';
import fs from 'fs';
import matter from 'gray-matter';
import { format } from 'date-fns';

export default function Home({ latestPost }) {
  return (
    <div className="space-y-16">
      {/* Hero Section */}
      <section className="py-8">
        <div className="grid md:grid-cols-2 gap-8 items-center">
          <div className="space-y-6">
            <h1 className="text-4xl font-bold leading-tight">
              <span className="bg-gradient-to-r from-accent to-blue-500 bg-clip-text text-transparent">
                Ivan Spiridonov
              </span>
              <span className="block text-gray-100 mt-2">Professional Penetration Tester</span>
            </h1>
            <p className="text-gray-400 text-lg">
              Specialized in discovering and exploiting security vulnerabilities in web applications, 
              networks, and infrastructure to help organizations improve their security posture.
            </p>
            <div className="flex flex-wrap gap-4">
              <Link href="/blog" className="btn btn-primary">
                Read My Blog
              </Link>
              <Link href="/cves" className="btn btn-outline">
                View My CVEs
              </Link>
            </div>
          </div>
          <div>
            <TerminalHero />
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section className="py-8">
        <h2 className="text-2xl font-bold mb-8 flex items-center">
          <FaShieldAlt className="mr-2 text-accent" />
          Expertise
        </h2>
        <div className="grid md:grid-cols-3 gap-6">
          <div className="bg-secondary/30 rounded-lg p-6 border border-gray-700">
            <FaCode className="text-accent text-2xl mb-4" />
            <h3 className="text-xl font-semibold mb-2">Web Application Security</h3>
            <p className="text-gray-400">
              Identifying and exploiting vulnerabilities in web applications to prevent potential security breaches.
            </p>
          </div>
          <div className="bg-secondary/30 rounded-lg p-6 border border-gray-700">
            <FaBug className="text-accent text-2xl mb-4" />
            <h3 className="text-xl font-semibold mb-2">Advanced Threat Detection</h3>
            <p className="text-gray-400">
              Red teaming and adversary emulation to test defenses against sophisticated attack techniques.
            </p>
          </div>
          <div className="bg-secondary/30 rounded-lg p-6 border border-gray-700">
            <FaFileAlt className="text-accent text-2xl mb-4" />
            <h3 className="text-xl font-semibold mb-2">Security Research</h3>
            <p className="text-gray-400">
              Discovering and responsibly disclosing vulnerabilities in software and systems with published CVEs.
            </p>
          </div>
        </div>
      </section>

      {/* Featured Content */}
      <section className="py-8">
        <div className="flex justify-between items-center mb-8">
          <h2 className="text-2xl font-bold">Latest Research</h2>
          <Link href="/blog" className="text-accent hover:text-accent/80">
            View all posts →
          </Link>
        </div>
        <div className="bg-secondary/30 rounded-lg p-6 border border-gray-700">
          <div className="mb-2">
            {latestPost.tags && latestPost.tags.map(tag => (
              <span key={tag} className={`badge ${tag.toLowerCase().includes('cve') ? 'badge-cve' : 'badge-certification'} mr-2`}>
                {tag}
              </span>
            ))}
            <span className="text-sm text-gray-400 ml-2">
              {format(new Date(latestPost.date), 'MMM d, yyyy')}
            </span>
          </div>
          <h3 className="text-xl font-semibold mb-2">
            {latestPost.title}
          </h3>
          <p className="text-gray-400 mb-4">
            {latestPost.excerpt}
          </p>
          <Link href={`/blog/${latestPost.slug}`} className="text-accent hover:text-accent/80">
            Read full analysis →
          </Link>
        </div>
      </section>
    </div>
  );
}

export async function getStaticProps() {
  const postsDirectory = path.join(process.cwd(), 'posts');
  const fileNames = fs.readdirSync(postsDirectory);
  
  const allPosts = fileNames.map(fileName => {
    // Remove ".md" from file name to get slug
    const slug = fileName.replace(/\.md$/, '');
    
    // Read markdown file as string
    const fullPath = path.join(postsDirectory, fileName);
    const fileContents = fs.readFileSync(fullPath, 'utf8');
    
    // Use gray-matter to parse the post metadata section
    const matterResult = matter(fileContents);
    
    // Create excerpt
    const excerpt = matterResult.content.trim().split('\n\n')[0].replace(/^#+\s+.*$/m, '').trim();
    
    // Combine the data
    return {
      slug,
      title: matterResult.data.title,
      date: matterResult.data.date,
      tags: matterResult.data.tags,
      excerpt: excerpt.substring(0, 150) + (excerpt.length > 150 ? '...' : '')
    };
  });
  
  // Sort posts by date
  const sortedPosts = allPosts.sort((a, b) => {
    return new Date(b.date) - new Date(a.date);
  });
  
  const latestPost = sortedPosts.length > 0 ? sortedPosts[0] : {
    title: 'No posts available',
    date: new Date().toISOString(),
    slug: '',
    excerpt: 'There are currently no blog posts available.',
    tags: []
  };
  
  return {
    props: {
      latestPost
    }
  };
} 
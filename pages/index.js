import Link from 'next/link';
import { FaShieldAlt, FaCode, FaBug, FaFileAlt } from 'react-icons/fa';
import TerminalHero from '../components/TerminalHero';
import path from 'path';
import fs from 'fs';
import matter from 'gray-matter';
import { format } from 'date-fns';
import Head from 'next/head';
import { useEffect, useState } from 'react';

export default function Home({ latestPosts }) {
  const [isGlitching, setIsGlitching] = useState(false);
  
  useEffect(() => {
    // Randomly trigger the glitch effect
    const glitchInterval = setInterval(() => {
      const shouldGlitch = Math.random() > 0.7;
      if (shouldGlitch) {
        setIsGlitching(true);
        // Turn off glitch after a short period
        setTimeout(() => setIsGlitching(false), 2000);
      }
    }, 3000);
    
    return () => clearInterval(glitchInterval);
  }, []);
  
  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Command Line to Front Line</title>
        <meta name="description" content="Ivan Spiridonov (xbz0n) - Offensive security professional specializing in Red Teaming, Web/Mobile/AD Pentesting, and vulnerability research. Discover pentesting insights, exploit techniques, and security tools." />
        <link rel="canonical" href="https://xbz0n.sh/" />
      </Head>
      
      <div className="space-y-16">
        <section className="py-8">
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div className="space-y-6">
              <h1 className="text-4xl font-bold leading-tight">
                <div className="glitch-wrapper">
                  <span 
                    className={`glitch ${isGlitching ? 'active' : 'no-glitch'}`} 
                    data-text="Ivan Spiridonov"
                  >
                    Ivan Spiridonov
                  </span>
                </div>
                <span className="block text-gray-100 mt-2 font-mono">Penetration Tester</span>
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
              <h3 className="text-xl font-semibold mb-2">Exploit Development</h3>
              <p className="text-gray-400">
                Creating proof-of-concept exploits for discovered vulnerabilities and developing custom security tools for specialized testing scenarios.
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

        <section className="py-8">
          <div className="flex justify-between items-center mb-8">
            <h2 className="text-2xl font-bold">Latest Research</h2>
            <Link href="/blog" className="text-accent hover:text-accent/80">
              View all posts →
            </Link>
          </div>
          
          {latestPosts.map((post, index) => (
            <div key={post.slug} className={`bg-secondary/30 rounded-lg p-6 border border-gray-700 ${index > 0 ? 'mt-6' : ''}`}>
              <div className="mb-2">
                {post.tags && post.tags.map(tag => (
                  <span key={tag} className={`badge ${tag.toLowerCase().includes('cve') ? 'badge-cve' : 'badge-certification'} mr-2`}>
                    {tag}
                  </span>
                ))}
                <span className="text-sm text-gray-400 ml-2">
                  {format(new Date(post.date), 'MMM d, yyyy')}
                </span>
              </div>
              <h3 className="text-xl font-semibold mb-2">
                {post.title}
              </h3>
              <p className="text-gray-400 mb-4">
                {post.excerpt}
              </p>
              <Link href={`/blog/${post.slug}`} className="text-accent hover:text-accent/80">
                Read full analysis →
              </Link>
            </div>
          ))}
        </section>
      </div>
    </>
  );
}

export async function getStaticProps() {
  const postsDirectory = path.join(process.cwd(), 'posts');
  const fileNames = fs.readdirSync(postsDirectory);
  
  const allPosts = fileNames.map((fileName) => {
    const slug = fileName.replace(/\.md$/, '');
    const fullPath = path.join(postsDirectory, fileName);
    const fileContents = fs.readFileSync(fullPath, 'utf8');
    const matterResult = matter(fileContents);
    
    // Extract a clean excerpt from the content
    const excerpt = matterResult.content.trim().split('\n\n')[0].replace(/^#+\s+.*$/m, '').trim();
    
    return {
      slug,
      excerpt,
      ...matterResult.data,
    };
  });
  
  // Sort posts by date
  const sortedPosts = allPosts.sort((a, b) => {
    return new Date(b.date) - new Date(a.date);
  });
  
  // Get the latest 3 posts
  const latestPosts = sortedPosts.slice(0, 3);
  
  return {
    props: {
      latestPosts,
    },
  };
} 
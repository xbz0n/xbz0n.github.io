import Link from 'next/link';
import { FaShieldAlt, FaCode, FaBug, FaFileAlt } from 'react-icons/fa';
import TerminalHero from '../components/TerminalHero';
import path from 'path';
import fs from 'fs';
import matter from 'gray-matter';
import { format } from 'date-fns';
import Head from 'next/head';
import { useState, useEffect, useRef } from 'react';

export default function Home({ latestPosts }) {
  const nameString = "Ivan Spiridonov";
  const nameRef = useRef(null);
  const [isScrambling, setIsScrambling] = useState(false);
  
  const scrambleText = () => {
    if (!nameRef.current || isScrambling) return;
    
    setIsScrambling(true);
    
    const symbols = ['$', '#', '!', '@', '%', '&', '*', '>', '<', '^', '~', '+', '=', '{', '}'];
    const chars = nameRef.current.querySelectorAll('.char');
    const originalChars = [...chars].map(c => c.textContent);
    
    // Select a random subset of characters to glitch (between 2-5 characters)
    const numCharsToGlitch = Math.floor(Math.random() * 4) + 2;
    const charsToGlitch = new Set();
    
    // Only consider non-space characters
    const validIndices = originalChars
      .map((char, index) => char !== ' ' ? index : -1)
      .filter(index => index !== -1);
    
    // Randomly select indices to glitch
    while (charsToGlitch.size < numCharsToGlitch && charsToGlitch.size < validIndices.length) {
      const randomIndex = validIndices[Math.floor(Math.random() * validIndices.length)];
      charsToGlitch.add(randomIndex);
    }
    
    let iterations = 0;
    const maxIterations = 10;
    
    const interval = setInterval(() => {
      chars.forEach((char, index) => {
        // Skip if not in our set of characters to glitch
        if (!charsToGlitch.has(index)) return;
        
        // Gradually restore original characters as iterations progress
        if (iterations > maxIterations / 2 && Math.random() < iterations / maxIterations) {
          char.textContent = originalChars[index];
          char.style.animation = 'none';
          return;
        }
        
        // Replace with random symbol
        if (Math.random() < 0.6) { // Increased probability for more visible effect
          char.textContent = symbols[Math.floor(Math.random() * symbols.length)];
          char.style.animation = `charScramble ${0.2 + Math.random() * 0.3}s ease`;
        }
      });
      
      iterations++;
      
      if (iterations >= maxIterations) {
        clearInterval(interval);
        
        // Restore all characters to original
        chars.forEach((char, index) => {
          char.textContent = originalChars[index];
          char.style.animation = 'none';
        });
        
        setTimeout(() => {
          setIsScrambling(false);
        }, 1000);
      }
    }, 100);
  };
  
  useEffect(() => {
    // Split the text into individual characters with spans
    if (nameRef.current) {
      const text = nameRef.current.textContent;
      nameRef.current.innerHTML = '';
      
      for (let i = 0; i < text.length; i++) {
        const charSpan = document.createElement('span');
        charSpan.className = 'char';
        charSpan.textContent = text[i];
        nameRef.current.appendChild(charSpan);
      }
    }
  }, []);
  
  useEffect(() => {
    // Randomly trigger the scramble effect
    const randomInterval = setInterval(() => {
      if (Math.random() > 0.7 && !isScrambling) {
        scrambleText();
      }
    }, 3000);
    
    return () => clearInterval(randomInterval);
  }, [isScrambling]);
  
  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Command Line to Front Line</title>
        <meta name="description" content="Ivan Spiridonov (xbz0n) - Offensive Security Consultant specializing in penetration testing, red team operations, vulnerability research, and exploit development. Published CVEs and security tools." />
        <link rel="canonical" href="https://xbz0n.sh/" />
      </Head>
      
      <div className="space-y-16">
        <section className="py-8">
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div className="space-y-6">
              <h1 className="leading-tight">
                <div className="block">
                  <span 
                    ref={nameRef}
                    className="name-title text-5xl" 
                  >
                    {nameString}
                  </span>
                </div>
                <div className="mt-2">
                  <span className="job-title text-2xl">Offensive Security Consultant</span>
                </div>
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
  
  // Filter out non-markdown files and system files
  const markdownFiles = fileNames.filter(fileName => 
    fileName.endsWith('.md') && 
    !fileName.startsWith('.') &&
    !fileName.includes('.DS_Store')
  );
  
  const allPosts = markdownFiles.map((fileName) => {
    const slug = fileName.replace(/\.md$/, '');
    const fullPath = path.join(postsDirectory, fileName);
    const fileContents = fs.readFileSync(fullPath, 'utf8');
    const matterResult = matter(fileContents);
    
    // Extract a clean excerpt from the content
    // The matter library already separates frontmatter from content
    // So matterResult.content only contains the actual markdown content
    const contentLines = matterResult.content.trim().split('\n');
    
    // Find the first paragraph that's not a header, image, or empty line
    let excerpt = '';
    for (let i = 0; i < contentLines.length; i++) {
      const line = contentLines[i].trim();
      
      // Skip empty lines, headers, and image references
      if (line.length === 0 || 
          line.startsWith('#') || 
          line.startsWith('![') || 
          line.startsWith('<img')) {
        continue;
      }
      
      // If we found a good line, use it and potentially the next few lines
      const paragraphLines = [];
      for (let j = i; j < contentLines.length && j < i + 3; j++) {
        const nextLine = contentLines[j].trim();
        if (nextLine.length === 0) break;
        if (nextLine.startsWith('#') || nextLine.startsWith('![') || nextLine.startsWith('<img')) break;
        paragraphLines.push(nextLine);
      }
      
      excerpt = paragraphLines.join(' ');
      break;
    }
    
    // Fallback to a simple approach if no good excerpt was found
    if (!excerpt) {
      excerpt = matterResult.content
        .replace(/^#+\s+.*$/gm, '') // Remove headers
        .replace(/!\[.*?\]\(.*?\)/g, '') // Remove images
        .trim()
        .split('\n\n')[0] // Get first paragraph
        .trim();
    }
    
    // Limit excerpt length
    if (excerpt.length > 200) {
      excerpt = excerpt.substring(0, 197) + '...';
    }
    
    return {
      slug,
      excerpt,
      ...matterResult.data,
    };
  });
  
  // Filter out posts with invalid dates and sort posts by date
  const sortedPosts = allPosts
    .filter(post => post.date && !isNaN(new Date(post.date)))
    .sort((a, b) => {
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
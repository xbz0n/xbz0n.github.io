import Link from 'next/link';
import { FaGithub, FaTwitter, FaLinkedinIn, FaRss, FaEnvelope } from 'react-icons/fa';
import siteData from '../data/site-data.json';

export default function Footer() {
  const currentYear = new Date().getFullYear();
  const recentPosts = siteData.recentPosts || [];
  const popularTags = siteData.popularTags || [];

  return (
    <footer className="bg-primary/90 border-t border-gray-800 mt-16">
      <div className="container py-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          <div className="space-y-3">
            <div className="font-mono text-accent text-sm">[xbz0n@sh]$</div>
            <p className="text-sm text-gray-400">
              Offensive security research, exploit development, and CVE disclosures by
              Ivan Spiridonov.
            </p>
            <div className="flex gap-3 text-gray-400 pt-1">
              <a
                href="https://github.com/xbz0n"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="GitHub"
                className="hover:text-accent"
              >
                <FaGithub size={18} />
              </a>
              <a
                href="https://twitter.com/xbz0n"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Twitter"
                className="hover:text-accent"
              >
                <FaTwitter size={18} />
              </a>
              <a
                href="https://www.linkedin.com/in/ivanspiridonov/"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="LinkedIn"
                className="hover:text-accent"
              >
                <FaLinkedinIn size={18} />
              </a>
              <a href="/rss.xml" aria-label="RSS feed" className="hover:text-accent">
                <FaRss size={18} />
              </a>
              <a
                href="mailto:ivanspiridonov@gmail.com"
                aria-label="Email"
                className="hover:text-accent"
              >
                <FaEnvelope size={18} />
              </a>
            </div>
          </div>

          <div className="space-y-3">
            <div className="text-sm font-bold text-gray-200">Site</div>
            <ul className="space-y-2 text-sm">
              <li>
                <Link href="/" className="text-gray-400 hover:text-accent">
                  Home
                </Link>
              </li>
              <li>
                <Link href="/blog" className="text-gray-400 hover:text-accent">
                  Blog
                </Link>
              </li>
              <li>
                <Link href="/cves" className="text-gray-400 hover:text-accent">
                  CVEs
                </Link>
              </li>
              <li>
                <Link href="/tools" className="text-gray-400 hover:text-accent">
                  Tools
                </Link>
              </li>
              <li>
                <Link href="/about" className="text-gray-400 hover:text-accent">
                  About
                </Link>
              </li>
            </ul>
          </div>

          {recentPosts.length > 0 && (
            <div className="space-y-3">
              <div className="text-sm font-bold text-gray-200">Recent posts</div>
              <ul className="space-y-2 text-sm">
                {recentPosts.map(p => (
                  <li key={p.slug}>
                    <Link
                      href={`/blog/${p.slug}`}
                      className="text-gray-400 hover:text-accent line-clamp-2 block"
                    >
                      {p.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {popularTags.length > 0 && (
            <div className="space-y-3">
              <div className="text-sm font-bold text-gray-200">Popular topics</div>
              <div className="flex flex-wrap gap-x-3 gap-y-2">
                {popularTags.map(t => (
                  <Link
                    key={t.slug}
                    href={`/blog/tag/${t.slug}`}
                    className="text-xs text-gray-400 hover:text-accent font-mono"
                  >
                    #{t.slug}
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-col md:flex-row justify-between items-center pt-6 border-t border-gray-800 gap-2">
          <div className="text-sm text-gray-500">
            &copy; {currentYear} Ivan Spiridonov (xbz0n). All rights reserved.
          </div>
          <div className="text-xs text-gray-600 font-mono">
            Built with Next.js · static export
          </div>
        </div>
      </div>
    </footer>
  );
}

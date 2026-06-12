import Link from 'next/link';
import { FaGithub, FaTwitter, FaLinkedinIn } from 'react-icons/fa';

export default function AuthorBio() {
  return (
    <section className="mt-12 pt-8 border-t border-gray-700" aria-label="About the author">
      <div className="bg-secondary/30 rounded-lg border border-gray-700 p-6">
        <div className="flex items-start gap-4">
          <div className="flex-shrink-0 w-14 h-14 rounded-full bg-secondary border border-accent/40 flex items-center justify-center font-mono text-xl text-accent">
            xb
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-bold text-gray-100 mb-1">Ivan Spiridonov (xbz0n)</h3>
            <p className="text-sm text-gray-400 mb-3">
              Offensive Security Consultant — penetration testing, red teaming, vulnerability
              research, and exploit development. OSCE³ certified with multiple published CVEs.
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
              <Link href="/about" className="text-accent hover:text-accent/80">
                More about me →
              </Link>
              <a
                href="https://github.com/xbz0n"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-accent flex items-center gap-1"
              >
                <FaGithub /> GitHub
              </a>
              <a
                href="https://twitter.com/xbz0n"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-accent flex items-center gap-1"
              >
                <FaTwitter /> Twitter
              </a>
              <a
                href="https://www.linkedin.com/in/ivanspiridonov/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-accent flex items-center gap-1"
              >
                <FaLinkedinIn /> LinkedIn
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

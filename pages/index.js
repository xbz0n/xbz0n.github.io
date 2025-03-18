import Link from 'next/link';
import { FaShieldAlt, FaCode, FaBug, FaFileAlt } from 'react-icons/fa';
import TerminalHero from '../components/TerminalHero';

export default function Home() {
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
            <span className="badge badge-cve">CVE</span>
            <span className="text-sm text-gray-400 ml-2">Published</span>
          </div>
          <h3 className="text-xl font-semibold mb-2">
            Exploiting the vulnerability and gaining root privileges (CVE-2023–0830)
          </h3>
          <p className="text-gray-400 mb-4">
            A vulnerability in EasyNAS backup and restore script allowing arbitrary command execution with root privileges.
          </p>
          <Link href="/blog/cve-2023-0830" className="text-accent hover:text-accent/80">
            Read full analysis →
          </Link>
        </div>
      </section>
    </div>
  );
} 
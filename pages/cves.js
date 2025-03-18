import { FaBug, FaCalendar, FaExternalLinkAlt } from 'react-icons/fa';
import Link from 'next/link';
import Head from 'next/head';

export default function CVEs() {
  const cves = [
    {
      id: "CVE-2023-0830",
      name: "EasyNAS 1.1.0 - Authenticated Remote Code Execution",
      description: "EasyNAS 1.1.0 allows authenticated users to execute arbitrary code via shell metacharacters in certain file operations.",
      date: "March 2023",
      cveLink: "https://nvd.nist.gov/vuln/detail/CVE-2023-0830",
      blogLink: "/blog/cve-2023-0830",
      severity: "High"
    }
  ];

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Discovered CVEs</title>
        <meta name="description" content="Security vulnerabilities discovered by Ivan Spiridonov with assigned CVE identifiers" />
      </Head>
      
      <div className="space-y-8">
        <div className="space-y-4">
          <h1 className="text-3xl font-bold">CVE Discoveries</h1>
          <p className="text-gray-400">
            Security vulnerabilities that I've discovered, responsibly disclosed, and been acknowledged for through the Common Vulnerabilities and Exposures (CVE) program.
          </p>
        </div>
        
        <div className="space-y-6">
          {cves.map((cve, index) => (
            <div key={index} className="bg-secondary/50 rounded-lg border border-gray-700 p-5 hover:border-accent/40 transition-all">
              <div className="flex items-start justify-between">
                <h2 className="text-xl font-semibold text-accent">{cve.id}</h2>
                <span className={`badge ${cve.severity === 'Critical' ? 'badge-critical' : cve.severity === 'High' ? 'badge-high' : 'badge-medium'}`}>
                  {cve.severity}
                </span>
              </div>
              
              <h3 className="text-lg font-medium mt-2">{cve.name}</h3>
              
              <p className="mt-3 text-gray-300">
                {cve.description}
              </p>
              
              <div className="mt-4 flex items-center text-sm text-gray-400">
                <FaCalendar className="mr-1" />
                <span>{cve.date}</span>
              </div>
              
              <div className="mt-4 flex space-x-4">
                <a 
                  href={cve.cveLink} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center text-sm text-accent hover:text-accent/80"
                >
                  <FaExternalLinkAlt className="mr-1 h-3 w-3" />
                  <span>CVE Database</span>
                </a>
                
                {cve.blogLink && (
                  <Link href={cve.blogLink} className="flex items-center text-sm text-accent hover:text-accent/80">
                    <FaBug className="mr-1" />
                    <span>Read Analysis</span>
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
} 
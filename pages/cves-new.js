import CVECardEnhanced from '../components/CVECardEnhanced';
import Head from 'next/head';

export default function CVEsNew() {
  const cves = [
    {
      id: "CVE-2025-50674",
      link: "https://nvd.nist.gov/vuln/detail/CVE-2025-50674",
      description: "Privilege escalation vulnerability in OpenMediaVault 7.4.17 allowing authenticated users to gain root access through password change function.",
      severity: "Critical",
      cvss: 9.8,
      type: "Privilege Escalation",
      product: "OpenMediaVault 7.4.17",
      year: "2025",
      blogPost: "/blog/CVE-2025-50674"
    },
    {
      id: "CVE-2024-32136",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-32136",
      description: "A SQL injection vulnerability in database systems leading to unauthorized access.",
      severity: "High",
      cvss: 8.5,
      type: "SQL Injection",
      product: "Database Systems",
      year: "2024"
    },
    {
      id: "CVE-2023-0830",
      link: "https://www.cve.org/CVERecord?id=CVE-2023-0830",
      description: "Vulnerability in EasyNAS backup and restore script allowing arbitrary command execution with root privileges.",
      severity: "Critical",
      cvss: 9.8,
      type: "Command Injection",
      product: "EasyNAS",
      year: "2023",
      blogPost: "/blog/cve-2023-0830"
    },
    {
      id: "CVE-2024-0365",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0365",
      description: "A security flaw in system components allowing privilege escalation.",
      severity: "High",
      cvss: 7.8,
      type: "Privilege Escalation",
      product: "System Components",
      year: "2024"
    },
    {
      id: "CVE-2024-0399",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0399",
      description: "A critical vulnerability affecting data integrity and confidentiality.",
      severity: "Critical",
      cvss: 9.1,
      type: "Data Exposure",
      product: "Multiple Systems",
      year: "2024"
    },
    {
      id: "CVE-2024-0405",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0405",
      description: "An input validation vulnerability leading to remote code execution.",
      severity: "Critical",
      cvss: 9.8,
      type: "Remote Code Execution",
      product: "Web Applications",
      year: "2024"
    },
    {
      id: "CVE-2024-0566",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0566",
      description: "A SQL injection vulnerability allowing data exfiltration in web applications.",
      severity: "High",
      cvss: 8.6,
      type: "SQL Injection",
      product: "Web Applications",
      year: "2024"
    },
    {
      id: "CVE-2024-30240",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-30240",
      description: "A critical SQL injection vulnerability allowing authentication bypass in systems.",
      severity: "Critical",
      cvss: 9.8,
      type: "SQL Injection",
      product: "Authentication Systems",
      year: "2024"
    },
    {
      id: "CVE-2024-31370",
      link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-31370",
      description: "An injection vulnerability allowing arbitrary code execution.",
      severity: "High",
      cvss: 8.8,
      type: "Code Injection",
      product: "Multiple Systems",
      year: "2024"
    },
    {
      id: "CVE-2024-33911",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-33911",
      description: "A vulnerability affecting system configurations and security controls.",
      severity: "Medium",
      cvss: 6.5,
      type: "Security Misconfiguration",
      product: "System Configurations",
      year: "2024"
    }
  ];

  // Calculate stats
  const totalCVEs = cves.length;
  const latestCVE = cves[0];
  const criticalCount = cves.filter(c => c.severity === 'Critical').length;
  const highCount = cves.filter(c => c.severity === 'High').length;
  const mediumCount = cves.filter(c => c.severity === 'Medium').length;

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Discovered CVEs</title>
        <meta name="description" content="Published CVEs by Ivan Spiridonov (xbz0n) - Security vulnerabilities discovered in OpenMediaVault, EasyNAS, and other systems. Includes privilege escalation, SQL injection, and command injection flaws." />
        <link rel="canonical" href="https://xbz0n.sh/cves-new" />
      </Head>

      <div className="space-y-8">
        <div className="space-y-4">
          <h1 className="text-3xl font-bold">CVEs</h1>
          <p className="text-gray-400">
            Common Vulnerabilities and Exposures (CVEs) discovered and responsibly disclosed
            as part of security research and penetration testing efforts.
          </p>
        </div>

        {/* Stats Dashboard */}
        <div className="bg-secondary/30 rounded-lg border border-gray-700 p-6 font-mono">
          <div className="text-sm text-gray-400 mb-4">
            <span className="text-accent">[xbz0n@vulnerabilities]$</span> cat stats.txt
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-black/40 rounded p-4 border border-gray-700/50">
              <div className="text-xs text-gray-500 uppercase mb-1">Total CVEs</div>
              <div className="text-3xl font-bold text-accent">{totalCVEs}</div>
            </div>
            <div className="bg-black/40 rounded p-4 border border-red-500/30">
              <div className="text-xs text-gray-500 uppercase mb-1">Critical</div>
              <div className="text-3xl font-bold text-red-500">{criticalCount}</div>
            </div>
            <div className="bg-black/40 rounded p-4 border border-orange-500/30">
              <div className="text-xs text-gray-500 uppercase mb-1">High</div>
              <div className="text-3xl font-bold text-orange-500">{highCount}</div>
            </div>
            <div className="bg-black/40 rounded p-4 border border-yellow-500/30">
              <div className="text-xs text-gray-500 uppercase mb-1">Medium</div>
              <div className="text-3xl font-bold text-yellow-500">{mediumCount}</div>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-gray-700/50 text-sm">
            <div className="flex items-center justify-between text-gray-400">
              <span>Latest Discovery:</span>
              <span className="text-accent font-bold">{latestCVE.id}</span>
            </div>
          </div>
        </div>

        {/* CVE Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {cves.map((cve, index) => (
            <CVECardEnhanced
              key={index}
              id={cve.id}
              link={cve.link}
              description={cve.description}
              severity={cve.severity}
              cvss={cve.cvss}
              type={cve.type}
              product={cve.product}
              year={cve.year}
              blogPost={cve.blogPost}
            />
          ))}
        </div>
      </div>
    </>
  );
}

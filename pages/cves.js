import CVECard from '../components/CVECard';
import Head from 'next/head';

export default function CVEs() {
  const cves = [
    {
      id: "CVE-2024-32136",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-32136",
      description: "A SQL injection vulnerability in database systems leading to unauthorized access."
    },
    {
      id: "CVE-2023-0830",
      link: "https://www.cve.org/CVERecord?id=CVE-2023-0830",
      description: "Vulnerability in EasyNAS backup and restore script allowing arbitrary command execution with root privileges."
    },
    {
      id: "CVE-2024-0365",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0365",
      description: "A security flaw in system components allowing privilege escalation."
    },
    {
      id: "CVE-2024-0399",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0399",
      description: "A critical vulnerability affecting data integrity and confidentiality."
    },
    {
      id: "CVE-2024-0405",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0405",
      description: "An input validation vulnerability leading to remote code execution."
    },
    {
      id: "CVE-2024-0566",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-0566",
      description: "A SQL injection vulnerability allowing data exfiltration in web applications."
    },
    {
      id: "CVE-2024-30240",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-30240",
      description: "A critical SQL injection vulnerability allowing authentication bypass in systems."
    },
    {
      id: "CVE-2024-31370",
      link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-31370",
      description: "An injection vulnerability allowing arbitrary code execution."
    },
    {
      id: "CVE-2024-33911",
      link: "https://www.cve.org/CVERecord?id=CVE-2024-33911",
      description: "A vulnerability affecting system configurations and security controls."
    }
  ];

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Discovered CVEs</title>
        <meta name="description" content="Ivan Spiridonov (xbz0n) - Offensive security professional specializing in Red Teaming, Web/Mobile/AD Pentesting, and vulnerability research. Discover pentesting insights, exploit techniques, and security tools." />
        <link rel="canonical" href="https://xbz0n.sh/cves" />
      </Head>
      
      <div className="space-y-8">
        <div className="space-y-4">
          <h1 className="text-3xl font-bold">CVEs</h1>
          <p className="text-gray-400">
            Common Vulnerabilities and Exposures (CVEs) discovered and responsibly disclosed
            as part of security research and penetration testing efforts.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {cves.map((cve, index) => (
            <CVECard 
              key={index}
              id={cve.id}
              link={cve.link}
              description={cve.description}
            />
          ))}
        </div>
      </div>
    </>
  );
} 
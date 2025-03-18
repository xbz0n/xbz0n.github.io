import CVECard from '../components/CVECard';
import Head from 'next/head';

export default function CVEs() {
  const cves = [
    {
      id: "CVE-2023-0830",
      link: "https://nvd.nist.gov/vuln/detail/CVE-2023-0830",
      description: "Vulnerability in EasyNAS backup and restore script allowing arbitrary command execution with root privileges."
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
import ToolCard from '../components/ToolCard';
import Head from 'next/head';

export default function Tools() {
  const tools = [
    {
      name: "AspXVenom",
      repo: "https://github.com/xbz0n/AspXVenom",
      description: "Automates the process of generating encoded shellcode and embedding it into ASPX webshells, providing a smooth workflow for penetration testers during security assessments. The tool is specifically designed for testing ASPX-enabled web servers and .NET environments.",
      features: [
        'Generates encoded shellcode for ASPX webshells',
        'Streamlines testing of .NET environments',
        'Simplified workflow for penetration testers',
        'Designed for ASPX-enabled web servers'
      ],
      liveLink: null
    },
    {
      name: "MacroPhantom",
      repo: "https://github.com/xbz0n/MacroPhantom",
      description: "MacroPhantom automates the process of generating XOR+Caesar encrypted shellcode and embedding it into VBA macros for Microsoft Office documents. The tool streamlines the workflow for security professionals during penetration tests and security assessments, particularly for phishing simulations.",
      features: [
        'Generates XOR+Caesar encrypted shellcode',
        'Creates VBA macros for Microsoft Office documents',
        'Designed for phishing simulations',
        'Streamlines workflow for penetration testers'
      ],
      liveLink: null
    },
    {
      name: "GoPhish Deploy",
      repo: "https://github.com/xbz0n/gophish-deploy",
      description: "Python script to automate the deployment and configuration of the GoPhish phishing framework. The script installs all necessary dependencies, configures SSL certificates, and sets up the environment for a production-ready deployment.",
      features: [
        'Automated dependency installation',
        'SSL certificate configuration',
        'Production-ready environment setup',
        'Security hardening',
        'Easy deployment process'
      ],
      liveLink: null
    },
    {
      name: "AutoMSF",
      repo: "https://github.com/xbz0n/AutoMSF",
      description: "Script to automate the process of generating multiple types of reverse_https payloads using msfvenom and setting up a multi/handler in Metasploit.",
      features: [
        'Generates C#, EXE, VBS, and PS1 payloads',
        'Copies payloads to web server directory',
        'Creates base64-encoded PowerShell commands',
        'Starts multi/handler for incoming connections',
        'Optimized for OSEP challenges and exams'
      ],
      liveLink: null
    }
  ];

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# Security Tools</title>
        <meta name="description" content="Ivan Spiridonov (xbz0n) - Offensive security professional specializing in Red Teaming, Web/Mobile/AD Pentesting, and vulnerability research. Discover pentesting insights, exploit techniques, and security tools." />
        <link rel="canonical" href="https://xbz0n.sh/tools" />
      </Head>
    
      <div className="space-y-8">
        <div className="space-y-4">
          <h1 className="text-3xl font-bold">Tools</h1>
          <p className="text-gray-400">
            Open-source security tools and utilities developed to assist with penetration testing, 
            vulnerability research, and security assessments.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {tools.map((tool, index) => (
            <ToolCard 
              key={index}
              name={tool.name}
              repo={tool.repo}
              description={tool.description}
              features={tool.features}
              liveLink={tool.liveLink}
            />
          ))}
        </div>
      </div>
    </>
  );
} 
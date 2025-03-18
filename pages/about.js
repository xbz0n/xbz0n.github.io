import { FaShieldAlt, FaServer, FaCode, FaHackerNews, FaBug, FaEnvelope, FaGithub, FaTwitter, FaLinkedinIn } from 'react-icons/fa';
import Head from 'next/head';
import CertificationCard from '../components/CertificationCard';

export default function About() {
  const certifications = [
    {
      title: "OffSec Web Expert (OSWE)",
      link: "https://www.credential.net/b24c3444-42f4-4355-b5dc-f4e885ce3f4c",
      icon: FaCode
    },
    {
      title: "OffSec Experienced Penetration Tester (OSEP)",
      link: "https://www.credential.net/b3d9d569-b3c8-43b2-9ddc-7dffc8308194",
      icon: FaServer
    },
    {
      title: "OffSec Certified Professional (OSCP)",
      link: "https://www.credential.net/d07917a9-34b9-46ca-8fe2-7db76681e55c",
      icon: FaHackerNews
    },
    {
      title: "Certified Red Team Operator",
      link: "https://eu.badgr.com/public/assertions/gs2PPSGSQr-jDsOy-l-fcA",
      icon: FaBug
    },
    {
      title: "Certified Red Team Lead",
      link: "https://eu.badgr.com/public/assertions/rWbIBlvXTyuELPHXiDls7g",
      icon: FaShieldAlt
    },
    {
      title: "Certified Red Team Expert",
      link: "https://www.credential.net/495e426e-41c5-48a3-afee-e10f78a737de",
      icon: FaShieldAlt
    },
    {
      title: "Burp Suite Certified Practitioner",
      link: "https://portswigger.net/web-security/e/c/bec525281dd69532",
      icon: FaBug
    }
  ];

  return (
    <>
      <Head>
        <title>xbz0n@sh:~# About Me</title>
        <meta name="description" content="About Ivan Spiridonov - Professional Penetration Tester and Security Researcher" />
      </Head>

      <div className="space-y-12">
        <section className="space-y-6">
          <h1 className="text-4xl font-bold">About Me</h1>
          
          <div className="bg-secondary/30 rounded-lg p-6 border border-gray-700">
            <div className="prose prose-invert max-w-none">
              <p>
                I'm Ivan Spiridonov (xbz0n), a penetration tester and security researcher with a passion for uncovering and exploiting vulnerabilities in web applications, networks, and infrastructure.
              </p>
              <p>
                With extensive experience in offensive security, I specialize in exploit development, security research, and red team operations. My work involves identifying security weaknesses, developing proof-of-concept exploits, and helping organizations strengthen their security posture.
              </p>
              <p>
                Throughout my career, I've earned several professional certifications and discovered multiple vulnerabilities that have been assigned CVEs. I'm constantly expanding my knowledge and skills, staying up-to-date with the latest security trends and attack vectors.
              </p>
              <p>
                When I'm not breaking into systems (ethically, of course), I enjoy sharing my knowledge through blog posts, developing security tools, and contributing to the security community.
              </p>
            </div>
          </div>
        </section>

        <section className="space-y-6">
          <h2 className="text-2xl font-bold">Certifications</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {certifications.map((cert, index) => (
              <CertificationCard 
                key={index}
                title={cert.title}
                link={cert.link}
                icon={cert.icon}
              />
            ))}
          </div>
        </section>

        <section className="space-y-6">
          <h2 className="text-2xl font-bold">Get in Touch</h2>
          <div className="bg-secondary/30 rounded-lg p-6 border border-gray-700">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Contact Information</h3>
                <div className="space-y-3">
                  <a href="mailto:ivanspiridonov@gmail.com" className="flex items-center text-gray-300 hover:text-accent">
                    <FaEnvelope className="w-5 h-5 mr-3" />
                    <span>ivanspiridonov@gmail.com</span>
                  </a>
                </div>
              </div>
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Social Media</h3>
                <div className="space-y-3">
                  <a href="https://github.com/xbz0n" target="_blank" rel="noopener noreferrer" className="flex items-center text-gray-300 hover:text-accent">
                    <FaGithub className="w-5 h-5 mr-3" />
                    <span>GitHub</span>
                  </a>
                  <a href="https://twitter.com/xbz0n" target="_blank" rel="noopener noreferrer" className="flex items-center text-gray-300 hover:text-accent">
                    <FaTwitter className="w-5 h-5 mr-3" />
                    <span>Twitter</span>
                  </a>
                  <a href="https://www.linkedin.com/in/ivanspiridonov/" target="_blank" rel="noopener noreferrer" className="flex items-center text-gray-300 hover:text-accent">
                    <FaLinkedinIn className="w-5 h-5 mr-3" />
                    <span>LinkedIn</span>
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </>
  );
} 
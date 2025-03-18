import { FaShieldAlt, FaServer, FaCode, FaHackerNews, FaBug } from 'react-icons/fa';
import CertificationCard from '../components/CertificationCard';

export default function Certifications() {
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
    <div className="space-y-8">
      <div className="space-y-4">
        <h1 className="text-3xl font-bold">Certifications</h1>
        <p className="text-gray-400">
          Professional certifications demonstrating expertise in offensive security, web application security, 
          and red team operations.
        </p>
      </div>
      
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
    </div>
  );
} 
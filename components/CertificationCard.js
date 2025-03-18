import { FaExternalLinkAlt } from 'react-icons/fa';

export default function CertificationCard({ title, link, icon: Icon }) {
  return (
    <div className="bg-secondary/50 rounded-lg border border-gray-700 p-4 transition-all hover:border-accent/50">
      <div className="flex items-center space-x-3">
        {Icon && <Icon className="text-accent w-6 h-6" />}
        <h3 className="text-lg font-medium">{title}</h3>
      </div>
      
      {link && (
        <a
          href={link}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center mt-4 text-sm text-accent hover:text-accent/80"
        >
          <span>View Credential</span>
          <FaExternalLinkAlt className="ml-1 w-3 h-3" />
        </a>
      )}
    </div>
  );
} 
import { FaExternalLinkAlt } from 'react-icons/fa';

export default function CVECard({ id, link, description }) {
  return (
    <div className="bg-secondary/50 rounded-lg border border-gray-700 p-4 transition-all hover:border-accent/50">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium text-danger">{id}</h3>
        <span className="badge badge-cve">CVE</span>
      </div>
      
      {description && (
        <p className="mt-2 text-sm text-gray-300">{description}</p>
      )}
      
      {link && (
        <a
          href={link}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center mt-4 text-sm text-accent hover:text-accent/80"
        >
          <span>View CVE Details</span>
          <FaExternalLinkAlt className="ml-1 w-3 h-3" />
        </a>
      )}
    </div>
  );
} 
import { FaExternalLinkAlt } from 'react-icons/fa';
import Image from 'next/image';

export default function CertificationCard({ title, link, icon: Icon, imagePath }) {
  return (
    <div className="bg-secondary/50 rounded-lg border border-gray-700 p-4 transition-all hover:border-accent/50">
      <div className="flex items-center space-x-3">
        {imagePath ? (
          <div className="relative w-16 h-16 flex-shrink-0">
            <Image 
              src={imagePath} 
              alt={`${title} icon`} 
              width={64} 
              height={64} 
              className="object-contain"
            />
          </div>
        ) : Icon ? (
          <Icon className="text-accent w-8 h-8" />
        ) : null}
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
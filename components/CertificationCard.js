import { FaExternalLinkAlt } from 'react-icons/fa';
import Image from 'next/image';

export default function CertificationCard({ title, link, icon: Icon, imagePath }) {
  return (
    <div className="bg-gradient-to-br from-secondary/80 to-secondary/30 rounded-lg border border-gray-700/50 p-5 transition-all hover:border-accent/60 hover:shadow-md hover:shadow-accent/10 flex flex-col h-full">
      <div className="flex items-start">
        {/* Left column for icon - fixed width */}
        <div className="w-16 flex-shrink-0 mr-4">
          {imagePath ? (
            <div className="relative w-16 h-16 bg-black/20 rounded-lg p-2 border border-gray-700/30 flex items-center justify-center">
              <Image 
                src={imagePath} 
                alt={`${title} icon`} 
                width={64} 
                height={64} 
                className="object-contain"
              />
            </div>
          ) : Icon ? (
            <div className="w-16 h-16 bg-black/20 rounded-lg flex items-center justify-center border border-gray-700/30">
              <Icon className="text-accent w-8 h-8" />
            </div>
          ) : null}
        </div>
        
        {/* Right column for text - flexible width */}
        <div className="flex-1 flex flex-col min-h-[4rem] justify-center">
          <h3 className="text-lg font-medium text-white/90">{title}</h3>
        </div>
      </div>
      
      <div className="mt-auto pt-4">
      {link && (
        <a
          href={link}
          target="_blank"
          rel="noopener noreferrer"
            className="flex items-center text-sm text-accent/90 hover:text-accent transition-colors group"
        >
          <span>View Credential</span>
            <FaExternalLinkAlt className="ml-1 w-3 h-3 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
        </a>
      )}
      </div>
    </div>
  );
} 
import { FaExternalLinkAlt, FaCheckCircle } from 'react-icons/fa';
import Image from 'next/image';

export default function CertificationCardTerminal({ title, link, icon: Icon, imagePath, issueYear, provider }) {
  // Determine provider color
  const getProviderGlow = (provider) => {
    if (provider === 'OffSec') return 'hover:border-red-500/60 hover:shadow-red-500/20';
    if (provider === 'ZeroPoint') return 'hover:border-blue-500/60 hover:shadow-blue-500/20';
    if (provider === 'PortSwigger') return 'hover:border-orange-500/60 hover:shadow-orange-500/20';
    return 'hover:border-accent/60 hover:shadow-accent/20';
  };

  return (
    <div className={`bg-secondary/50 rounded-lg border border-gray-700 transition-all ${getProviderGlow(provider)} hover:shadow-lg group`}>
      {/* Card content */}
      <div className="p-5 space-y-4">
        {/* Icon and badge */}
        <div className="flex items-start space-x-4">
          {imagePath && (
            <div className="relative w-16 h-16 bg-secondary/30 rounded-lg p-2 border border-gray-700/50 flex items-center justify-center flex-shrink-0">
              <Image
                src={imagePath}
                alt={`${title} icon`}
                width={64}
                height={64}
                className="object-contain"
              />
            </div>
          )}

          <div className="flex-1">
            <div className="inline-block">
              <span className="badge badge-certification text-xs font-mono mb-2">
                [VERIFIED]
              </span>
            </div>
            <h3 className="text-base font-semibold text-white/90 leading-tight">
              {title}
            </h3>
          </div>
        </div>

        {/* Terminal output */}
        <div className="bg-black/40 rounded p-3 border border-gray-700/50 font-mono text-xs space-y-1">
          <div className="text-gray-400">
            <span className="text-accent">$</span> verify-cert --status
          </div>
          <div className="text-green-400 flex items-center space-x-2">
            <span>●</span>
            <span>Status: Active</span>
          </div>
          {issueYear && (
            <div className="text-gray-400">
              Issued: {issueYear}
            </div>
          )}
          {provider && (
            <div className="text-gray-400">
              Provider: {provider}
            </div>
          )}
        </div>

        {/* View credential link */}
        {link && (
          <div className="pt-2">
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center text-xs font-mono text-accent/90 hover:text-accent transition-colors group-hover:translate-x-1 transition-transform"
            >
              <span className="text-gray-500">$</span>
              <span className="ml-1">view-credential --verify</span>
              <FaExternalLinkAlt className="ml-2 w-3 h-3" />
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

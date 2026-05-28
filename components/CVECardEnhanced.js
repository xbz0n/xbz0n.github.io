import { FaExternalLinkAlt, FaBug, FaFileAlt } from 'react-icons/fa';

export default function CVECardEnhanced({ id, link, description, severity, cvss, type, product, year, blogPost }) {
  // Determine severity styling
  const getSeverityStyles = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical':
        return {
          border: 'border-red-500/60',
          glow: 'hover:shadow-red-500/30',
          badge: 'bg-red-500/20 text-red-400 ring-red-500/50',
          bar: 'bg-red-500'
        };
      case 'high':
        return {
          border: 'border-orange-500/60',
          glow: 'hover:shadow-orange-500/30',
          badge: 'bg-orange-500/20 text-orange-400 ring-orange-500/50',
          bar: 'bg-orange-500'
        };
      case 'medium':
        return {
          border: 'border-yellow-500/60',
          glow: 'hover:shadow-yellow-500/30',
          badge: 'bg-yellow-500/20 text-yellow-400 ring-yellow-500/50',
          bar: 'bg-yellow-500'
        };
      default:
        return {
          border: 'border-gray-600/60',
          glow: 'hover:shadow-gray-500/30',
          badge: 'bg-gray-500/20 text-gray-400 ring-gray-500/50',
          bar: 'bg-gray-500'
        };
    }
  };

  const styles = getSeverityStyles(severity);

  return (
    <div className={`bg-secondary/50 rounded-lg border-2 ${styles.border} transition-all ${styles.glow} hover:shadow-lg group`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-700/50">
        <div className="flex items-start justify-between mb-2">
          <div className="flex items-center space-x-2">
            <FaBug className="text-red-500 w-4 h-4" />
            <h3 className="text-lg font-bold font-mono text-white">{id}</h3>
          </div>
          {cvss && (
            <div className="flex items-center space-x-2">
              <span className={`badge ${styles.badge} font-mono text-xs font-bold`}>
                {cvss}/10
              </span>
            </div>
          )}
        </div>

        {/* Severity and Type badges */}
        <div className="flex flex-wrap gap-2 mt-2">
          {severity && (
            <span className={`badge ${styles.badge} text-xs font-mono uppercase`}>
              {severity}
            </span>
          )}
          {type && (
            <span className="badge badge-certification text-xs">
              {type}
            </span>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="p-4 space-y-3">
        {/* Product/Target */}
        {product && (
          <div className="text-xs text-gray-400 font-mono">
            <span className="text-accent">Target:</span> {product}
          </div>
        )}

        {/* Description */}
        {description && (
          <p className="text-sm text-gray-300 leading-relaxed">
            {description}
          </p>
        )}

        {/* CVSS Score Bar */}
        {cvss && (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
              <span>CVSS Score</span>
              <span>{cvss}/10</span>
            </div>
            <div className="w-full bg-gray-700/50 rounded-full h-2 overflow-hidden">
              <div
                className={`h-full ${styles.bar} transition-all duration-300 group-hover:animate-pulse`}
                style={{ width: `${(cvss / 10) * 100}%` }}
              ></div>
            </div>
          </div>
        )}

        {/* Links */}
        <div className="flex flex-wrap gap-2 pt-2">
          {link && (
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center text-xs font-mono text-accent hover:text-accent/80 transition-colors"
            >
              <span>$ view-cve</span>
              <FaExternalLinkAlt className="ml-1 w-3 h-3" />
            </a>
          )}
          {blogPost && (
            <a
              href={blogPost}
              className="inline-flex items-center text-xs font-mono text-blue-400 hover:text-blue-300 transition-colors"
            >
              <FaFileAlt className="mr-1 w-3 h-3" />
              <span>Writeup</span>
            </a>
          )}
        </div>

        {/* Discovery year */}
        {year && (
          <div className="text-xs text-gray-500 font-mono pt-1">
            Discovered: {year}
          </div>
        )}
      </div>
    </div>
  );
}

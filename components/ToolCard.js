import { FaGithub, FaExternalLinkAlt, FaDownload } from 'react-icons/fa';

export default function ToolCard({ name, repo, description, features, previewImage, liveLink }) {
  return (
    <div className="bg-secondary/50 rounded-lg border border-gray-700 p-5 transition-all hover:border-accent/50">
      <div className="flex items-start justify-between">
        <h3 className="text-lg font-medium text-white">{name}</h3>
        <span className="badge badge-tool">Tool</span>
      </div>
      
      {description && (
        <p className="mt-3 text-sm text-gray-300">{description}</p>
      )}
      
      {features && features.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-semibold mb-2">Features:</h4>
          <ul className="list-disc list-inside space-y-1 text-gray-300 text-sm">
            {features.map((feature, idx) => (
              <li key={idx}>{feature}</li>
            ))}
          </ul>
        </div>
      )}
      
      <div className="flex mt-4 space-x-4">
        {repo && (
          <a
            href={repo}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center text-sm text-accent hover:text-accent/80"
          >
            <FaGithub className="mr-1 w-4 h-4" />
            <span>GitHub</span>
          </a>
        )}
        
        {repo && (
          <a
            href={`${repo}/archive/refs/heads/main.zip`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center text-sm text-accent hover:text-accent/80"
          >
            <FaDownload className="mr-1 w-4 h-4" />
            <span>Download</span>
          </a>
        )}
        
        {liveLink && (
          <a
            href={liveLink}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center text-sm text-accent hover:text-accent/80"
          >
            <FaExternalLinkAlt className="mr-1 w-3 h-3" />
            <span>Live Demo</span>
          </a>
        )}
      </div>
    </div>
  );
} 
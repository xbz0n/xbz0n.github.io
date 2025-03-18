import { FaGithub, FaTwitter, FaEnvelope } from 'react-icons/fa';

export default function Footer() {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="bg-primary/90 border-t border-gray-800">
      <div className="container py-6">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="text-sm text-gray-400 mb-4 md:mb-0">
            &copy; {currentYear} Ivan Spiridonov (xbz0n). All rights reserved.
          </div>
          
          <div className="flex items-center space-x-6">
            <a 
              href="https://github.com/xbz0n" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="text-gray-400 hover:text-accent transition-colors"
              aria-label="GitHub"
            >
              <FaGithub className="w-5 h-5" />
            </a>
            <a 
              href="https://twitter.com/xbz0n" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="text-gray-400 hover:text-accent transition-colors"
              aria-label="Twitter"
            >
              <FaTwitter className="w-5 h-5" />
            </a>
            <a 
              href="mailto:contact@example.com" 
              className="text-gray-400 hover:text-accent transition-colors"
              aria-label="Email"
            >
              <FaEnvelope className="w-5 h-5" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
} 
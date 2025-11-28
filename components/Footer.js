import { FaGithub, FaTwitter, FaEnvelope } from 'react-icons/fa';

export default function Footer() {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="bg-primary/90 border-t border-gray-800">
      <div className="container py-6">
        <div className="flex justify-center items-center">
          <div className="text-sm text-gray-400">
            &copy; {currentYear} Ivan Spiridonov (xbz0n). All rights reserved.
          </div>
        </div>
      </div>
    </footer>
  );
} 
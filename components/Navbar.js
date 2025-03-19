import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { FaGithub, FaTwitter, FaBars, FaTimes, FaEnvelope, FaLinkedinIn } from 'react-icons/fa';

export default function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const router = useRouter();
  
  const isActive = (path) => router.pathname === path;
  
  return (
    <nav className="bg-primary/80 backdrop-blur-sm sticky top-0 z-10 shadow-md">
      <div className="container py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <Link href="/">
              <span className="text-xl font-bold tracking-tighter bg-gradient-to-r from-accent to-blue-500 bg-clip-text text-transparent">xbz0n@sh:~#</span>
            </Link>
            
            <div className="hidden md:flex space-x-6">
              <Link href="/" className={isActive('/') ? 'nav-link-active' : 'nav-link'}>
                Home
              </Link>
              <Link href="/about" className={isActive('/about') ? 'nav-link-active' : 'nav-link'}>
                About
              </Link>
              <Link href="/blog" className={isActive('/blog') ? 'nav-link-active' : 'nav-link'}>
                Blog
              </Link>
              <Link href="/tools" className={isActive('/tools') ? 'nav-link-active' : 'nav-link'}>
                Tools
              </Link>
              <Link href="/cves" className={isActive('/cves') ? 'nav-link-active' : 'nav-link'}>
                CVEs
              </Link>
              {/* Certs link temporarily hidden
              <Link href="/certifications" className={isActive('/certifications') ? 'nav-link-active' : 'nav-link'}>
                Certs
              </Link>
              */}
            </div>
          </div>
          
          <div className="hidden md:flex items-center space-x-4">
            <a href="mailto:ivanspiridonov@gmail.com" className="text-gray-300 hover:text-accent" aria-label="Email">
              <FaEnvelope className="w-5 h-5" />
            </a>
            <a href="https://github.com/xbz0n" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-accent" aria-label="GitHub">
              <FaGithub className="w-5 h-5" />
            </a>
            <a href="https://twitter.com/xbz0n" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-accent" aria-label="Twitter">
              <FaTwitter className="w-5 h-5" />
            </a>
            <a href="https://www.linkedin.com/in/ivanspiridonov/" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-accent" aria-label="LinkedIn">
              <FaLinkedinIn className="w-5 h-5" />
            </a>
          </div>
          
          <button 
            className="md:hidden focus:outline-none" 
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-label="Toggle menu"
          >
            {isMenuOpen ? (
              <FaTimes className="h-6 w-6 text-gray-300" />
            ) : (
              <FaBars className="h-6 w-6 text-gray-300" />
            )}
          </button>
        </div>
        
        {isMenuOpen && (
          <div className="md:hidden mt-4 pb-2 space-y-4">
            <Link 
              href="/" 
              className={`block py-2 ${isActive('/') ? 'nav-link-active' : 'nav-link'}`}
              onClick={() => setIsMenuOpen(false)}
            >
              Home
            </Link>
            <Link 
              href="/about" 
              className={`block py-2 ${isActive('/about') ? 'nav-link-active' : 'nav-link'}`}
              onClick={() => setIsMenuOpen(false)}
            >
              About
            </Link>
            <Link 
              href="/blog" 
              className={`block py-2 ${isActive('/blog') ? 'nav-link-active' : 'nav-link'}`}
              onClick={() => setIsMenuOpen(false)}
            >
              Blog
            </Link>
            <Link 
              href="/tools" 
              className={`block py-2 ${isActive('/tools') ? 'nav-link-active' : 'nav-link'}`}
              onClick={() => setIsMenuOpen(false)}
            >
              Tools
            </Link>
            <Link 
              href="/cves" 
              className={`block py-2 ${isActive('/cves') ? 'nav-link-active' : 'nav-link'}`}
              onClick={() => setIsMenuOpen(false)}
            >
              CVEs
            </Link>
            {/* Certs link temporarily hidden
            <Link 
              href="/certifications" 
              className={`block py-2 ${isActive('/certifications') ? 'nav-link-active' : 'nav-link'}`}
              onClick={() => setIsMenuOpen(false)}
            >
              Certs
            </Link>
            */}
            
            <div className="flex justify-evenly items-center pt-4 pb-2 border-t border-gray-700">
              <a href="mailto:ivanspiridonov@gmail.com" className="flex flex-col items-center text-gray-300 hover:text-accent" aria-label="Email">
                <FaEnvelope className="w-6 h-6 mb-1" />
                <span className="text-xs">Email</span>
              </a>
              <a href="https://github.com/xbz0n" target="_blank" rel="noopener noreferrer" className="flex flex-col items-center text-gray-300 hover:text-accent" aria-label="GitHub">
                <FaGithub className="w-6 h-6 mb-1" />
                <span className="text-xs">GitHub</span>
              </a>
              <a href="https://twitter.com/xbz0n" target="_blank" rel="noopener noreferrer" className="flex flex-col items-center text-gray-300 hover:text-accent" aria-label="Twitter">
                <FaTwitter className="w-6 h-6 mb-1" />
                <span className="text-xs">Twitter</span>
              </a>
              <a href="https://www.linkedin.com/in/ivanspiridonov/" target="_blank" rel="noopener noreferrer" className="flex flex-col items-center text-gray-300 hover:text-accent" aria-label="LinkedIn">
                <FaLinkedinIn className="w-6 h-6 mb-1" />
                <span className="text-xs">LinkedIn</span>
              </a>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
} 
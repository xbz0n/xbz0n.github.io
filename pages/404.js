import Link from 'next/link';
import Head from 'next/head';
import { useState, useEffect } from 'react';

export default function Custom404() {
  const [glitchText, setGlitchText] = useState('404');
  const [terminalText, setTerminalText] = useState('');
  const fullCommand = '$ cat /dev/null > page_not_found.txt';

  useEffect(() => {
    // Glitch effect for 404
    const glitchInterval = setInterval(() => {
      const glitchChars = ['4', '0', '4', '#', '@', '$', '!', '404'];
      const randomGlitch = glitchChars[Math.floor(Math.random() * glitchChars.length)];
      setGlitchText(randomGlitch);

      setTimeout(() => setGlitchText('404'), 100);
    }, 3000);

    // Typewriter effect for terminal command
    let currentIndex = 0;
    const typeInterval = setInterval(() => {
      if (currentIndex <= fullCommand.length) {
        setTerminalText(fullCommand.slice(0, currentIndex));
        currentIndex++;
      } else {
        clearInterval(typeInterval);
      }
    }, 50);

    return () => {
      clearInterval(glitchInterval);
      clearInterval(typeInterval);
    };
  }, []);

  return (
    <>
      <Head>
        <title>404 - Access Denied | xbz0n@sh</title>
        <meta name="description" content="404 - The requested resource could not be found" />
        <meta name="robots" content="noindex" />
      </Head>

      <div className="min-h-[70vh] flex items-center justify-center">
        <div className="text-center space-y-8 max-w-2xl mx-auto px-4">
          {/* Glitchy 404 */}
          <div className="relative">
            <h1
              className="text-9xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-accent to-red-500 animate-pulse"
              style={{
                textShadow: '0 0 30px rgba(239, 68, 68, 0.5), 0 0 60px rgba(239, 68, 68, 0.3)',
                fontFamily: 'JetBrains Mono, monospace'
              }}
            >
              {glitchText}
            </h1>
            <div className="absolute inset-0 text-9xl font-bold text-red-500 opacity-20 blur-sm animate-pulse">
              404
            </div>
          </div>

          {/* Terminal-style error message */}
          <div className="terminal p-6 text-left">
            <div className="flex items-center space-x-2 mb-4">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="text-gray-400 text-sm ml-2">xbz0n@sh: ~</span>
            </div>

            <div className="font-mono text-sm space-y-2">
              <div className="text-accent">
                {terminalText}
                <span className="animate-pulse">|</span>
              </div>
              <div className="text-red-400 mt-4">
                [!] ERROR: Page Not Found
              </div>
              <div className="text-gray-400 mt-2">
                <span className="text-yellow-400">warning:</span> The requested endpoint does not exist in this reality
              </div>
              <div className="text-gray-500 mt-2 text-xs">
                → Possible causes:
              </div>
              <div className="text-gray-500 ml-4 text-xs space-y-1">
                <div>  • URL typo detected</div>
                <div>  • Resource moved or deleted</div>
                <div>  • You stumbled into the void</div>
                <div>  • The matrix glitched</div>
              </div>
            </div>
          </div>

          {/* 1337 speak message */}
          <div className="space-y-4">
            <p className="text-xl text-gray-300 font-mono">
              <span className="text-red-400">[</span>
              <span className="text-accent">ACCESS_DENIED</span>
              <span className="text-red-400">]</span>
            </p>
            <p className="text-gray-400">
              7h3 p493 y0u'r3 l00k1n9 f0r d035n'7 3x157
            </p>
            <p className="text-sm text-gray-500">
              (The page you're looking for doesn't exist)
            </p>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-6">
            <Link href="/" className="btn btn-primary group">
              <span className="group-hover:hidden">← Return Home</span>
              <span className="hidden group-hover:inline">← 3x17 t0 h0m3</span>
            </Link>
            <Link href="/blog" className="btn btn-outline group">
              <span className="group-hover:hidden">Read Blog</span>
              <span className="hidden group-hover:inline">r34d bl09</span>
            </Link>
          </div>

          {/* Easter egg - Matrix-style falling characters */}
          <div className="text-xs text-gray-600 font-mono opacity-50 mt-8">
            <div className="overflow-hidden whitespace-nowrap">
              01001000 01000001 01000011 01001011 00100000 01010100 01001000 01000101 00100000 01010000 01001100 01000001 01001110 01000101 01010100
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes glitch {
          0%, 100% { transform: translate(0); }
          20% { transform: translate(-2px, 2px); }
          40% { transform: translate(-2px, -2px); }
          60% { transform: translate(2px, 2px); }
          80% { transform: translate(2px, -2px); }
        }

        h1 {
          animation: glitch 0.3s infinite;
        }
      `}</style>
    </>
  );
}

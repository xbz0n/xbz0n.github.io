import Link from 'next/link';
import Head from 'next/head';
import { useState, useEffect } from 'react';

export default function Custom500() {
  const [glitchText, setGlitchText] = useState('500');
  const [terminalLines, setTerminalLines] = useState([]);
  const errorMessages = [
    'ERROR: Segmentation fault (core dumped)',
    'FATAL: Kernel panic - not syncing',
    'CRITICAL: System process terminated unexpectedly',
    'WARNING: Memory corruption detected',
    'ERROR: Unable to recover from internal server error'
  ];

  useEffect(() => {
    // Glitch effect for 500
    const glitchInterval = setInterval(() => {
      const glitchChars = ['5', '0', '0', '5##', '@!0', '$00', '5ERR', '500'];
      const randomGlitch = glitchChars[Math.floor(Math.random() * glitchChars.length)];
      setGlitchText(randomGlitch);

      setTimeout(() => setGlitchText('500'), 150);
    }, 4000);

    // Terminal error cascade effect
    let currentLine = 0;
    const terminalInterval = setInterval(() => {
      if (currentLine < errorMessages.length) {
        setTerminalLines(prev => [...prev, errorMessages[currentLine]]);
        currentLine++;
      } else {
        clearInterval(terminalInterval);
      }
    }, 300);

    return () => {
      clearInterval(glitchInterval);
      clearInterval(terminalInterval);
    };
  }, []);

  return (
    <>
      <Head>
        <title>500 - Internal Server Error | xbz0n@sh</title>
        <meta name="description" content="500 - Internal server error occurred" />
        <meta name="robots" content="noindex" />
      </Head>

      <div className="min-h-[70vh] flex items-center justify-center">
        <div className="text-center space-y-8 max-w-2xl mx-auto px-4">
          {/* Glitchy 500 */}
          <div className="relative">
            <h1
              className="text-9xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-red-600 via-orange-500 to-red-600 animate-pulse"
              style={{
                textShadow: '0 0 40px rgba(220, 38, 38, 0.6), 0 0 80px rgba(220, 38, 38, 0.4)',
                fontFamily: 'JetBrains Mono, monospace'
              }}
            >
              {glitchText}
            </h1>
            <div className="absolute inset-0 text-9xl font-bold text-red-600 opacity-20 blur-md animate-pulse">
              500
            </div>
          </div>

          {/* Terminal-style error cascade */}
          <div className="terminal p-6 text-left bg-black/50">
            <div className="flex items-center space-x-2 mb-4">
              <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>
              <div className="w-3 h-3 rounded-full bg-red-400"></div>
              <div className="w-3 h-3 rounded-full bg-red-300"></div>
              <span className="text-red-400 text-sm ml-2">system@crashed: ~</span>
            </div>

            <div className="font-mono text-sm space-y-2 max-h-48 overflow-hidden">
              {terminalLines.map((line, index) => (
                <div
                  key={index}
                  className={`text-red-400 ${index === terminalLines.length - 1 ? 'animate-pulse' : ''}`}
                >
                  [!] {line}
                </div>
              ))}
              {terminalLines.length === errorMessages.length && (
                <div className="text-orange-400 mt-4 animate-pulse">
                  → System attempting recovery...
                </div>
              )}
            </div>

            <div className="mt-6 pt-4 border-t border-red-500/30">
              <div className="text-gray-400 text-xs space-y-1">
                <div><span className="text-red-400">Exception:</span> InternalServerError</div>
                <div><span className="text-red-400">Stack Trace:</span> 0x7fff5fc3d000</div>
                <div><span className="text-red-400">Timestamp:</span> {new Date().toISOString()}</div>
              </div>
            </div>
          </div>

          {/* 1337 speak message */}
          <div className="space-y-4">
            <p className="text-xl text-gray-300 font-mono">
              <span className="text-red-500">[</span>
              <span className="text-orange-500">SYSTEM_FAILURE</span>
              <span className="text-red-500">]</span>
            </p>
            <p className="text-gray-400">
              50m37h1n9 w3n7 73rr1bly wr0n9 0n 0ur 51d3
            </p>
            <p className="text-sm text-gray-500">
              (Something went terribly wrong on our side)
            </p>
          </div>

          {/* Error explanation */}
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-left">
            <div className="flex items-start space-x-3">
              <div className="text-red-500 text-2xl mt-1">⚠</div>
              <div className="text-sm text-gray-300 space-y-2">
                <p className="font-semibold text-red-400">Internal Server Error</p>
                <p>The server encountered an unexpected condition that prevented it from fulfilling the request.</p>
                <p className="text-gray-400 text-xs">This is not your fault. Our systems are automatically notified and we're working on a fix.</p>
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-6">
            <Link href="/" className="btn btn-primary group">
              <span className="group-hover:hidden">← Go Home</span>
              <span className="hidden group-hover:inline">← r3570r3 5y573m</span>
            </Link>
            <button
              onClick={() => window.location.reload()}
              className="btn btn-outline group"
            >
              <span className="group-hover:hidden">Try Again</span>
              <span className="hidden group-hover:inline">r3b007 5y573m</span>
            </button>
          </div>

          {/* System status indicator */}
          <div className="flex items-center justify-center space-x-2 text-xs text-gray-600 font-mono">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
            <span>SYSTEM STATUS: DEGRADED</span>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes flicker {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.8; }
        }

        h1 {
          animation: flicker 2s infinite;
        }

        @keyframes scan {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100%); }
        }

        .terminal::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 2px;
          background: linear-gradient(to right, transparent, rgba(239, 68, 68, 0.5), transparent);
          animation: scan 3s infinite;
        }
      `}</style>
    </>
  );
}

import { useState, useEffect } from 'react';
import { FaChevronRight } from 'react-icons/fa';

export default function TerminalHero() {
  const [displayText, setDisplayText] = useState('');
  const [currentLine, setCurrentLine] = useState(0);
  const [cursorVisible, setCursorVisible] = useState(true);
  
  const lines = [
    'Hello, I am Ivan Spiridonov (xbz0n)',
    'Penetration Tester & Security Researcher',
    'Uncovering critical security flaws that conventional testing misses',
    'Specialties: Red Teaming, Web/Mobile/AD Pentesting',
    'Responsible for multiple CVE discoveries',
    'Type "help" for available commands...'
  ];
  
  useEffect(() => {
    const interval = setInterval(() => {
      setCursorVisible(prev => !prev);
    }, 500);
    
    return () => clearInterval(interval);
  }, []);
  
  useEffect(() => {
    if (currentLine >= lines.length) return;
    
    let currentText = '';
    let index = 0;
    
    const typingInterval = setInterval(() => {
      if (index >= lines[currentLine].length) {
        clearInterval(typingInterval);
        setTimeout(() => {
          setCurrentLine(prev => prev + 1);
        }, 500);
        return;
      }
      
      currentText += lines[currentLine][index];
      setDisplayText(prev => {
        const prevLines = prev.split('\n');
        prevLines[currentLine] = currentText;
        return prevLines.join('\n');
      });
      
      index++;
    }, 30);
    
    return () => clearInterval(typingInterval);
  }, [currentLine]);
  
  return (
    <div className="terminal font-mono text-green-400 leading-relaxed">
      <div className="flex items-center space-x-2 text-xs text-gray-400 mb-2">
        <div className="w-3 h-3 rounded-full bg-red-500"></div>
        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
        <div className="w-3 h-3 rounded-full bg-green-500"></div>
        <span>terminal — xbz0n@sh:~#</span>
      </div>
      
      <div className="whitespace-pre-wrap">
        {displayText.split('\n').map((line, i) => (
          <div key={i} className="flex">
            <span className="text-accent mr-2">
              <FaChevronRight />
            </span>
            <span>{line}</span>
          </div>
        ))}
        
        {currentLine >= lines.length && (
          <div className="flex mt-2">
            <span className="text-accent mr-2">xbz0n@sh:~#</span>
            <span className={`${cursorVisible ? 'opacity-100' : 'opacity-0'}`}>|</span>
          </div>
        )}
      </div>
    </div>
  );
} 
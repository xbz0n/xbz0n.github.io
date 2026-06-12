import { useState, useEffect } from 'react';

export default function TableOfContents({ headings }) {
  const [open, setOpen] = useState(true);
  const [activeId, setActiveId] = useState(null);

  useEffect(() => {
    if (!headings || headings.length === 0) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter(e => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActiveId(visible[0].target.id);
      },
      { rootMargin: '-80px 0px -70% 0px' }
    );
    headings.forEach(h => {
      const el = document.getElementById(h.id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [headings]);

  if (!headings || headings.length < 4) return null;

  return (
    <nav
      aria-label="Table of contents"
      className="bg-secondary/30 rounded-lg border border-gray-700 mb-8 overflow-hidden"
    >
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-secondary/50 transition-colors"
        aria-expanded={open}
      >
        <span className="font-mono text-sm text-accent">
          <span className="text-gray-500">$</span> cat table-of-contents
        </span>
        <span className="text-gray-500 text-xs">{open ? '[−]' : '[+]'}</span>
      </button>
      {open && (
        <ul className="px-4 pb-4 space-y-1 text-sm">
          {headings.map(h => (
            <li key={h.id} className={h.level === 3 ? 'pl-4' : ''}>
              <a
                href={`#${h.id}`}
                className={`block py-1 hover:text-accent transition-colors ${
                  activeId === h.id ? 'text-accent' : 'text-gray-400'
                }`}
              >
                {h.text}
              </a>
            </li>
          ))}
        </ul>
      )}
    </nav>
  );
}

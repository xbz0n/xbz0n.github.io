import { useEffect, useRef, useState } from 'react';
import { FaSearch } from 'react-icons/fa';

export default function SearchModal() {
  const [open, setOpen] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const containerRef = useRef(null);
  const initRef = useRef(false);

  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(o => !o);
      } else if (e.key === 'Escape' && open) {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open]);

  useEffect(() => {
    if (!open || !containerRef.current || initRef.current) return;

    const ensureCss = () => {
      if (!document.querySelector('link[data-pagefind-ui-css]')) {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = '/pagefind/pagefind-ui.css';
        link.setAttribute('data-pagefind-ui-css', '');
        document.head.appendChild(link);
      }
    };

    const init = () => {
      if (initRef.current || !containerRef.current || !window.PagefindUI) return;
      initRef.current = true;
      try {
        new window.PagefindUI({
          element: containerRef.current,
          showSubResults: true,
          resetStyles: false,
          showImages: false,
        });
        setLoaded(true);
        setTimeout(() => {
          const input = containerRef.current?.querySelector('input[type="text"]');
          if (input) input.focus();
        }, 50);
      } catch (err) {
        console.error('[search] PagefindUI init failed:', err);
      }
    };

    ensureCss();

    if (window.PagefindUI) {
      init();
    } else {
      let script = document.querySelector('script[data-pagefind-ui]');
      if (!script) {
        script = document.createElement('script');
        script.src = '/pagefind/pagefind-ui.js';
        script.setAttribute('data-pagefind-ui', '');
        script.onload = init;
        script.onerror = () => console.error('[search] pagefind-ui.js failed to load — run `npm run build` first');
        document.head.appendChild(script);
      } else {
        script.addEventListener('load', init, { once: true });
      }
    }
  }, [open]);

  useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => { document.body.style.overflow = ''; };
  }, [open]);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        aria-label="Search (Cmd+K)"
        title="Search (⌘K)"
        className="text-gray-300 hover:text-accent flex items-center"
      >
        <FaSearch className="w-4 h-4" />
        <span className="hidden lg:inline ml-2 text-xs font-mono text-gray-500 border border-gray-700 rounded px-1.5 py-0.5">⌘K</span>
      </button>

      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Site search"
          className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/80"
          onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
        >
          <div className="bg-secondary border border-gray-700 rounded-lg w-full max-w-2xl max-h-[75vh] overflow-y-auto shadow-2xl">
            <div className="flex justify-between items-center px-4 py-2 border-b border-gray-800 text-xs text-gray-500 font-mono">
              <span><span className="text-accent">$</span> grep -r ./blog/</span>
              <button
                onClick={() => setOpen(false)}
                className="hover:text-accent border border-gray-700 rounded px-1.5 py-0.5"
                aria-label="Close search"
              >
                esc
              </button>
            </div>
            <div className="p-4">
              <div ref={containerRef} className="pagefind-search" />
              {!loaded && (
                <div className="text-sm text-gray-500 font-mono py-6 text-center">
                  loading search index…
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

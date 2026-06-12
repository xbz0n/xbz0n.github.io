import { useEffect, useState } from 'react';

export default function ReadingProgress() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    let rafId = null;

    const compute = () => {
      const article = document.querySelector('.blog-content');
      if (!article) {
        setProgress(0);
        return;
      }
      const rect = article.getBoundingClientRect();
      const articleTop = window.scrollY + rect.top;
      const articleHeight = article.offsetHeight;
      const winHeight = window.innerHeight;
      const scrollTop = window.scrollY;

      const startScroll = articleTop - winHeight * 0.3;
      const endScroll = articleTop + articleHeight - winHeight;
      const range = Math.max(1, endScroll - startScroll);
      const pct = Math.max(0, Math.min(100, ((scrollTop - startScroll) / range) * 100));
      setProgress(pct);
    };

    const handler = () => {
      if (rafId != null) return;
      rafId = window.requestAnimationFrame(() => {
        compute();
        rafId = null;
      });
    };

    window.addEventListener('scroll', handler, { passive: true });
    window.addEventListener('resize', handler);
    compute();

    return () => {
      window.removeEventListener('scroll', handler);
      window.removeEventListener('resize', handler);
      if (rafId != null) window.cancelAnimationFrame(rafId);
    };
  }, []);

  return (
    <div
      className="fixed top-0 left-0 right-0 z-40 h-0.5 bg-transparent pointer-events-none"
      role="progressbar"
      aria-label="Reading progress"
      aria-valuenow={Math.round(progress)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full bg-accent transition-[width] duration-75 ease-out"
        style={{ width: `${progress}%` }}
      />
    </div>
  );
}

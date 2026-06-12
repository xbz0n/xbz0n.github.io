// Forwards Core Web Vitals (CLS, FID, FCP, LCP, TTFB, INP) to Google Analytics
// so they end up in GA + Google's CrUX dataset used for ranking.
// Called automatically by Next.js via the `reportWebVitals` export in _app.js.

export function sendToGA(metric) {
  if (typeof window === 'undefined' || typeof window.gtag !== 'function') return;
  const value = Math.round(metric.name === 'CLS' ? metric.value * 1000 : metric.value);
  window.gtag('event', metric.name, {
    event_category: 'Web Vitals',
    value,
    event_label: metric.id,
    metric_id: metric.id,
    metric_value: metric.value,
    metric_delta: metric.delta,
    metric_rating: metric.rating,
    non_interaction: true,
  });
}

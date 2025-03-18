import Link from 'next/link';
import { format } from 'date-fns';

export default function BlogPostCard({ title, excerpt, date, slug }) {
  return (
    <div className="bg-secondary/50 rounded-lg border border-gray-700 p-5 transition-all hover:border-accent/50">
      <div className="flex flex-col space-y-2">
        <span className="text-xs text-gray-400">
          {format(new Date(date), 'MMMM d, yyyy')}
        </span>
        <Link href={`/blog/${slug}`} className="inline-block">
          <h3 className="text-xl font-medium hover:text-accent">{title}</h3>
        </Link>
        <p className="text-gray-300 text-sm line-clamp-3">{excerpt}</p>
        <Link href={`/blog/${slug}`} className="text-accent hover:text-accent/80 text-sm mt-2">
          Read more →
        </Link>
      </div>
    </div>
  );
} 
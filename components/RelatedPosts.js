import Link from 'next/link';
import { format } from 'date-fns';

export default function RelatedPosts({ posts }) {
  if (!posts || posts.length === 0) return null;

  return (
    <section className="mt-12 pt-8 border-t border-gray-700">
      <h2 className="text-xl font-bold mb-6 font-mono">
        <span className="text-gray-500">$</span> ls related/
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {posts.map(post => (
          <Link
            key={post.slug}
            href={`/blog/${post.slug}`}
            className="block bg-secondary/30 rounded-lg p-4 border border-gray-700 hover:border-accent/60 transition-colors group"
          >
            <h3 className="text-sm font-semibold text-gray-200 group-hover:text-accent mb-2 line-clamp-3">
              {post.title}
            </h3>
            <div className="text-xs text-gray-500 font-mono">
              {format(new Date(post.date), 'MMM d, yyyy')}
            </div>
            {post.sharedTags && post.sharedTags.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {post.sharedTags.slice(0, 3).map(tag => (
                  <span key={tag} className="text-[10px] text-accent/80 font-mono">
                    #{tag.toLowerCase().replace(/\s+/g, '-')}
                  </span>
                ))}
              </div>
            )}
          </Link>
        ))}
      </div>
    </section>
  );
}

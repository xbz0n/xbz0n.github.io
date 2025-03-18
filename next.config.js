/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  images: {
    unoptimized: true,
  },
  basePath: process.env.NODE_ENV === 'production' ? '/xbz0n-web' : '',
  assetPrefix: process.env.NODE_ENV === 'production' ? '/xbz0n-web/' : '',
};

module.exports = nextConfig; 
import Head from 'next/head';
import Navbar from './Navbar';
import Footer from './Footer';

export default function Layout({ children, title = 'xbz0n@sh:~# Command Line to Front Line' }) {
  return (
    <>
      <Head>
        <title>{title}</title>
        <meta name="description" content="Personal website of Ivan Spiridonov (xbz0n) - Professional Penetration Tester and Security Researcher" />
        <link rel="icon" href="/favicon.ico" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />
      </Head>
      
      <div className="flex flex-col min-h-screen">
        <Navbar />
        <main className="flex-grow container py-8">{children}</main>
        <Footer />
      </div>
    </>
  );
} 
import { Html, Head, Main, NextScript } from 'next/document';

export default function Document() {
  return (
    <Html lang="en">
      <Head>
        <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" />
        <meta name="author" content="Ivan Spiridonov" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
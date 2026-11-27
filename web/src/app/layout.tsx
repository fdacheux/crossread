import type { Metadata } from 'next';
import { headers } from 'next/headers';
import { Bricolage_Grotesque, IBM_Plex_Mono, Public_Sans } from 'next/font/google';
import './globals.css';

const bricolage = Bricolage_Grotesque({
  subsets: ['latin'],
  weight: ['600', '700'],
  variable: '--font-bricolage',
});

const publicSans = Public_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-public-sans',
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-ibm-plex-mono',
});

export const metadata: Metadata = {
  title: 'CrossRead — Bilingual Cybersecurity Briefing Desk',
  description:
    'Unified English briefings synthesized from English and French cybersecurity sources using CVE-first clustering and structured fact sheets.',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Reading the per-request nonce header opts HTML responses into dynamic CSP nonce binding
  const nonce = (await headers()).get('x-nonce') ?? undefined;

  return (
    <html
      lang="en"
      data-csp-nonce={nonce ? 'enabled' : undefined}
      className={`${bricolage.variable} ${publicSans.variable} ${ibmPlexMono.variable}`}
    >
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased">{children}</body>
    </html>
  );
}

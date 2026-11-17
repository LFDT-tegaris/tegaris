import type { Metadata } from 'next';

import { Providers } from '../components/providers';

import './globals.css';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Tegaris | Application Privacy',
  description:
    'Manage application privacy, access policies and governed contract operations with Tegaris.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <Providers processEventsEnabled={process.env.OPENPC_UI_TEST_OVERLAY === '1'}>
          {children}
        </Providers>
      </body>
    </html>
  );
}

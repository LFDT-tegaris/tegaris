import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  // Match the bounded build's two-CPU budget during page data generation.
  experimental: {
    cpus: process.env.OPENPC_BUILD_PROFILE === 'retained-qa-serial' ? 1 : 2,
    // The BFF reuses NodeNext service contracts, whose source imports name the
    // emitted .js paths. Resolve their TypeScript sources without duplicating
    // schemas or rewriting the service's production module convention.
    extensionAlias: { '.js': ['.ts', '.tsx', '.js'] },
  },
  transpilePackages: ['@openpc/ui-shell', '@openpc/ui-extensions'],
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
        ],
      },
    ];
  },
};

export default nextConfig;

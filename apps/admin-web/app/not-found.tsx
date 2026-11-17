import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="mx-auto max-w-3xl p-8" id="main-content" tabIndex={-1}>
      <h1 className="text-2xl font-semibold">Page not available</h1>
      <p className="mt-3 text-[color:var(--muted)]">
        This route is not part of the registered workbench.
      </p>
      <Link className="mt-5 inline-block underline" href="/home">
        Return to Home
      </Link>
    </main>
  );
}

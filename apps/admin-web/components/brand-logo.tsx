import Image from 'next/image';

export function BrandLogo({ light = false }: { readonly light?: boolean }) {
  return (
    <Image
      className="tegaris-logo"
      src={`/brand/tegaris-logo-${light ? 'light' : 'primary'}.svg`}
      alt="Tegaris"
      width={256}
      height={56}
      unoptimized
      priority
    />
  );
}

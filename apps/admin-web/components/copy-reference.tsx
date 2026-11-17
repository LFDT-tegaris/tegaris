'use client';

import { useLayoutEffect, useRef, useState } from 'react';
import { Check, Copy, LoaderCircle } from 'lucide-react';

type ReferenceProps = { label: string; value: string };

export function CopyReference(props: ReferenceProps) {
  return <ReferenceValue key={`${props.label}:${props.value}`} {...props} />;
}

function ReferenceValue({ label, value }: ReferenceProps) {
  const [status, setStatus] = useState<'idle' | 'copying' | 'copied' | 'failed'>('idle');
  const mounted = useRef(false);
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  async function copy() {
    setStatus('copying');
    try {
      await navigator.clipboard.writeText(value);
      if (mounted.current) setStatus('copied');
    } catch {
      if (mounted.current) setStatus('failed');
    }
  }
  const Icon = status === 'copied' ? Check : status === 'copying' ? LoaderCircle : Copy;
  return (
    <span className="copy-reference">
      <code className="copy-reference-value">{value}</code>
      <button
        type="button"
        className="copy-reference-button"
        aria-label={`Copy ${label}`}
        disabled={status === 'copying'}
        onClick={() => void copy()}
      >
        <Icon
          size={15}
          aria-hidden
          className={status === 'copying' ? 'animate-spin motion-reduce:animate-none' : undefined}
        />
        {status === 'copied' ? 'Copied' : status === 'copying' ? 'Copying…' : 'Copy'}
      </button>
      <span className="copy-reference-feedback" role="status" data-failed={status === 'failed'}>
        {status === 'copied'
          ? `${label} copied.`
          : status === 'failed'
            ? 'Could not copy. Select and copy the reference.'
            : ''}
      </span>
    </span>
  );
}

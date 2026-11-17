import { Button, type ButtonProps } from 'react-aria-components';

import styles from './accessible-button.module.css';

export type AccessibleButtonProps = ButtonProps;

/** A generic accessible button primitive; product semantics stay outside I01. */
export function AccessibleButton({ className, ...props }: AccessibleButtonProps) {
  return <Button {...props} className={className ?? styles.button} />;
}

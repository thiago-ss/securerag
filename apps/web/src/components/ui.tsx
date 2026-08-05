import { useId, useRef, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react';

/**
 * Accessible UI primitives: every interactive control has a label, every
 * status region uses aria-live, loading/empty/error states carry roles.
 * No unsafe HTML anywhere in the console (answers are rendered as text).
 */

export function Loading({ label = 'Loading' }: { label?: string }): ReactNode {
  return (
    <p role="status" className="status-text" data-testid="loading">
      {label}…
    </p>
  );
}

export function EmptyState({ children }: { children: ReactNode }): ReactNode {
  return (
    <p role="status" className="empty-state" data-testid="empty-state">
      {children}
    </p>
  );
}

export function ErrorNotice({ message }: { message: string }): ReactNode {
  return (
    <div role="alert" className="notice error" data-testid="error-notice">
      {message}
    </div>
  );
}

export function SuccessNotice({ children }: { children: ReactNode }): ReactNode {
  return (
    <div role="status" className="notice success" data-testid="success-notice">
      {children}
    </div>
  );
}

export function TextField({
  label,
  hint,
  ...inputProps
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }): ReactNode {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <input id={id} {...inputProps} />
      {hint !== undefined ? <p className="field-hint">{hint}</p> : null}
    </div>
  );
}

export function TextAreaField({
  label,
  hint,
  ...textareaProps
}: TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; hint?: string }): ReactNode {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <textarea id={id} {...textareaProps} />
      {hint !== undefined ? <p className="field-hint">{hint}</p> : null}
    </div>
  );
}

export function SelectField({
  label,
  children,
  ...selectProps
}: SelectHTMLAttributes<HTMLSelectElement> & { label: string; children: ReactNode }): ReactNode {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <select id={id} {...selectProps}>
        {children}
      </select>
    </div>
  );
}

/** Focus a heading on mount (route-change focus management). */
export function FocusHeading({
  level = 1,
  children,
}: {
  level?: 1 | 2;
  children: ReactNode;
}): ReactNode {
  const ref = useRef<HTMLHeadingElement>(null);
  useFocusOnMount(ref);
  const cls = 'page-heading';
  if (level === 1) {
    return (
      <h1 ref={ref} tabIndex={-1} className={cls}>
        {children}
      </h1>
    );
  }
  return (
    <h2 ref={ref} tabIndex={-1} className={`${cls} page-heading-2`}>
      {children}
    </h2>
  );
}

export function useFocusOnMount<T extends HTMLElement>(ref: React.RefObject<T | null>): void {
  const ran = useRef(false);
  if (!ran.current) {
    ref.current?.focus();
    ran.current = true;
  }
}

export function PageSection({ title, children }: { title: string; children: ReactNode }): ReactNode {
  return (
    <section className="page-section" aria-label={title}>
      <h2 className="section-title">{title}</h2>
      {children}
    </section>
  );
}

/** Stable error codes for programmatic handling; never rely on message text. */
export const ERROR_CODES = {
  securityContext: 'SECURITY_CONTEXT_ERROR',
  membership: 'MEMBERSHIP_ERROR',
} as const;

/**
 * The transaction-local security context is missing or malformed. Thrown when
 * verifyContext finds an unset or invalid GUC, or when a context write fails.
 * Safe to surface to callers: it never contains tenant data.
 */
export class SecurityContextError extends Error {
  readonly code = ERROR_CODES.securityContext;

  constructor(message: string) {
    super(message);
    this.name = 'SecurityContextError';
  }
}

/**
 * No active membership exists for the requested tenant and authenticated
 * principal. Foreign, nonexistent, and deactivated tenants are deliberately
 * indistinguishable: the message is static and carries no identifiers, so it
 * cannot be used to enumerate tenants (default deny, CONTEXT.md).
 */
export class MembershipError extends Error {
  readonly code = ERROR_CODES.membership;

  constructor() {
    super('No active membership for the requested tenant');
    this.name = 'MembershipError';
  }
}

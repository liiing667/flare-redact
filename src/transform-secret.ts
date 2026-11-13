/**
 * Single fail-closed gate for every keyed transform (hash, pseudonym,
 * surrogate, including the deprecated fpe alias). A missing or blank key would
 * make the output a public, dictionary-reversible fingerprint, so every entry
 * point — library, vault, stream, gateway and CLI — refuses the same way.
 */

export const KEYED_MODES = ['hash', 'pseudonym', 'surrogate', 'fpe'] as const;

export type KeyedMode = (typeof KEYED_MODES)[number];

export const TRANSFORM_SECRET_MESSAGE =
  'A non-empty transformSecret is required for hash, pseudonym and surrogate modes.';

export class TransformSecretError extends Error {
  readonly code = 'ERR_TRANSFORM_SECRET';

  constructor(message: string = TRANSFORM_SECRET_MESSAGE) {
    super(message);
    this.name = 'TransformSecretError';
  }
}

export function isKeyedMode(mode: string | undefined): mode is KeyedMode {
  return mode !== undefined && (KEYED_MODES as readonly string[]).includes(mode);
}

/**
 * Validate the options of a keyed mode. `hashSalt` is the deprecated alias of
 * `transformSecret`; an empty value counts as missing.
 */
export function requireTransformSecret(opts: {
  mode?: string;
  transformSecret?: string;
  hashSalt?: string;
}): string {
  const secret = opts.transformSecret ?? opts.hashSalt ?? '';
  if (isKeyedMode(opts.mode) && !secret) {
    throw new TransformSecretError();
  }
  return secret;
}

/** Guard for the standalone keyed primitives, which take the key directly. */
export function assertTransformSecret(secret: string): void {
  if (!secret) throw new TransformSecretError();
}

/**
 * Its own module so that `witness-router.ts` can catch it without importing a
 * value from `witness.ts`, which imports the router back. The remaining cycle
 * is type-only, and erases.
 */
export class WitnessError extends Error {}

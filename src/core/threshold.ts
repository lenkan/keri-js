export type Threshold = string | string[];

export interface WeightedThreshold {
  weights: number[];
  required: number;
}

function greatestCommonDivisor(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);

  while (y !== 0) {
    const remainder = x % y;
    x = y;
    y = remainder;
  }

  return x;
}

function findLeastCommonDenominator(denominators: number[]): number {
  if (denominators.length === 0) {
    throw new Error("At least one denominator is required");
  }

  return denominators.reduce((lcm, value) => {
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`Invalid denominator: ${value}`);
    }

    return (lcm * value) / greatestCommonDivisor(lcm, value);
  }, 1);
}

function parsePositiveInteger(value: string, errorMessage: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error(errorMessage);
  }

  const parsed = Number.parseInt(value, 10);
  if (parsed <= 0) {
    throw new Error(errorMessage);
  }

  return parsed;
}

function parseFraction(fraction: string): [number, number] {
  const parts = fraction.split("/", 2);

  if (parts.length !== 2) {
    throw new Error(`Invalid threshold: ${fraction}`);
  }

  const numerator = parsePositiveInteger(parts[0], `Invalid threshold: ${fraction}`);
  const denominator = parsePositiveInteger(parts[1], `Invalid threshold: ${fraction}`);
  return [numerator, denominator] as const;
}

export function parseThreshold(threshold: Threshold, numKeys: number): WeightedThreshold {
  if (typeof threshold === "string") {
    const required = parsePositiveInteger(threshold, `Invalid threshold: ${threshold}`);

    if (required > numKeys) {
      throw new Error(`Invalid threshold: ${threshold} exceeds number of parties: ${numKeys}`);
    }

    return {
      required,
      weights: Array.from({ length: numKeys }, () => 1),
    };
  }

  const values = threshold.map((t) => parseFraction(t));

  const denominators = values.map(([, denom]) => denom);
  const required = findLeastCommonDenominator(denominators);
  const weights = values.map(([num, denom]) => (num * required) / denom);

  return { weights, required };
}

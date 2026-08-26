/**
 * Shifts a number left
 *
 * @param num Number to shift left
 * @param bits How many bits to shift
 */
export function lshift(num: number, bits: number): number {
  return num * 2 ** bits;
}

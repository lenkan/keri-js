// A replayed stream would otherwise double every signature it carries.
export function unique<T>(entries: T[]): T[] {
  const seen = new Set<string>();

  return entries.filter((entry) => {
    const key = JSON.stringify(entry);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

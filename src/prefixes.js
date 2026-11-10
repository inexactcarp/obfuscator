/**
 * Find IPv4 addresses and rewrite only the first two octets.
 * The last two octets are left as written. Blank or unchanged
 * replacements are ignored. The scan result is the prefix list only.
 */

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(
  `(?<![\\d.])${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}(?![\\d.])`,
  "g",
);

export function scanPrefixes(text) {
  const found = new Set();
  for (const match of String(text ?? "").matchAll(IPV4)) {
    const [first, second] = match[0].split(".");
    found.add(`${first}.${second}`);
  }
  return [...found].sort(comparePrefixes);
}

export function applyPrefixes(text, replacements) {
  const source = String(text ?? "");
  const active = activeReplacements(replacements);
  if (active.size === 0) return { text: source, addressesRewritten: 0 };
  let addressesRewritten = 0;
  const output = source.replace(IPV4, (ip) => {
    const parts = ip.split(".");
    const prefix = `${parts[0]}.${parts[1]}`;
    const next = active.get(prefix);
    if (!next) return ip;
    addressesRewritten += 1;
    return `${next}.${parts[2]}.${parts[3]}`;
  });
  return { text: output, addressesRewritten };
}

function activeReplacements(replacements) {
  const active = new Map();
  if (!replacements) return active;
  const entries = replacements instanceof Map ? replacements.entries() : Object.entries(replacements);
  for (const [prefix, value] of entries) {
    const next = normalizePrefixReplacement(value);
    if (!next || next === prefix || !next.includes(".")) continue;
    active.set(String(prefix), next);
  }
  return active;
}

export function normalizePrefixReplacement(value) {
  return String(value ?? "").replace(/[\r\n]/g, "").trim();
}

function comparePrefixes(a, b) {
  const [a1, a2] = a.split(".").map(Number);
  const [b1, b2] = b.split(".").map(Number);
  return a1 - b1 || a2 - b2;
}

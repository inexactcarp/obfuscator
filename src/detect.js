/** Heuristic platform detection. Scores are not shown in the UI. */

export const PLATFORM_LABELS = {
  auto: "Auto",
  ios: "Cisco IOS / IOS-XE",
  nxos: "Cisco NX-OS",
  eos: "Arista EOS",
  unknown: "Unknown",
};

const MIN_SCORE = 3;

/**
 * @param {string} text
 * @returns {{ platform: "ios" | "nxos" | "eos" | "unknown", scores: Record<string, number> }}
 */
export function detectPlatform(text) {
  const src = String(text ?? "");
  const scores = { ios: 0, nxos: 0, eos: 0 };

  if (/^! device:.*\bEOS-/m.test(src)) scores.eos += 6;
  if (/^aaa root secret\b/m.test(src)) scores.eos += 4;
  if (/^daemon TerminAttr\b/m.test(src)) scores.eos += 4;
  if (/^management api http-commands\b/m.test(src)) scores.eos += 3;
  if (/^service routing protocols model\b/m.test(src)) scores.eos += 3;
  if (/^interface Ethernet\d+\s*$/m.test(src)) scores.eos += 2;
  if (/\bArista\b/.test(src)) scores.eos += 2;

  if (/^boot nxos\b/m.test(src)) scores.nxos += 6;
  if (/^feature\s+(?:bgp|nxapi|interface-vlan|ospf|eigrp|lldp|vpc|pim|lacp)\b/m.test(src)) {
    scores.nxos += 5;
  }
  if (/^feature\s+tacacs\+/m.test(src)) scores.nxos += 2;
  if (/^vdc\s+\S+/m.test(src)) scores.nxos += 3;
  if (/^version\s+(?:[6-9]|10)\.\d+\(/m.test(src)) scores.nxos += 3;
  if (/\brole network-(?:admin|operator)\b/.test(src)) scores.nxos += 2;
  if (/^interface Ethernet\d+\/\d+/m.test(src)) scores.nxos += 2;
  const featureLines = src.match(/^feature\s+\S+/gm);
  if (featureLines && featureLines.length >= 2) scores.nxos += 2;

  if (/^version\s+1[24567]\.\d+/m.test(src)) scores.ios += 4;
  if (/^boot system\b/m.test(src) && !/\bEOS/i.test(src)) scores.ios += 2;
  if (/^interface (?:GigabitEthernet|FastEthernet|TenGigabitEthernet|FortyGigabitEthernet|HundredGigE|TwoGigabitEthernet|FiveGigabitEthernet|AppGigabitEthernet)/m.test(src)) {
    scores.ios += 3;
  }
  if (/^ip cef\b/m.test(src)) scores.ios += 2;
  if (/^license (?:boot|udi)\b/m.test(src)) scores.ios += 2;
  if (/^switch \d+ provision\b/m.test(src)) scores.ios += 2;

  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [best, bestScore] = ranked[0];
  const secondScore = ranked[1][1];
  if (bestScore < MIN_SCORE || bestScore === secondScore) {
    return { platform: "unknown", scores };
  }
  return { platform: best, scores };
}

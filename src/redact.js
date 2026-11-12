/**
 * Replace secret fields with stable placeholders.
 * Within one config, the same secret string always becomes the same
 * REDACTED_N token. The map is discarded with the function call and is
 * not part of the result.
 *
 * Encryption type digits that may precede a secret:
 * 0 clear, 3 NX-OS, 4 legacy, 5 MD5, 6 AES, 7 Cisco, 8 PBKDF2, 9 scrypt.
 */

export const CATEGORIES = [
  { id: "enable", label: "Enable password/secret" },
  { id: "user", label: "Username passwords and secrets" },
  { id: "line", label: "Line passwords" },
  { id: "snmp", label: "SNMP communities and SNMPv3 passphrases" },
  { id: "tacacsRadius", label: "TACACS and RADIUS keys" },
  { id: "keychain", label: "AAA and key-chain keys" },
  { id: "routing", label: "Routing authentication keys" },
  { id: "ntp", label: "NTP authentication keys" },
  { id: "crypto", label: "IPsec, IKE, and crypto keys" },
  { id: "certificate", label: "Crypto certificates" },
  { id: "banner", label: "Login banners" },
  { id: "wireless", label: "Wireless and 802.1X PSKs" },
  { id: "mgmt", label: "Management API secrets" },
];

const ENCRYPTION_TYPES = new Set(["0", "3", "4", "5", "6", "7", "8", "9"]);
const USER_HASH_TYPES = new Set([
  ...ENCRYPTION_TYPES,
  "md5",
  "sha",
  "sha1",
  "sha256",
  "sha384",
  "sha512",
  "scrypt",
]);
const ISIS_KEY_TYPES = new Set([
  ...ENCRYPTION_TYPES,
  "md5",
  "text",
  "hmac-md5",
  "hmac-sha-1",
  "hmac-sha1",
]);
const SNMP_AUTH = new Set(["md5", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"]);
const SNMP_PRIV = new Set([
  "des",
  "3des",
  "aes",
  "aes128",
  "aes-128",
  "aes192",
  "aes-192",
  "aes256",
  "aes-256",
]);
const SNMP_KEYWORDS = new Set([
  "auth",
  "priv",
  "access",
  "localized",
  "localizedkey",
  "v3",
  "version",
  "encrypted",
  "engineid",
]);

const SUBCOMMANDS = {
  line: /^(no\s+)?(login|exec-timeout|transport|access-class|authorization|accounting|logging|length|width|history|privilege|rotary|session-timeout|absolute-timeout|timeout|stopbits|databits|flowcontrol|speed|parity|modem|location|vacancy-login|motd-banner|exec-banner|international|flush-at-activation|session-limit)\b/i,
  bgp: /^(no\s+)?(neighbor|address-family|router-id|bgp|timers|network|redistribute|maximum-paths|template|vrf|log-neighbor|graceful-restart|bestpath)\b/i,
  "bgp-neighbor": /^(no\s+)?(remote-as|password|description|update-source|address-family|inherit|ebgp-multihop|next-hop-self|shutdown|timers|send-community|route-map|soft-reconfiguration)\b/i,
  keychain: /^key\s+\d+\b/i,
  "keychain-key": /^(no\s+)?(key-string|cryptographic-algorithm|accept-lifetime|send-lifetime|lifetime)\b/i,
  radius: /^(no\s+)?(address|key|retransmit|timeout|automate-tester|pac)\b/i,
  tacacs: /^(no\s+)?(address|key|port|timeout|single-connection)\b/i,
  "aaa-group": /^(no\s+)?(server-private|server|deadtime|source-interface|ip|ipv6|key|vrf)\b/i,
  "aaa-radius": /^(no\s+)?(client|auth-type|port|ignore)\b/i,
  "ikev2-keyring": /^(no\s+)?peer\b/i,
  "ikev2-peer": /^(no\s+)?(address|hostname|identity|pre-shared-key|description)\b/i,
  "crypto-keyring": /^(no\s+)?(pre-shared-key|local-address|description|psk)\b/i,
  "pubkey-chain": /^(no\s+)?(addressed-key|named-key|key-string|quit)\b/i,
  "pki-chain": /^(no\s+)?(certificate|quit)\b/i,
  "pubkey-key": /^(no\s+)?(key-string|quit|address|serial-number|signature|key-hash)\b/i,
  dot1x: /^(no\s+)?(username|password|anonymous-id|description|psk)\b/i,
  dot11: /^(no\s+)?(authentication|wpa-psk|vlan|mbssid|guest-mode|max-associations)\b/i,
  wlan: /^(no\s+)?(security|shutdown|client|radio|broadcast-ssid|session-timeout|ccx)\b/i,
  interface: /^(no\s+)?(ip|ipv6|isis|description|switchport|shutdown|vrf|encapsulation|standby|vrrp|glbp|ospf|cdp|lldp|spanning-tree|mtu|speed|duplex|channel-group|service-policy|authentication|dot1x|mpls|bfd|arp|negotiation|logging|bandwidth|delay|keepalive|mac-address|load-interval)\b/i,
  router: /^(no\s+)?(network|passive-interface|redistribute|address-family|af-interface|authentication|area-password|domain-password|lsp-password|metric|auto-summary|version|default-information|distance|maximum-paths|neighbor|eigrp)\b/i,
};

export function placeholderStem(value) {
  const cleaned = String(value ?? "").replace(/[\r\n]/g, "").trim();
  return (cleaned || "REDACTED").slice(0, 40);
}

function createSession(placeholder) {
  const stem = placeholderStem(placeholder);
  const values = new Map();
  const counts = Object.fromEntries(CATEGORIES.map((category) => [category.id, 0]));
  return {
    counts,
    tokenFor(secret, category) {
      let token = values.get(secret);
      if (!token) {
        token = `${stem}_${values.size + 1}`;
        values.set(secret, token);
      }
      counts[category] += 1;
      return token;
    },
  };
}

function readToken(text, from) {
  let i = from;
  while (i < text.length && /\s/.test(text[i])) i += 1;
  if (i >= text.length) return null;
  const start = i;
  let value;
  let quoted = false;
  if (text[i] === '"' || text[i] === "'") {
    const quote = text[i];
    i += 1;
    const valueStart = i;
    while (i < text.length && text[i] !== quote) i += 1;
    value = text.slice(valueStart, i);
    quoted = i < text.length && text[i] === quote;
    if (quoted) i += 1;
  } else {
    while (i < text.length && !/\s/.test(text[i])) i += 1;
    value = text.slice(start, i);
  }
  return { start, end: i, raw: text.slice(start, i), value, quoted };
}

function showToken(tokenInfo, placeholder) {
  if (!tokenInfo.quoted) return placeholder;
  const quote = tokenInfo.raw[0];
  return `${quote}${placeholder}${quote}`;
}

function replaceKeywordSecret(line, pattern, session, category, options = {}) {
  const flags = pattern.flags.includes("i") ? "i" : "";
  const match = new RegExp(pattern.source, flags).exec(line);
  if (!match) return line;
  let token = readToken(line, match.index + match[0].length);
  if (!token) return line;
  if (options.types && options.types.has(token.value.toLowerCase())) {
    const next = readToken(line, token.end);
    if (next) token = next;
  }
  if (options.skip && options.skip.has(token.value.toLowerCase())) return line;
  if (token.value === "") return line;
  const placeholder = session.tokenFor(token.value, category);
  return line.slice(0, token.start) + showToken(token, placeholder) + line.slice(token.end);
}

function tokenize(line) {
  const tokens = [];
  let i = 0;
  while (i < line.length) {
    const token = readToken(line, i);
    if (!token) break;
    tokens.push(token);
    i = token.end;
  }
  return tokens;
}

function isPasswordCommand(trimmed) {
  return /^\s*password\b/i.test(trimmed)
    && !/^\s*password\s+(?:encryption|complexity|strength-check|secure-mode|policy)\b/i.test(trimmed);
}

function isSubcommand(context, trimmed) {
  if ((context === "line" || context === "dot1x" || context === "bgp-neighbor") && isPasswordCommand(trimmed)) {
    return true;
  }
  if (context === "bgp-neighbor") {
    return SUBCOMMANDS["bgp-neighbor"].test(trimmed) || SUBCOMMANDS.bgp.test(trimmed);
  }
  if (context === "keychain-key") {
    return SUBCOMMANDS["keychain-key"].test(trimmed) || SUBCOMMANDS.keychain.test(trimmed);
  }
  if (context === "ikev2-peer") {
    return SUBCOMMANDS["ikev2-peer"].test(trimmed) || SUBCOMMANDS["ikev2-keyring"].test(trimmed);
  }
  if (context === "pubkey-key") {
    return SUBCOMMANDS["pubkey-key"].test(trimmed) || SUBCOMMANDS["pubkey-chain"].test(trimmed);
  }
  const rule = SUBCOMMANDS[context];
  return rule ? rule.test(trimmed) : false;
}

function openingContext(trimmed) {
  if (/^line\s+(?:con|console|aux|vty|tty)\b/i.test(trimmed)) return "line";
  if (/^router\s+bgp\b/i.test(trimmed)) return "bgp";
  if (/^router\s+/i.test(trimmed)) return "router";
  if (/^key\s+chain\b/i.test(trimmed)) return "keychain";
  if (/^radius\s+server\b/i.test(trimmed)) return "radius";
  if (/^tacacs\s+server\b/i.test(trimmed)) return "tacacs";
  if (/^aaa\s+group\s+server\s+(?:radius|tacacs\+)/i.test(trimmed)) return "aaa-group";
  if (/^aaa\s+server\s+radius\b/i.test(trimmed)) return "aaa-radius";
  if (/^crypto\s+ikev2\s+keyring\b/i.test(trimmed)) return "ikev2-keyring";
  if (/^crypto\s+keyring\b/i.test(trimmed)) return "crypto-keyring";
  if (/^crypto\s+key\s+pubkey-chain\b/i.test(trimmed)) return "pubkey-chain";
  if (/^crypto\s+(?:pki|ca)\s+certificate\s+chain\b/i.test(trimmed)) return "pki-chain";
  if (/^dot1x\s+credentials\b/i.test(trimmed)) return "dot1x";
  if (/^dot11\s+ssid\b/i.test(trimmed)) return "dot11";
  if (/^wlan\s+\S+/i.test(trimmed)) return "wlan";
  if (/^interface\s+/i.test(trimmed)) return "interface";
  return null;
}

function updateContext(ctx, line) {
  const trimmed = line.trim();
  if (!trimmed) return;
  if (trimmed.startsWith("!")) {
    ctx.name = "global";
    ctx.indent = 0;
    return;
  }
  const indent = line.match(/^\s*/)[0].length;
  const opener = openingContext(trimmed);
  const inside = ctx.name !== "global" && (indent > ctx.indent || isSubcommand(ctx.name, trimmed));
  if (inside) {
    if ((ctx.name === "bgp" || ctx.name === "bgp-neighbor") && /^neighbor\s+\S+\s*$/i.test(trimmed)) {
      ctx.name = "bgp-neighbor";
    } else if ((ctx.name === "keychain" || ctx.name === "keychain-key") && /^key\s+\d+\b/i.test(trimmed)) {
      ctx.name = "keychain-key";
    } else if ((ctx.name === "ikev2-keyring" || ctx.name === "ikev2-peer") && /^peer\b/i.test(trimmed)) {
      ctx.name = "ikev2-peer";
    } else if ((ctx.name === "pubkey-chain" || ctx.name === "pubkey-key") && /^key-string\s*$/i.test(trimmed)) {
      ctx.name = "pubkey-key";
    }
    return;
  }
  if (opener) {
    ctx.name = opener;
    ctx.indent = indent;
    return;
  }
  ctx.name = "global";
  ctx.indent = 0;
}

function bannerDelimiter(line) {
  const match = /^(\s*banner\s+(motd|login|exec|incoming|slip-ppp)\s+)(\S)/i.exec(line);
  if (!match) return null;
  const delim = match[3];
  const rest = line.slice(match[1].length + 1);
  return { kind: match[2].toLowerCase(), head: match[1], delim, closed: rest.includes(delim) };
}

function redactLoginBanner(line, lines, index, session) {
  const parsed = bannerDelimiter(line);
  if (!parsed || parsed.kind !== "login") return null;
  const { head, delim } = parsed;
  const rest = line.slice(head.length + 1);
  const closeAt = rest.indexOf(delim);
  if (closeAt !== -1) {
    const body = rest.slice(0, closeAt);
    const token = body.trim() ? session.tokenFor(body, "banner") : "";
    return {
      lines: [head + delim + token + delim + rest.slice(closeAt + 1)],
      next: index + 1,
    };
  }
  const parts = [];
  if (rest.trim()) parts.push(rest);
  let j = index + 1;
  while (j < lines.length && !lines[j].includes(delim)) {
    parts.push(lines[j]);
    j += 1;
  }
  const body = parts.join("\n").trim();
  const out = [head + delim];
  if (body) {
    const sample = lines[index + 1] && !lines[index + 1].includes(delim) ? lines[index + 1] : "";
    const indent = sample.match(/^\s*/)[0];
    out.push(`${indent}${session.tokenFor(body, "banner")}`);
  }
  if (j < lines.length) out.push(lines[j]);
  return { lines: out, next: j + 1 };
}

function pemCategory(line) {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(line);
  if (!match) return null;
  if (/PRIVATE KEY$/.test(match[1])) return { label: match[1], category: "crypto" };
  if (/CERTIFICATE$/.test(match[1])) return { label: match[1], category: "certificate" };
  return null;
}

function isHexDump(line) {
  return /^[0-9A-Fa-f]{2,}(?:\s+[0-9A-Fa-f]{2,})*$/.test(line.trim());
}

function redactEnable(line, session) {
  if (!/^\s*enable\s+(?:password|secret)\b/i.test(line)) return line;
  return replaceKeywordSecret(
    line,
    /^\s*enable\s+(?:password|secret)(?:\s+level\s+\d+)?\s+/i,
    session,
    "enable",
    { types: ENCRYPTION_TYPES },
  );
}

function redactUser(line, session) {
  if (!/^\s*(?:username\s+\S+|aaa\s+root)\b/i.test(line)) return line;
  if (!/(^|\s)(?:password|secret)\s+/i.test(line)) return line;
  return replaceKeywordSecret(line, /(^|\s)(?:password|secret)\s+/i, session, "user", {
    types: USER_HASH_TYPES,
  });
}

function redactContextPassword(line, session, context) {
  const category = { line: "line", dot1x: "wireless", "bgp-neighbor": "routing" }[context];
  if (!category || !isPasswordCommand(line)) return line;
  return replaceKeywordSecret(line, /^\s*password\s+/i, session, category, {
    types: ENCRYPTION_TYPES,
  });
}

function redactSnmpCommunity(line, session) {
  if (!/^\s*snmp-server\s+community\s+/i.test(line)) return line;
  return replaceKeywordSecret(line, /^\s*snmp-server\s+community\s+/i, session, "snmp");
}

function redactSnmpHost(line, session) {
  if (!/^\s*snmp-server\s+host\s+/i.test(line)) return line;
  if (/\bversion\s+3\b/i.test(line)) return line;
  if (/\bversion\s+(?:1|2c)\b/i.test(line)) {
    return replaceKeywordSecret(line, /\bversion\s+(?:1|2c)\s+/i, session, "snmp");
  }
  return replaceKeywordSecret(
    line,
    /^\s*snmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+)?/i,
    session,
    "snmp",
    { skip: new Set(["version", "traps", "informs"]) },
  );
}

function redactSnmpUser(line, session) {
  if (!/^\s*snmp-server\s+user\s+/i.test(line)) return line;
  const tokens = tokenize(line);
  const lower = tokens.map((token) => token.value.toLowerCase());
  const hit = new Set();

  for (let n = 0; n < tokens.length; n += 1) {
    if (lower[n] === "auth") {
      let j = n + 1;
      if (j < tokens.length && SNMP_AUTH.has(lower[j])) j += 1;
      if (j < tokens.length && ENCRYPTION_TYPES.has(lower[j]) && j + 1 < tokens.length) j += 1;
      if (j < tokens.length && !SNMP_KEYWORDS.has(lower[j])) hit.add(j);
    }
    if (lower[n] === "priv") {
      let j = n + 1;
      if (j < tokens.length && SNMP_PRIV.has(lower[j])) j += 1;
      if (j < tokens.length && /^(128|192|256)$/.test(lower[j])) j += 1;
      if (j < tokens.length && ENCRYPTION_TYPES.has(lower[j]) && j + 1 < tokens.length) j += 1;
      if (j < tokens.length && !SNMP_KEYWORDS.has(lower[j])) hit.add(j);
    }
  }
  if (hit.size === 0) return line;

  let out = "";
  let cursor = 0;
  for (const index of [...hit].sort((a, b) => a - b)) {
    const token = tokens[index];
    const placeholder = session.tokenFor(token.value, "snmp");
    out += line.slice(cursor, token.start) + showToken(token, placeholder);
    cursor = token.end;
  }
  return out + line.slice(cursor);
}

function redactStandaloneKey(line, session, category) {
  if (/^\s*key\s+\d+\s*$/i.test(line)) return line;
  const match = /(^|\s)key(\s+)(?!chain\b|config-key\b)/i.exec(line);
  if (!match) return line;
  let token = readToken(line, match.index + match[0].length);
  if (!token) return line;
  if (ENCRYPTION_TYPES.has(token.value.toLowerCase())) {
    const next = readToken(line, token.end);
    if (!next) return line;
    token = next;
  }
  if (token.value === "" || /^(chain|config-key)$/i.test(token.value)) return line;
  const placeholder = session.tokenFor(token.value, category);
  return line.slice(0, token.start) + showToken(token, placeholder) + line.slice(token.end);
}

function redactTacacsRadius(line, session, context) {
  const inBlock = context === "radius"
    || context === "tacacs"
    || context === "aaa-group"
    || context === "aaa-radius";
  const serverLine = /^\s*(?:tacacs-server|radius-server)\b/i.test(line);
  if (!inBlock && !serverLine && !/(^|\s)server-key\s+/i.test(line)) return line;

  let next = line;
  if (/(^|\s)server-key\s+/i.test(next)) {
    next = replaceKeywordSecret(next, /(^|\s)server-key\s+/i, session, "tacacsRadius", {
      types: ENCRYPTION_TYPES,
    });
  }
  if (/(^|\s)key(\s+)(?!chain\b|config-key\b)/i.test(next)) {
    next = redactStandaloneKey(next, session, "tacacsRadius");
  }
  return next;
}

function redactKeyString(line, session) {
  if (!/^\s*key-string\s+\S/i.test(line)) return line;
  return replaceKeywordSecret(line, /^\s*key-string\s+/i, session, "keychain", {
    types: ENCRYPTION_TYPES,
  });
}

function redactMasterKey(line, session) {
  if (!/^\s*key\s+config-key\s+password-encrypt\s+\S/i.test(line)) return line;
  return replaceKeywordSecret(line, /\bpassword-encrypt\s+/i, session, "keychain", {
    types: ENCRYPTION_TYPES,
  });
}

function redactRouting(line, session) {
  if (/^\s*(?:ip|ipv6)\s+ospf\s+message-digest-key\s+\d+\s+\S+\s+/i.test(line)) {
    return replaceKeywordSecret(
      line,
      /^\s*(?:ip|ipv6)\s+ospf\s+message-digest-key\s+\d+\s+\S+\s+/i,
      session,
      "routing",
      { types: ENCRYPTION_TYPES },
    );
  }
  if (/^\s*(?:ip|ipv6)\s+ospf\s+authentication-key\s+/i.test(line)) {
    return replaceKeywordSecret(
      line,
      /^\s*(?:ip|ipv6)\s+ospf\s+authentication-key\s+/i,
      session,
      "routing",
      { types: ENCRYPTION_TYPES },
    );
  }
  if (/^\s*ipv6\s+ospf\s+authentication\s+ipsec\s+spi\s+\d+\s+\S+\s+/i.test(line)) {
    return replaceKeywordSecret(
      line,
      /^\s*ipv6\s+ospf\s+authentication\s+ipsec\s+spi\s+\d+\s+\S+\s+/i,
      session,
      "routing",
      { types: ENCRYPTION_TYPES },
    );
  }
  if (/^\s*isis\s+password\s+/i.test(line)) {
    return replaceKeywordSecret(line, /^\s*isis\s+password\s+/i, session, "routing", {
      types: ENCRYPTION_TYPES,
    });
  }
  if (/^\s*(?:lsp-password|domain-password|area-password)\s+/i.test(line)) {
    return replaceKeywordSecret(
      line,
      /^\s*(?:lsp-password|domain-password|area-password)\s+/i,
      session,
      "routing",
      { types: ISIS_KEY_TYPES },
    );
  }
  if (/^\s*neighbor\s+\S+\s+password\s+/i.test(line)) {
    return replaceKeywordSecret(line, /^\s*neighbor\s+\S+\s+password\s+/i, session, "routing", {
      types: ENCRYPTION_TYPES,
    });
  }
  return line;
}

function redactNtp(line, session) {
  if (!/^\s*ntp\s+authentication-key\s+\d+\s+\S+\s+/i.test(line)) return line;
  return replaceKeywordSecret(
    line,
    /^\s*ntp\s+authentication-key\s+\d+\s+\S+\s+/i,
    session,
    "ntp",
    { types: ENCRYPTION_TYPES },
  );
}

function redactIsakmp(line, session) {
  if (!/^\s*crypto\s+isakmp\s+key\s+/i.test(line)) return line;
  return replaceKeywordSecret(line, /^\s*crypto\s+isakmp\s+key\s+/i, session, "crypto", {
    types: ENCRYPTION_TYPES,
  });
}

function redactPreShared(line, session) {
  if (!/^\s*pre-shared-key\b/i.test(line)) return line;
  if (/\b(?:address|hostname)\b/i.test(line) && /(^|\s)key\s+/i.test(line)) {
    return redactStandaloneKey(line, session, "crypto");
  }
  if (/\blocal\b/i.test(line) || /\bremote\b/i.test(line)) {
    let next = replaceKeywordSecret(line, /\blocal\s+/i, session, "crypto");
    next = replaceKeywordSecret(next, /\bremote\s+/i, session, "crypto");
    return next;
  }
  return replaceKeywordSecret(line, /^\s*pre-shared-key\s+/i, session, "crypto");
}

function redactWireless(line, session) {
  if (/\bsecurity\s+wpa\s+psk\s+set-key\s+(?:ascii|hex)\s+/i.test(line)) {
    return replaceKeywordSecret(
      line,
      /\bsecurity\s+wpa\s+psk\s+set-key\s+(?:ascii|hex)\s+/i,
      session,
      "wireless",
      { types: ENCRYPTION_TYPES },
    );
  }
  if (/^\s*wpa-psk\s+(?:ascii|hex)\s+/i.test(line)) {
    return replaceKeywordSecret(line, /^\s*wpa-psk\s+(?:ascii|hex)\s+/i, session, "wireless", {
      types: ENCRYPTION_TYPES,
    });
  }
  return line;
}

function redactCvauth(line, session) {
  if (!/-cvauth(?:=|\s+)/i.test(line)) return line;
  return replaceKeywordSecret(line, /-cvauth(?:=|\s+)/i, session, "mgmt");
}

function redactLabeled(line, session) {
  if (/^\s*(?:description|remark|banner|name)\b/i.test(line)) return line;
  let next = replaceKeywordSecret(line, /(?:^|\s)(?:Password|password|passwd|passphrase)\s*[:=]\s+/i, session, "user");
  next = replaceKeywordSecret(next, /(?:^|\s)community(?:\s+(?:string|name))?\s*[:=]\s+/i, session, "snmp");
  return next;
}

const EMBEDDED_COMMAND = /(?:enable\s+(?:password|secret)|username\s+\S+|aaa\s+root\s+secret|snmp-server\s+(?:community|host|user)|(?:tacacs|radius)-server\b|ntp\s+authentication-key|(?:ip|ipv6)\s+ospf\s+(?:message-digest-key|authentication-key)|neighbor\s+\S+\s+password|crypto\s+isakmp\s+key|pre-shared-key\b|key-string\b|server-key\b|wpa-psk\s+|security\s+wpa\s+psk\s+set-key\b)/i;

function redactLoose(line, session, context) {
  const direct = redactLabeled(redactLine(line, session, context), session);
  if (direct !== line) return direct;
  if (/^\s*(?:description|remark|banner|name|!)/i.test(line)) return direct;
  const embedded = EMBEDDED_COMMAND.exec(line);
  if (!embedded || embedded.index === 0) return direct;
  return line.slice(0, embedded.index) + redactLine(line.slice(embedded.index), session, context);
}

function peelCommandOutput(line) {
  let prefix = "";
  let rest = line;
  const prompt = rest.match(/^(\s*[A-Za-z0-9][\w.\-/:]*[#>])\s*/);
  if (prompt) {
    prefix = prompt[0];
    rest = rest.slice(prompt[0].length);
  }
  const stamp = rest.match(/^((?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?:\s+)|(?:\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+))/);
  if (stamp) {
    prefix += stamp[1];
    rest = rest.slice(stamp[1].length);
  }
  return { prefix, rest };
}

function redactLine(line, session, context) {
  let next = line;
  next = redactEnable(next, session);
  next = redactUser(next, session);
  next = redactContextPassword(next, session, context);
  next = redactSnmpCommunity(next, session);
  next = redactSnmpHost(next, session);
  next = redactSnmpUser(next, session);
  next = redactTacacsRadius(next, session, context);
  next = redactKeyString(next, session);
  next = redactMasterKey(next, session);
  next = redactRouting(next, session);
  next = redactNtp(next, session);
  next = redactIsakmp(next, session);
  next = redactPreShared(next, session);
  next = redactWireless(next, session);
  next = redactCvauth(next, session);
  return next;
}

function takeBlock(lines, start, endTest) {
  const body = [];
  let indent = "";
  let saw = false;
  let i = start;
  while (i < lines.length && !endTest(lines[i])) {
    if (!saw) {
      indent = lines[i].match(/^\s*/)[0];
      saw = true;
    }
    body.push(lines[i].trim());
    i += 1;
  }
  return { body, indent, next: i };
}

/**
 * @param {string} text
 * @returns {{ output: string, counts: Record<string, number> }}
 */
export function redactConfig(text, options = {}) {
  const source = String(text ?? "");
  const session = createSession(options.placeholder);
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  const lines = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const out = [];
  const ctx = { name: "global", indent: 0 };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const banner = bannerDelimiter(line);
    if (banner) {
      ctx.name = "global";
      ctx.indent = 0;
      if (banner.kind === "login") {
        const replaced = redactLoginBanner(line, lines, i, session);
        out.push(...replaced.lines);
        i = replaced.next;
        continue;
      }
      out.push(line);
      if (!banner.closed) {
        i += 1;
        while (i < lines.length) {
          out.push(lines[i]);
          if (lines[i].includes(banner.delim)) break;
          i += 1;
        }
      }
      i += 1;
      continue;
    }

    const pem = pemCategory(line);
    if (pem) {
      ctx.name = "global";
      ctx.indent = 0;
      out.push(line);
      const end = `-----END ${pem.label}-----`;
      const block = takeBlock(lines, i + 1, (candidate) => candidate.includes(end));
      const secret = block.body.filter(Boolean).join("");
      if (secret) out.push(`${block.indent}${session.tokenFor(secret, pem.category)}`);
      i = block.next;
      if (i < lines.length) out.push(lines[i]);
      i += 1;
      continue;
    }

    const peeled = peelCommandOutput(line);
    const commandLine = peeled.prefix && peeled.rest ? peeled.rest : line;
    updateContext(ctx, commandLine);

    if (/^\s*certificate\b/i.test(commandLine) && ctx.name === "pki-chain") {
      const hex = [];
      let j = i + 1;
      while (j < lines.length && isHexDump(lines[j])) {
        hex.push(lines[j].trim());
        j += 1;
      }
      if (hex.length) {
        out.push(line);
        const indent = lines[i + 1].match(/^\s*/)[0];
        out.push(`${indent}${session.tokenFor(hex.join(""), "certificate")}`);
        i = j;
        if (i < lines.length && /^\s*quit\s*$/i.test(lines[i])) {
          out.push(lines[i]);
          i += 1;
        }
        continue;
      }
    }

    if (/^\s*key-string\s*$/i.test(commandLine) && (ctx.name === "pubkey-chain" || ctx.name === "pubkey-key")) {
      out.push(line);
      const block = takeBlock(lines, i + 1, (candidate) => /^\s*quit\s*$/i.test(candidate));
      const secret = block.body.filter(Boolean).join("");
      if (secret) out.push(`${block.indent}${session.tokenFor(secret, "crypto")}`);
      i = block.next;
      if (i < lines.length) out.push(lines[i]);
      i += 1;
      continue;
    }

    const redacted = peeled.prefix && peeled.rest
      ? peeled.prefix + redactLoose(peeled.rest, session, ctx.name)
      : redactLoose(line, session, ctx.name);
    out.push(redacted);
    i += 1;
  }

  return { output: out.join(newline), counts: session.counts };
}

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { detectPlatform } from "../src/detect.js";
import { processConfig } from "../src/process.js";
import { redactConfig } from "../src/redact.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function load(name) {
  return fs.readFileSync(path.join(root, "test", "fixtures", name), "utf8");
}

function tokenCount(output) {
  return (output.match(/REDACTED_\d+/g) || []).length;
}

function assertFixture(name, platform, counts) {
  const input = load(name);
  const result = processConfig(input, "auto");
  assert.equal(result.platform, platform, name);
  assert.equal(result.uncertain, false, name);
  assert.equal(result.output.endsWith("\n"), input.endsWith("\n"));

  const outputLines = new Set(result.output.split("\n"));
  for (const line of input.split("\n")) {
    if (line.includes("SEC_")) {
      assert.equal(result.output.includes(line), false, `secret line leaked: ${line}`);
    } else {
      assert.ok(outputLines.has(line), `changed a non-secret line: ${JSON.stringify(line)}`);
    }
  }

  assert.doesNotMatch(result.output, /SEC_/);
  assert.doesNotMatch(JSON.stringify({ counts: result.counts, detection: result.detection, platform: result.platform }), /SEC_/);
  assert.deepEqual(result.counts, counts, JSON.stringify(result.counts));
  const sum = Object.values(result.counts).reduce((total, count) => total + count, 0);
  assert.equal(tokenCount(result.output), sum);
  return result;
}

const zero = {
  enable: 0,
  user: 0,
  line: 0,
  snmp: 0,
  tacacsRadius: 0,
  keychain: 0,
  routing: 0,
  ntp: 0,
  crypto: 0,
  certificate: 0,
  banner: 0,
  wireless: 0,
  mgmt: 0,
};

test("IOS fixture redacts secrets and keeps structure", () => {
  const result = assertFixture("ios.cfg", "ios", {
    ...zero,
    enable: 7,
    user: 3,
    line: 3,
    snmp: 4,
    tacacsRadius: 7,
    keychain: 1,
    routing: 4,
    ntp: 1,
    crypto: 6,
    certificate: 1,
    banner: 1,
    wireless: 3,
  });
  const output = result.output;
  const enable = output.match(/^enable secret 0 (REDACTED_\d+)$/m);
  const vty = output.match(/^ password 0 (REDACTED_\d+)$/m);
  assert.ok(enable && vty);
  assert.equal(enable[1], vty[1]);
  const user = output.match(/^username ops password 0 (REDACTED_\d+)$/m);
  assert.ok(user);
  assert.notEqual(user[1], enable[1]);

  assert.match(output, /^username admin privilege 15 secret 9 REDACTED_\d+$/m);
  assert.match(output, /^username noc privilege 1 password 7 REDACTED_\d+$/m);
  assert.match(output, /^snmp-server user snmpuser SNMPGROUP v3 auth sha REDACTED_\d+ priv aes 128 REDACTED_\d+$/m);
  assert.match(output, /^snmp-server host 10\.9\.9\.2 version 3 priv snmpuser$/m);
  assert.match(output, /^tacacs-server host 10\.8\.8\.1 key 7 REDACTED_\d+$/m);
  assert.match(output, /^ client 10\.8\.8\.5 server-key 0 REDACTED_\d+$/m);
  assert.match(output, /^  key-string 7 REDACTED_\d+$/m);
  assert.match(output, /^ neighbor 192\.0\.2\.10 password 7 REDACTED_\d+$/m);
  assert.match(output, /^ntp authentication-key 1 md5 REDACTED_\d+ 7$/m);
  assert.match(output, /^ntp server 10\.7\.7\.1 key 1$/m);
  assert.match(output, /^crypto isakmp key REDACTED_\d+ address 192\.0\.2\.50$/m);
  assert.match(output, /^ pre-shared-key address 192\.0\.2\.40 key REDACTED_\d+$/m);
  assert.match(output, /^  pre-shared-key local REDACTED_\d+ remote REDACTED_\d+$/m);
  assert.match(output, /^ security wpa psk set-key ascii 0 REDACTED_\d+$/m);
  assert.match(output, /^ wpa-psk ascii 0 REDACTED_\d+$/m);
  assert.match(output, /^ password 0 REDACTED_\d+$/m);
  assert.match(output, /^-----BEGIN RSA PRIVATE KEY-----$/m);
  assert.match(output, /^-----END RSA PRIVATE KEY-----$/m);
  assert.match(output, /^-----BEGIN CERTIFICATE-----$/m);
  assert.doesNotMatch(output, /SEC_IOS_CERT_BODY/);
  assert.doesNotMatch(output, /SEC_IOS_LOGIN_BANNER/);
  assert.match(output, /^banner login \^$/m);
  assert.match(output, /SSH_PUBLIC_FINGERPRINT/);
  assert.match(output, /^ authentication pre-share$/m);
  assert.match(output, /^service password-encryption$/m);
  assert.match(output, /^password encryption aes$/m);
  assert.match(output, /^ key 1$/m);
  assert.equal((output.match(/^password encryption aes$/gm) || []).length, 2);
});

test("NX-OS fixture redacts secrets and keeps structure", () => {
  const result = assertFixture("nxos.cfg", "nxos", {
    ...zero,
    user: 2,
    line: 1,
    snmp: 4,
    tacacsRadius: 3,
    keychain: 1,
    routing: 3,
    ntp: 1,
  });
  const output = result.output;
  assert.match(output, /^username admin password 5 REDACTED_\d+ role network-admin$/m);
  assert.match(output, /^username ops password 0 REDACTED_\d+ role network-operator$/m);
  assert.match(output, /^snmp-server user snmpuser network-operator auth md5 REDACTED_\d+ priv aes-128 REDACTED_\d+ localizedkey$/m);
  assert.match(output, /^tacacs-server host 10\.8\.8\.8 key 7 "REDACTED_\d+"$/m);
  assert.match(output, /^radius-server host 10\.8\.8\.9 key 0 "REDACTED_\d+" auth-port 1812 acct-port 1813$/m);
  assert.match(output, /^    password 3 REDACTED_\d+$/m);
  assert.match(output, /^    description Peer in site B$/m);
  assert.match(output, /^  key 1$/m);
  assert.match(output, /^password strength-check$/m);
  assert.match(output, /^ {2}ip address 10\.1\.1\.1\/24$/m);
});

test("EOS fixture redacts secrets and keeps structure", () => {
  const result = assertFixture("eos.cfg", "eos", {
    ...zero,
    user: 3,
    snmp: 4,
    tacacsRadius: 3,
    keychain: 1,
    routing: 2,
    ntp: 1,
    mgmt: 1,
  });
  const output = result.output;
  assert.match(output, /^aaa root secret sha512 REDACTED_\d+$/m);
  assert.match(output, /^username admin privilege 15 role network-admin secret sha512 REDACTED_\d+$/m);
  assert.match(output, /^username ops privilege 1 secret 0 REDACTED_\d+$/m);
  assert.match(output, /-cvauth=REDACTED_\d+/);
  assert.match(output, /\/usr\/bin\/TerminAttr/);
  assert.match(output, /-cvaddr=10\.5\.5\.5:9910/);
  assert.match(output, /-taillogs/);
  assert.match(output, /^   protocol https$/m);
  assert.match(output, /^   neighbor 10\.2\.2\.2 description WAN peer$/m);
  assert.match(output, /^   key 1$/m);
  assert.match(output, /^hostname eos-leaf-1$/m);
});

test("the same secret maps to one placeholder and a different secret does not", () => {
  const { output, counts } = redactConfig([
    "enable secret 0 SEC_SHARED",
    "username bob password 0 SEC_SHARED",
    "username bob password 0 SEC_OTHER",
  ].join("\n"));
  assert.doesNotMatch(output, /SEC_/);
  const lines = output.split("\n");
  const first = lines[0].match(/REDACTED_\d+/)[0];
  const second = lines[1].match(/REDACTED_\d+/)[0];
  const third = lines[2].match(/REDACTED_\d+/)[0];
  assert.equal(first, "REDACTED_1");
  assert.equal(second, first);
  assert.equal(third, "REDACTED_2");
  assert.match(lines[1], /^username bob password 0 REDACTED_1$/);
  assert.equal(counts.enable, 1);
  assert.equal(counts.user, 2);
});

test("usernames, descriptions, and hostnames stay when they match a secret", () => {
  const { output } = redactConfig([
    "hostname edge",
    "username admin password 0 edge",
    "interface GigabitEthernet0/1",
    " description edge",
    " ip address 10.0.0.1 255.255.255.0",
  ].join("\n"));
  const lines = output.split("\n");
  assert.equal(lines[0], "hostname edge");
  assert.equal(lines[1], "username admin password 0 REDACTED_1");
  assert.equal(lines[2], "interface GigabitEthernet0/1");
  assert.equal(lines[3], " description edge");
  assert.equal(lines[4], " ip address 10.0.0.1 255.255.255.0");
});

test("motd banners keep their text and login banners are removed", () => {
  const { output, counts } = redactConfig([
    "banner motd ^",
    "password SEC_SHOULD_STAY_IN_BANNER",
    "enable secret 0 not-a-command-here",
    "^",
    "banner login ^",
    "SEC_LOGIN_ONE",
    "SEC_LOGIN_TWO",
    "^",
    "banner login #SEC_INLINE#",
    "banner exec ^",
    "exec banner stays",
    "^",
    "enable secret 0 SEC_REAL",
  ].join("\n"));
  assert.match(output, /^password SEC_SHOULD_STAY_IN_BANNER$/m);
  assert.match(output, /^enable secret 0 not-a-command-here$/m);
  assert.match(output, /^exec banner stays$/m);
  assert.doesNotMatch(output, /SEC_LOGIN/);
  assert.doesNotMatch(output, /SEC_INLINE/);
  assert.match(output, /^banner login \^$/m);
  assert.match(output, /^banner login #REDACTED_\d+#$/m);
  assert.equal(counts.banner, 2);
  assert.doesNotMatch(output, /SEC_REAL/);
  assert.match(output, /^enable secret 0 REDACTED_\d+$/m);
});

test("crypto certificates are removed and key hashes stay", () => {
  const { output, counts } = redactConfig([
    "-----BEGIN CERTIFICATE-----",
    "SEC_CERT_PEM",
    "-----END CERTIFICATE-----",
    "-----BEGIN TRUSTED CERTIFICATE-----",
    "SEC_TRUSTED_CERT",
    "-----END TRUSTED CERTIFICATE-----",
    "-----BEGIN CERTIFICATE REQUEST-----",
    "CSR_SHOULD_STAY",
    "-----END CERTIFICATE REQUEST-----",
    "ip ssh pubkey-chain",
    " username admin",
    "  key-hash ssh-rsa 0123456789ABCDEF SSH_PUBLIC_FINGERPRINT",
    "crypto pki certificate chain TP",
    " certificate ca 01",
    "  30820314 30820202 A0030201",
    "  02020101 300D0609",
    "        quit",
    " certificate 02 nvram:TP.cer",
    "-----BEGIN RSA PRIVATE KEY-----",
    "SEC_PEM_STILL_A_KEY",
    "-----END RSA PRIVATE KEY-----",
  ].join("\n"));
  assert.doesNotMatch(output, /SEC_CERT_PEM/);
  assert.doesNotMatch(output, /SEC_TRUSTED_CERT/);
  assert.doesNotMatch(output, /30820314/);
  assert.doesNotMatch(output, /02020101/);
  assert.match(output, /^CSR_SHOULD_STAY$/m);
  assert.match(output, /SSH_PUBLIC_FINGERPRINT/);
  assert.match(output, /^ certificate 02 nvram:TP\.cer$/m);
  assert.match(output, /^        quit$/m);
  assert.match(output, /-----BEGIN RSA PRIVATE KEY-----\nREDACTED_\d+\n-----END RSA PRIVATE KEY-----/);
  assert.equal(counts.certificate, 3);
  assert.equal(counts.crypto, 1);
});

test("quoted secrets and CRLF line endings", () => {
  const { output } = redactConfig('tacacs-server key 7 "SEC_QUOTED PHRASE"\r\nhostname x\r\n');
  assert.equal(output, 'tacacs-server key 7 "REDACTED_1"\r\nhostname x\r\n');
});

test("private key blocks collapse to one placeholder", () => {
  for (const kind of ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]) {
    const { output } = redactConfig([
      `-----BEGIN ${kind}-----`,
      "SEC_PEM_BODY",
      `-----END ${kind}-----`,
    ].join("\n"));
    assert.doesNotMatch(output, /SEC_PEM_BODY/);
    assert.match(output, new RegExp(`-----BEGIN ${kind}-----\\nREDACTED_1\\n-----END ${kind}-----`));
  }
});

test("unrecognized config still redacts and says detection was uncertain", () => {
  const input = [
    "!",
    "hostname mystery",
    "enable secret 5 SEC_UNKNOWN",
    "ip access-list extended X",
    " permit ip any any",
  ].join("\n");
  const result = processConfig(input, "auto");
  assert.equal(result.platform, "unknown");
  assert.equal(result.uncertain, true);
  assert.equal(detectPlatform(input).platform, "unknown");
  assert.doesNotMatch(result.output, /SEC_/);
  assert.match(result.output, /^hostname mystery$/m);
  assert.match(result.output, /^ permit ip any any$/m);
  assert.match(result.output, /^enable secret 5 REDACTED_1$/m);
});

test("manual override changes the label only", () => {
  const input = load("ios.cfg");
  const auto = processConfig(input, "auto");
  const forced = processConfig(input, "nxos");
  assert.equal(forced.output, auto.output);
  assert.equal(forced.platform, "nxos");
  assert.equal(forced.uncertain, false);
  assert.deepEqual(forced.counts, auto.counts);
});

test("empty input yields empty output and zero counts", () => {
  const { output, counts } = redactConfig("");
  assert.equal(output, "");
  assert.deepEqual(counts, zero);
});

test("more secret command forms", () => {
  const { output } = redactConfig([
    "ipv6 ospf authentication ipsec spi 256 md5 SEC_V6_OSPF",
    "key config-key password-encrypt SEC_MASTER",
    "area-password text SEC_AREA",
    "lsp-password hmac-md5 SEC_LSP level-1",
    "crypto isakmp key 6 SEC_IKE6 address 10.1.1.1",
    "pre-shared-key SEC_BARE_PSK",
    "snmp-server host 10.1.1.1 SEC_PLAIN_COMM",
  ].join("\n"));
  assert.doesNotMatch(output, /SEC_/);
  assert.match(output, /^ipv6 ospf authentication ipsec spi 256 md5 REDACTED_1$/m);
  assert.match(output, /^key config-key password-encrypt REDACTED_2$/m);
  assert.match(output, /^area-password text REDACTED_3$/m);
  assert.match(output, /^lsp-password hmac-md5 REDACTED_4 level-1$/m);
  assert.match(output, /^crypto isakmp key 6 REDACTED_5 address 10\.1\.1\.1$/m);
  assert.match(output, /^pre-shared-key REDACTED_6$/m);
  assert.match(output, /^snmp-server host 10\.1\.1\.1 REDACTED_7$/m);
});

test("ntp server key ids and snmp v3 host users are not secrets", () => {
  const { output } = redactConfig([
    "ntp server 10.7.7.1 key 1",
    "snmp-server host 10.1.1.1 version 3 priv snmpuser",
    "snmp-server host 10.1.1.1 informs version 2c SEC_INFORM",
  ].join("\n"));
  assert.match(output, /^ntp server 10\.7\.7\.1 key 1$/m);
  assert.match(output, /^snmp-server host 10\.1\.1\.1 version 3 priv snmpuser$/m);
  assert.match(output, /^snmp-server host 10\.1\.1\.1 informs version 2c REDACTED_1$/m);
});

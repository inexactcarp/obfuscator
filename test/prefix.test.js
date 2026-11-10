import assert from "node:assert/strict";
import test from "node:test";
import { applyPrefixes, scanPrefixes } from "../src/prefixes.js";
import { processConfig } from "../src/process.js";

test("scan lists each IPv4 prefix once and ignores non-addresses", () => {
  const prefixes = scanPrefixes([
    "ip address 10.1.4.9 255.255.255.0",
    "ip address 10.1.4.10/24",
    "neighbor 10.10.0.1",
    "permit ip 192.168.1.10 0.0.0.255 any",
    "version 17.9",
    "interface Ethernet1/1",
    "ipv6 address 2001:db8::1/64",
    "value 10.1.1.1.5",
    "skip 10.1.1.256",
  ].join("\n"));
  assert.deepEqual(prefixes, ["0.0", "10.1", "10.10", "192.168", "255.255"]);
});

test("an edited prefix replaces the first two octets and leaves the rest", () => {
  const input = [
    "ip address 10.1.4.9 255.255.255.0",
    "neighbor 10.1.4.10",
    "neighbor 10.10.0.1",
    "neighbor 10.100.0.1",
    "description 10.1 is the site",
  ].join("\n");
  const { text, addressesRewritten } = applyPrefixes(input, {
    "10.1": "x.x",
    "10.10": "10.10",
    "255.255": "   ",
  });
  assert.equal(addressesRewritten, 2);
  assert.equal(text, [
    "ip address x.x.4.9 255.255.255.0",
    "neighbor x.x.4.10",
    "neighbor 10.10.0.1",
    "neighbor 10.100.0.1",
    "description 10.1 is the site",
  ].join("\n"));
});

test("prefix rewrite runs before secret redaction and does not echo the secret", () => {
  const input = [
    "hostname edge",
    "enable secret 0 10.1.8.8",
    "interface GigabitEthernet0/1",
    " ip address 10.1.4.9 255.255.255.0",
  ].join("\n");
  const result = processConfig(input, "auto", { "10.1": "a.b" });
  assert.deepEqual(result.prefixes, ["10.1", "255.255"]);
  assert.equal(result.addressesRewritten, 2);
  assert.match(result.output, /^ ip address a\.b\.4\.9 255\.255\.255\.0$/m);
  assert.match(result.output, /^enable secret 0 REDACTED_1$/m);
  assert.match(result.output, /^hostname edge$/m);
  assert.doesNotMatch(result.output, /10\.1\.8\.8/);
  assert.doesNotMatch(JSON.stringify(result.counts), /10\.1/);
});

test("leaving every prefix unchanged keeps the config text", () => {
  const input = "ip address 10.1.4.9 255.255.255.0\n";
  const same = processConfig(input, "auto");
  const explicit = processConfig(input, "auto", { "10.1": "10.1", "255.255": "255.255" });
  assert.equal(same.output, input);
  assert.equal(explicit.output, input);
  assert.equal(explicit.addressesRewritten, 0);
});

test("a prefix replacement without a dot is ignored", () => {
  const input = "ip address 10.1.4.9 255.255.255.0\n";
  const { text, addressesRewritten } = applyPrefixes(input, { "10.1": "SITEA" });
  assert.equal(addressesRewritten, 0);
  assert.equal(text, input);
});

test("the placeholder stem can be changed and still stays stable", () => {
  const input = "enable secret 0 SEC_A\nline vty 0 4\n password 0 SEC_A\n";
  const result = processConfig(input, "auto", {}, { placeholder: "XXXXX" });
  assert.equal(result.output.split("XXXXX_1").length - 1, 2);
  assert.doesNotMatch(result.output, /REDACTED/);
  assert.doesNotMatch(result.output, /SEC_A/);
});

test("command output and labeled values still lose secrets and can rewrite addresses", () => {
  const input = [
    "edge-sw1#show running-config | include secret",
    "edge-sw1#enable secret 5 SEC_PROMPT",
    "edge-sw1#show ip route",
    "O  10.1.4.9/32 [110/2] via 10.20.1.1",
    "Community name: SEC_COMM",
    "Password: SEC_PASS",
    "description password is not a secret",
    "Nov 10 12:00:01.123: %SYS-5-CONFIG_I: enable secret 0 SEC_LOG",
  ].join("\n");
  const result = processConfig(input, "auto", { "10.1": "x.x", "10.20": "x.x" });
  assert.match(result.output, /^edge-sw1#show running-config \| include secret$/m);
  assert.match(result.output, /^edge-sw1#enable secret 5 REDACTED_\d+$/m);
  assert.match(result.output, /x\.x\.4\.9\/32/);
  assert.match(result.output, /via x\.x\.1\.1/);
  assert.match(result.output, /^Community name: REDACTED_\d+$/m);
  assert.match(result.output, /^Password: REDACTED_\d+$/m);
  assert.match(result.output, /^description password is not a secret$/m);
  assert.match(result.output, /^Nov 10 12:00:01\.123: %SYS-5-CONFIG_I: enable secret 0 REDACTED_\d+$/m);
  assert.doesNotMatch(result.output, /SEC_/);
});

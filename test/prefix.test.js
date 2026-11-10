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
    "10.1": "SITEA",
    "10.10": "10.10",
    "255.255": "   ",
  });
  assert.equal(addressesRewritten, 2);
  assert.equal(text, [
    "ip address SITEA.4.9 255.255.255.0",
    "neighbor SITEA.4.10",
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
  const result = processConfig(input, "auto", { "10.1": "CORP" });
  assert.deepEqual(result.prefixes, ["10.1", "255.255"]);
  assert.equal(result.addressesRewritten, 2);
  assert.match(result.output, /^ ip address CORP\.4\.9 255\.255\.255\.0$/m);
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

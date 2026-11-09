# Config Obfuscator

Redacts secrets from Cisco IOS, IOS-XE, NX-OS, and Arista EOS switch and router configs in the browser. The config is not uploaded and is not stored.

Paste a config or choose a `.cfg`, `.txt`, `.conf`, or similar text file. The tool replaces each secret field with a `REDACTED_N` placeholder. The same secret string in that config always gets the same placeholder, so repeated keys stay recognizable without revealing the value. Numbering starts over on the next run. The summary is counts by category. It never lists the removed values.

Hostnames, usernames, IP addresses, interface names, descriptions, ACLs, VLANs, and routing structure stay. A description or banner is left as written, even if it contains the word "password".

## Run locally

From this directory:

```bash
python3 -m http.server 8080
```

Open http://127.0.0.1:8080

`npm start` does the same thing. Opening `index.html` as a file will not work: the page loads ES modules, and browsers block those on `file://`.

No install step and no network calls from the app. Copy and Download use the obfuscated text only. Clear wipes the page. Nothing is written to `localStorage`.

## Tests

Node.js 18 or newer:

```bash
node --test
```

`npm test` is the same command. Fixtures under `test/fixtures/` are synthetic catalogs, not bootable configs. Every sentinel that starts with `SEC_` must be gone from the output, and every other line must be unchanged.

## What is redacted

| Category | Examples |
| --- | --- |
| Enable password/secret | `enable password` and `enable secret`, including type 0, 4, 5, 7, 8, and 9, with or without `level` |
| Username passwords and secrets | `username ... password\|secret`, NX-OS `password` plus `role`, EOS `secret sha512`, and `aaa root secret` |
| Line passwords | `password` under `line con`, `line console`, `line vty`, and `line aux` |
| SNMP communities and SNMPv3 passphrases | `snmp-server community`, v1/v2c `snmp-server host` communities, and `auth` / `priv` passphrases on `snmp-server user` |
| TACACS and RADIUS keys | `tacacs-server` / `radius-server` keys, `radius server` and `tacacs server` blocks, AAA group `key` and `server-private ... key`, and `server-key` |
| AAA and key-chain keys | `key-string` under `key chain`, and `key config-key password-encrypt` |
| Routing authentication keys | OSPF message-digest and authentication keys, OSPFv3 IPsec keys, BGP `neighbor ... password` (including NX-OS neighbor submode), IS-IS `isis password`, `lsp-password`, `domain-password`, and `area-password`. EIGRP and RIP keys are removed when they are `key-string` values in a key chain |
| NTP authentication keys | `ntp authentication-key`. A trailing type `7` is kept. `ntp server ... key <id>` is an id, not a secret |
| IPsec, IKE, and crypto keys | `crypto isakmp key`, keyring `pre-shared-key`, IKEv2 `pre-shared-key local` / `remote`, PEM private-key blocks, and hex blocks under `crypto key pubkey-chain` |
| Wireless and 802.1X PSKs | `security wpa psk set-key`, `wpa-psk ascii\|hex`, and `password` under `dot1x credentials` |
| Management API secrets | Arista TerminAttr `-cvauth` |

`password encryption aes` and `password strength-check` are commands, not secrets. Public certificates and SSH public key hashes are kept. SNMPv3 usernames on `snmp-server host ... version 3` are kept. `authentication pre-share` (the method name) is kept.

Platform detection is a hint. Auto labels a config as Cisco IOS / IOS-XE, Cisco NX-OS, or Arista EOS when the text looks like that platform. If detection is uncertain, the secret patterns still run. The manual override only changes the label. The same patterns run for every platform.

## Known gaps

- Passwords written into banners, descriptions, remarks, or `!` comments are kept.
- Abbreviated commands (`en sec`, `snmp comm`) are not expanded. Running-config uses full keywords.
- HSRP, VRRP, GLBP, NHRP, LDP, RSVP, and BMP authentication strings are not redacted.
- Secrets inside EEM, Tcl, guestshell, Python, or `alias` lines are not parsed, other than TerminAttr `-cvauth`.
- URL userinfo such as `ftp://user:pass@host` is not redacted.
- A secret that is only a hash algorithm name (`sha512`) and is followed by more tokens can be mis-read as the hash type.
- Public certificate bodies and `ip ssh pubkey-chain` key hashes are intentionally left in place.
- The tool replaces stored hashes. It does not decrypt type 7 or any other encoding, and it does not print the original value to prove a match.

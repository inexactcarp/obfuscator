# Config Obfuscator

A Windows app that redacts secrets from Cisco IOS, IOS-XE, NX-OS, and Arista EOS switch and router configs, command output, and other text. The text stays in the window. Nothing is uploaded or stored.

Paste into the window, or use **Open file**. The file dialog accepts any file type. The tool replaces each secret field with a numbered placeholder. The default is `REDACTED_1`. The placeholder menu also offers `SECRET`, `XXXXX`, and `********`, and Custom shows a box for another stem. The same secret string in that text always gets the same number, so repeated keys stay recognizable without revealing the value. Numbering starts over on the next run. The summary is counts by category. It never lists the removed values.

The window lists every unique IPv4 prefix (the first two octets), including addresses in `show` output and logs. **Set all** writes one replacement onto every prefix. `x.x` is filled in as the example: `10.1.4.9` and `10.20.1.1` both become `x.x.4.9` and `x.x.1.1`. Editing a single row is optional. A replacement must contain a dot; a value without one is left unchanged. A prefix left equal to itself is not changed, so addresses stay put until you edit them. The last two octets stay. The same prefix is rewritten in addresses, ACLs, command output, and banners. Subnet masks and wildcards are dotted quads too, so they show up in the list and stay unless you edit them.

Lines copied from a terminal may start with a prompt such as `edge-sw1#` or a syslog timestamp. Those prefixes are kept, and the command after them is still redacted. Labeled values such as `Password:` and `Community name:` are redacted too. A description, remark, or banner is not treated as a secret.

Hostnames, usernames, interface names, descriptions, ACL structure, VLANs, and routing structure stay. IPv6 addresses are not listed or rewritten.

## Run it

Download [obfuscator.exe](obfuscator.exe). It is one file, with no installer and no extra files. Double-click it. A window opens. It does not open a browser and it does not listen on a network port. Close the window to quit.

**Copy** puts the obfuscated text on the clipboard. **Save** writes that text to a file you choose. **Clear** wipes the window.

## Build

Install Go 1.22 or newer, then from this directory:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui" -o obfuscator.exe .
```

`-H windowsgui` builds a windowed program, so double-clicking it does not open a console.

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
- IPv6 addresses are not scanned or rewritten. Only dotted IPv4 addresses expose their first two octets.

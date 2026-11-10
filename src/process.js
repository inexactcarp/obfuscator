import { detectPlatform, PLATFORM_LABELS } from "./detect.js";
import { applyPrefixes, scanPrefixes } from "./prefixes.js";
import { CATEGORIES, redactConfig } from "./redact.js";

export { CATEGORIES, PLATFORM_LABELS, scanPrefixes };

/**
 * Rewrite selected IPv4 prefixes, then redact secrets.
 * `override` is "auto", "ios", "nxos", or "eos".
 * `replacements` maps a first-two-octet prefix to the string that should
 * replace it. A blank, unchanged, or undotted replacement is ignored.
 * `options.placeholder` sets the token stem. The returned object never
 * includes the secret map or full addresses.
 */
export function processConfig(text, override = "auto", replacements, options = {}) {
  const source = String(text ?? "");
  const detection = detectPlatform(source);
  const useOverride = Boolean(override) && override !== "auto";
  const platform = useOverride ? override : detection.platform;
  const prefixed = applyPrefixes(source, replacements);
  const { output, counts } = redactConfig(prefixed.text, options);
  return {
    output,
    counts,
    detection,
    platform,
    prefixes: scanPrefixes(source),
    addressesRewritten: prefixed.addressesRewritten,
    uncertain: !useOverride && detection.platform === "unknown",
  };
}

import { detectPlatform, PLATFORM_LABELS } from "./detect.js";
import { CATEGORIES, redactConfig } from "./redact.js";

export { CATEGORIES, PLATFORM_LABELS };

/**
 * Redact a config in memory. `override` is "auto", "ios", "nxos", or "eos".
 * The returned object never includes the secret-to-placeholder map.
 */
export function processConfig(text, override = "auto") {
  const source = String(text ?? "");
  const detection = detectPlatform(source);
  const useOverride = Boolean(override) && override !== "auto";
  const platform = useOverride ? override : detection.platform;
  const { output, counts } = redactConfig(source);
  return {
    output,
    counts,
    detection,
    platform,
    uncertain: !useOverride && detection.platform === "unknown",
  };
}

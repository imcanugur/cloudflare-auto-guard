/**
 * Zone Configuration and Parser for Multi-Zone Auto Guard
 */

export interface ZoneConfig {
  id: string;
  name: string;
}

/**
 * Parses zone configurations from the CF_ZONES environment variable.
 * Format: "goto.tc:zone_id_1" OR "goto.tc:zone_id_1 | airisto.ai:zone_id_2 | other.com:zone_id_3"
 */
export function parseZones(rawZones?: string): ZoneConfig[] {
  const zones: ZoneConfig[] = [];
  const seenIds = new Set<string>();

  const addZone = (id: string, name?: string) => {
    const cleanId = id.trim();
    if (!cleanId || seenIds.has(cleanId)) return;
    const cleanName = name ? name.trim() : cleanId;
    zones.push({ id: cleanId, name: cleanName });
    seenIds.add(cleanId);
  };

  if (rawZones && rawZones.trim()) {
    const trimmed = rawZones.trim();
    // Split by pipe '|' (primary), newline, comma, or semicolon
    const items = trimmed.split(/[|\r\n,;]+/).map((s) => s.trim()).filter(Boolean);

    for (const item of items) {
      if (item.includes(":")) {
        const [first, ...rest] = item.split(":");
        const second = rest.join(":").trim();
        // If first is 32-char hex ID, swap so name is domain
        if (/^[a-f0-9]{32}$/i.test(first.trim())) {
          addZone(first, second || first);
        } else {
          // Standard domain:zoneId format (e.g., goto.tc:9e4f77...)
          addZone(second, first);
        }
      } else {
        addZone(item);
      }
    }
  }

  return zones;
}

import { doRangesOverlap, parseAddressToken, parseFirewallAddress, parseTargetRanges } from "./ip-utils";
import type { AddressRef, AddressSetEntry, AnalyzeResult, FirewallVendor, PolicyRule, RangeRecord } from "./types";

type AddressSetMap = Map<string, AddressSetEntry[]>;

interface RawRule {
  ruleName: string;
  sourceZone: string[];
  destinationZone: string[];
  sourceAddresses: string[][];
  destinationAddresses: string[][];
  services: string[];
  action: string;
}

export function analyzeConfig(fileContent: string, targetCIDR: string, vendor: FirewallVendor = "huawei"): AnalyzeResult {
  const targetRanges = parseTargetRanges(targetCIDR);
  const addressSets = parseAddressSets(fileContent, vendor);
  const rawRules = parseSecurityPolicies(fileContent, vendor);

  if (rawRules.length === 0) {
    throw new Error("配置文件格式无法识别，请检查厂商类型是否选择正确");
  }

  const rules = rawRules
    .map((rule) => normalizeRule(rule, addressSets, targetRanges))
    .filter((rule) => rule.sourceAddresses.some((address) => address.matched));

  return {
    success: true,
    totalRules: rawRules.length,
    matchedRules: rules.length,
    rules,
  };
}

function parseAddressSets(content: string, vendor: FirewallVendor): AddressSetMap {
  if (vendor === "h3c") return parseH3cAddressSets(content);
  if (vendor === "dptech") return parseDptechAddressSets(content);
  return parseHuaweiAddressSets(content);
}

function parseHuaweiAddressSets(content: string): AddressSetMap {
  const sets: AddressSetMap = new Map();
  const lines = content.split(/\r?\n/);
  let currentName: string | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const header = line.match(/^ip address-set\s+(\S+)\s+type\s+object/i);

    if (header) {
      currentName = header[1];
      sets.set(currentName, []);
      continue;
    }

    if (line === "#") {
      currentName = null;
      continue;
    }

    if (!currentName || !line.startsWith("address ")) continue;

    const parts = line.split(/\s+/).slice(2);
    addAddressSetEntry(sets, currentName, parts);
  }

  return sets;
}

function parseH3cAddressSets(content: string): AddressSetMap {
  const sets: AddressSetMap = new Map();
  const lines = content.split(/\r?\n/);
  let currentName: string | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const header = line.match(/^object-group\s+ip\s+address\s+(.+)$/i);

    if (header) {
      currentName = header[1].trim();
      sets.set(currentName, []);
      continue;
    }

    if (line === "#") {
      currentName = null;
      continue;
    }

    if (!currentName) continue;
    const parts = line.split(/\s+/);
    if (/^\d+$/.test(parts[0])) {
      addAddressSetEntry(sets, currentName, parts.slice(1));
    }
  }

  return sets;
}

function parseDptechAddressSets(content: string): AddressSetMap {
  const sets: AddressSetMap = new Map();

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("address-object ")) continue;

    const parts = line.split(/\s+/);
    const name = parts[1];
    if (!name || parts[2] === "description") continue;

    try {
      const range = parts[2] === "range" ? parseFirewallAddress(parts.slice(2)) : parseAddressToken(parts[2]);
      if (range) {
        addEntry(sets, name, { value: range.label, range });
      }
    } catch {
      continue;
    }
  }

  return sets;
}

function addAddressSetEntry(sets: AddressSetMap, name: string, parts: string[]): void {
  try {
    const range = parseFirewallAddress(parts);
    if (range) addEntry(sets, name, { value: range.label, range });
  } catch {
    return;
  }
}

function addEntry(sets: AddressSetMap, name: string, entry: AddressSetEntry): void {
  const entries = sets.get(name) ?? [];
  entries.push(entry);
  sets.set(name, entries);
}

function parseSecurityPolicies(content: string, vendor: FirewallVendor): RawRule[] {
  if (vendor === "h3c") return parseH3cSecurityPolicies(content);
  if (vendor === "dptech") return parseDptechSecurityPolicies(content);
  return parseHuaweiSecurityPolicies(content);
}

function parseHuaweiSecurityPolicies(content: string): RawRule[] {
  const lines = content.split(/\r?\n/);
  const rules: RawRule[] = [];
  let inPolicy = false;
  let current: RawRule | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (line === "security-policy") {
      inPolicy = true;
      continue;
    }

    if (!inPolicy) continue;

    const nextTopBlock = rawLine.length > 0 && !rawLine.startsWith(" ") && line !== "#" && line !== "security-policy";
    if (nextTopBlock) break;

    const ruleName = line.match(/^rule name\s+(.+)$/i);
    if (ruleName) {
      if (current) rules.push(current);
      current = createRawRule(ruleName[1]);
      continue;
    }

    if (!current || line === "#") continue;
    applyHuaweiRuleLine(current, line);
  }

  if (current) rules.push(current);
  return rules;
}

function parseH3cSecurityPolicies(content: string): RawRule[] {
  const lines = content.split(/\r?\n/);
  const rules: RawRule[] = [];
  let inPolicy = false;
  let current: RawRule | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (line === "security-policy ip") {
      inPolicy = true;
      continue;
    }

    if (!inPolicy) continue;

    if (line === "#") continue;
    if (rawLine.length > 0 && !rawLine.startsWith(" ") && !line.startsWith("rule ")) break;

    const rule = line.match(/^rule\s+(\S+)\s+name\s+(.+)$/i);
    if (rule) {
      if (current) rules.push(current);
      current = createRawRule(rule[2]);
      continue;
    }

    if (!current) continue;
    applyH3cRuleLine(current, line);
  }

  if (current) rules.push(current);
  return rules;
}

function parseDptechSecurityPolicies(content: string): RawRule[] {
  const rules = new Map<string, RawRule>();

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("security-policy ") || line.includes(" acceleration ")) continue;

    const parts = line.split(/\s+/);
    const ruleName = parts[1];
    if (!ruleName) continue;

    const rule = rules.get(ruleName) ?? createRawRule(ruleName);
    applyDptechRuleParts(rule, parts.slice(2));
    rules.set(ruleName, rule);
  }

  return Array.from(rules.values());
}

function createRawRule(ruleName: string): RawRule {
  return {
    ruleName,
    sourceZone: [],
    destinationZone: [],
    sourceAddresses: [],
    destinationAddresses: [],
    services: [],
    action: "",
  };
}

function applyHuaweiRuleLine(rule: RawRule, line: string): void {
  const [key, ...rest] = line.split(/\s+/);
  if (key === "source-zone") rule.sourceZone.push(rest.join(" "));
  if (key === "destination-zone") rule.destinationZone.push(rest.join(" "));
  if (key === "source-address") rule.sourceAddresses.push(rest);
  if (key === "destination-address") rule.destinationAddresses.push(rest);
  if (key === "service") rule.services.push(rest.join(" "));
  if (key === "action") rule.action = rest.join(" ");
}

function applyH3cRuleLine(rule: RawRule, line: string): void {
  const [key, ...rest] = line.split(/\s+/);
  if (key === "source-zone") rule.sourceZone.push(rest.join(" "));
  if (key === "destination-zone") rule.destinationZone.push(rest.join(" "));
  if (key === "source-ip") rule.sourceAddresses.push(["address-set", rest.join(" ")]);
  if (key === "destination-ip") rule.destinationAddresses.push(["address-set", rest.join(" ")]);
  if (key === "source-ip-host") rule.sourceAddresses.push([rest[0]]);
  if (key === "destination-ip-host") rule.destinationAddresses.push([rest[0]]);
  if (key === "source-ip-subnet") rule.sourceAddresses.push([rest[0], "mask", rest[1]]);
  if (key === "destination-ip-subnet") rule.destinationAddresses.push([rest[0], "mask", rest[1]]);
  if (key === "service" || key === "service-port") rule.services.push(rest.join(" "));
  if (key === "action") rule.action = rest.join(" ");
}

function applyDptechRuleParts(rule: RawRule, parts: string[]): void {
  const keys = new Set(["src-zone", "dst-zone", "src-address", "dst-address", "service", "action"]);
  let index = 0;

  while (index < parts.length) {
    const key = parts[index];
    index += 1;

    if (key === "src-zone" && parts[index]) {
      rule.sourceZone.push(parts[index]);
      index += 1;
      continue;
    }

    if (key === "dst-zone" && parts[index]) {
      rule.destinationZone.push(parts[index]);
      index += 1;
      continue;
    }

    if ((key === "src-address" || key === "dst-address") && parts[index]) {
      const { address, nextIndex } = readDptechAddress(parts, index);
      if (key === "src-address") rule.sourceAddresses.push(address);
      if (key === "dst-address") rule.destinationAddresses.push(address);
      index = nextIndex;
      continue;
    }

    if (key === "service") {
      const values: string[] = [];
      while (index < parts.length && !keys.has(parts[index])) {
        values.push(parts[index]);
        index += 1;
      }
      rule.services.push(values.join(" "));
      continue;
    }

    if (key === "action") {
      rule.action = parts[index] ?? "";
      index += 1;
      continue;
    }

    while (index < parts.length && !keys.has(parts[index])) {
      index += 1;
    }
  }
}

function readDptechAddress(parts: string[], index: number): { address: string[]; nextIndex: number } {
  if (parts[index] === "address-object" && parts[index + 1]) {
    return { address: ["address-set", parts[index + 1]], nextIndex: index + 2 };
  }
  if (parts[index] === "any") {
    return { address: ["any"], nextIndex: index + 1 };
  }
  return { address: [parts[index]], nextIndex: index + 1 };
}

function normalizeRule(rule: RawRule, addressSets: AddressSetMap, targetRanges: RangeRecord[]): PolicyRule {
  const sourceAddresses = resolveAddresses(rule.sourceAddresses, addressSets, targetRanges, true);
  const destinationAddresses = resolveAddresses(rule.destinationAddresses, addressSets, targetRanges, false);

  return {
    ruleName: rule.ruleName,
    sourceZone: unique(rule.sourceZone).join(", ") || "any",
    destinationZone: unique(rule.destinationZone).join(", ") || "any",
    sourceAddresses,
    destinationAddresses,
    service: unique(rule.services).join(", ") || "any",
    action: rule.action || "unknown",
  };
}

function resolveAddresses(
  rawAddresses: string[][],
  addressSets: AddressSetMap,
  targetRanges: RangeRecord[],
  shouldMatch: boolean,
): AddressRef[] {
  if (rawAddresses.length === 0) {
    const matched = shouldMatch;
    return [{ type: "direct", value: "any", matched }];
  }

  return rawAddresses.map((parts) => {
    if (parts[0] === "any") {
      return { type: "direct", value: "any", matched: shouldMatch };
    }

    if (parts[0] === "address-set" && parts[1]) {
      const name = parts.slice(1).join(" ");
      const entries = addressSets.get(name) ?? [];
      if (entries.length === 0) {
        const direct = parseAddressToken(name);
        if (direct) {
          return { type: "direct", value: direct.label, matched: shouldMatch && matchesAnyTarget(direct, targetRanges) };
        }
      }

      const expanded = entries.map((entry) => ({
        value: entry.value,
        matched: shouldMatch ? matchesAnyTarget(entry.range, targetRanges) : false,
      }));

      return {
        type: "address-set",
        name,
        expanded,
        matched: expanded.some((entry) => entry.matched),
      };
    }

    try {
      const range = parts.length === 1 ? parseAddressToken(parts[0]) : parseFirewallAddress(parts);
      const matched = shouldMatch && !!range && matchesAnyTarget(range, targetRanges);
      return { type: "direct", value: range?.label ?? parts.join(" "), matched };
    } catch {
      return { type: "direct", value: parts.join(" "), matched: false };
    }
  });
}

function matchesAnyTarget(range: RangeRecord, targetRanges: RangeRecord[]): boolean {
  return targetRanges.some((targetRange) => doRangesOverlap(range, targetRange));
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

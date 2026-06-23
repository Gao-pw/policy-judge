import { doRangesOverlap, parseFirewallAddress, parseTargetRanges } from "./ip-utils";
import type { AddressRef, AddressSetEntry, AnalyzeResult, PolicyRule, RangeRecord } from "./types";

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

export function analyzeConfig(fileContent: string, targetCIDR: string): AnalyzeResult {
  const targetRanges = parseTargetRanges(targetCIDR);
  const addressSets = parseAddressSets(fileContent);
  const rawRules = parseSecurityPolicies(fileContent);

  if (rawRules.length === 0) {
    throw new Error("配置文件格式无法识别，请检查是否为华为防火墙配置");
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

function parseAddressSets(content: string): AddressSetMap {
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

    if (!currentName || !line.startsWith("address ")) {
      continue;
    }

    const parts = line.split(/\s+/).slice(2);
    try {
      const range = parseFirewallAddress(parts);
      if (range) {
        sets.get(currentName)?.push({ value: range.label, range });
      }
    } catch {
      continue;
    }
  }

  return sets;
}

function parseSecurityPolicies(content: string): RawRule[] {
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
    if (nextTopBlock) {
      break;
    }

    const ruleName = line.match(/^rule name\s+(.+)$/i);
    if (ruleName) {
      if (current) rules.push(current);
      current = createRawRule(ruleName[1]);
      continue;
    }

    if (!current || line === "#") continue;

    const [key, ...rest] = line.split(/\s+/);
    if (key === "source-zone") current.sourceZone.push(rest.join(" "));
    if (key === "destination-zone") current.destinationZone.push(rest.join(" "));
    if (key === "source-address") current.sourceAddresses.push(rest);
    if (key === "destination-address") current.destinationAddresses.push(rest);
    if (key === "service") current.services.push(rest.join(" "));
    if (key === "action") current.action = rest.join(" ");
  }

  if (current) rules.push(current);
  return rules;
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

function normalizeRule(rule: RawRule, addressSets: AddressSetMap, targetRanges: RangeRecord[]): PolicyRule {
  const sourceAddresses = resolveAddresses(rule.sourceAddresses, addressSets, targetRanges, true);
  const destinationAddresses = resolveAddresses(rule.destinationAddresses, addressSets, targetRanges, false);

  return {
    ruleName: rule.ruleName,
    sourceZone: rule.sourceZone.join(", ") || "any",
    destinationZone: rule.destinationZone.join(", ") || "any",
    sourceAddresses,
    destinationAddresses,
    service: rule.services.join(", ") || "any",
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
    if (parts[0] === "address-set" && parts[1]) {
      const entries = addressSets.get(parts[1]) ?? [];
      const expanded = entries.map((entry) => ({
        value: entry.value,
        matched: shouldMatch ? matchesAnyTarget(entry.range, targetRanges) : false,
      }));

      return {
        type: "address-set",
        name: parts[1],
        expanded,
        matched: expanded.some((entry) => entry.matched),
      };
    }

    try {
      const range = parseFirewallAddress(parts);
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

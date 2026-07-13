import { doRangesOverlap, isRangeCoveredBy, parseAddressToken, parseFirewallAddress, parseTargetRanges } from "./ip-utils";
import type {
  AddressRef,
  AddressSetEntry,
  AnalyzeResult,
  FirewallVendor,
  PolicyQuery,
  PolicyRule,
  QueryMatchDetail,
  QueryResult,
  QueryResultRule,
  RangeRecord,
} from "./types";

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
    mode: "filter",
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
    const header = line.match(/^ip\s+address-set\s+(\S+)\s+type\s+object/i);

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

/**
 * 解析华三对象组地址定义
 *
 * 华三格式：
 *   object-group ip address 10.124.150.229-230
 *    security-zone Untrust
 *    0 network host address 10.124.150.229
 *    0 network subnet 0.0.0.0 wildcard 255.255.255.0
 *    0 network range 10.124.150.229 10.124.150.230
 *   #
 *
 * 头部提取对象名称，只处理开头是数字序号的 network 行，忽略 security-zone 等描述行
 */
function parseH3cAddressSets(content: string): AddressSetMap {
  const sets: AddressSetMap = new Map();
  const lines = content.split(/\r?\n/);
  let currentName: string | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const header = line.match(/^object-group\s+ip\s+address\s+(.+)$/i);

    if (header) {
      // 遇到新的对象组，初始化 Map 条目
      currentName = header[1].trim();
      sets.set(currentName, []);
      continue;
    }

    if (line === "#") {
      // # 表示当前对象组结束
      currentName = null;
      continue;
    }

    if (!currentName) continue;
    const parts = line.split(/\s+/);
    // 华三对象组内的行以数字序号开头：0 / 5 / 10
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

    if (line === "#") {
      if (current) rules.push(current);
      current = null;
      continue;
    }

    const nextTopBlock = rawLine.length > 0 && !rawLine.startsWith(" ") && line !== "#" && line !== "security-policy";
    if (nextTopBlock) break;

    const ruleName = line.match(/^rule\s+name\s+(.+)$/i);
    if (ruleName) {
      if (current) rules.push(current);
      current = createRawRule(ruleName[1]);
      continue;
    }

    if (!current) continue;
    applyHuaweiRuleLine(current, line);
  }

  if (current) rules.push(current);
  return rules;
}

/**
 * 解析华三安全策略
 *
 * 华三格式：
 *   security-policy ip
 *    rule 635 name ICMP
 *     action pass
 *     source-zone Untrust
 *     destination-zone Trust
 *     source-ip 10.124.150.229 255.255.255.255
 *     service ICMP
 *    rule 636 name net_mgt
 *     ...
 *
 * 必须在 security-policy ip 块内逐行提取规则名和属性
 */
function parseH3cSecurityPolicies(content: string): RawRule[] {
  const lines = content.split(/\r?\n/);
  const rules: RawRule[] = [];
  let inPolicy = false;
  let current: RawRule | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (line === "security-policy ip") {
      // 进入策略块，开始解析
      inPolicy = true;
      continue;
    }

    if (!inPolicy) continue;

    if (line === "#") continue;
    // 遇到无缩进的非 rule 行表示策略块结束，跳出循环
    if (rawLine.length > 0 && !rawLine.startsWith(" ") && !line.startsWith("rule ")) break;

    const rule = line.match(/^rule\s+(\S+)\s+name\s+(.+)$/i);
    if (rule) {
      // 遇到新规则，先把上一条规则保存，再初始化新规则
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

/**
 * 解析华三单条策略属性行
 *
 * 华三支持多种地址格式：
 *   source-zone Untrust
 *   source-ip 10.124.150.229       → 引用对象组
 *   source-ip-host 10.124.150.229  → 主机地址
 *   source-ip-subnet 10.124.0.0 255.255.0.0  → 子网地址
 *   service ICMP / service-port 22
 *   action pass
 */
function applyH3cRuleLine(rule: RawRule, line: string): void {
  const [key, ...rest] = line.split(/\s+/);
  if (key === "source-zone") rule.sourceZone.push(rest.join(" "));
  if (key === "destination-zone") rule.destinationZone.push(rest.join(" "));
  // 引用对象组：转换成 address-set 格式
  if (key === "source-ip") rule.sourceAddresses.push(["address-set", rest.join(" ")]);
  if (key === "destination-ip") rule.destinationAddresses.push(["address-set", rest.join(" ")]);
  // 主机地址：直接存 IP
  if (key === "source-ip-host") rule.sourceAddresses.push([rest[0]]);
  if (key === "destination-ip-host") rule.destinationAddresses.push([rest[0]]);
  // 子网地址：转换成 mask 格式供解析
  if (key === "source-ip-subnet") rule.sourceAddresses.push([rest[0], "mask", rest[1]]);
  if (key === "destination-ip-subnet") rule.destinationAddresses.push([rest[0], "mask", rest[1]]);
  if (key === "service" || key === "service-port") rule.services.push(rest.join(" "));
  if (key === "action") rule.action = rest.join(" ");
}

/**
 * 解析迪普策略行的多个字段
 * 迪普格式：security-policy 规则名 src-zone Trust dst-zone Untrust src-address address-object xxxx service ... action permit
 * 整行拆成 parts 数组后，各字段交错出现，需要用指针逐个解析
 *
 * @param rule   正在填充的策略对象
 * @param parts  已去掉 security-policy 规则名之后的剩余 token 数组
 */
function applyDptechRuleParts(rule: RawRule, parts: string[]): void {
  // 迪普策略里的字段关键字集合，用来判断下一个 token 是不是新字段
  const keys = new Set(["src-zone", "dst-zone", "src-address", "dst-address", "service", "action"]);
  // 当前解析位置指针，从第一个 token 开始
  let index = 0;

  // 遍历所有 token，直到解析完
  while (index < parts.length) {
    const key = parts[index];
    index += 1;

    // 源域：src-zone 后面跟一个 zone 名称
    if (key === "src-zone" && parts[index]) {
      rule.sourceZone.push(parts[index]);
      index += 1;
      continue;
    }

    // 目的域：dst-zone 后面跟一个 zone 名称
    if (key === "dst-zone" && parts[index]) {
      rule.destinationZone.push(parts[index]);
      index += 1;
      continue;
    }

    // 源/目的地址：可能是 address-object 名称、any 或直接 IP
    // 用 readDptechAddress 读取地址，返回解析后的地址数组和新的指针位置
    if ((key === "src-address" || key === "dst-address") && parts[index]) {
      const { address, nextIndex } = readDptechAddress(parts, index);
      if (key === "src-address") rule.sourceAddresses.push(address);
      if (key === "dst-address") rule.destinationAddresses.push(address);
      index = nextIndex;
      continue;
    }

    // 服务：service 后面可能跟多个值（service-object xxxx service-object yyyy）
    // 连续读直到遇到下一个字段关键字为止
    if (key === "service") {
      const values: string[] = [];
      while (index < parts.length && !keys.has(parts[index])) {
        values.push(parts[index]);
        index += 1;
      }
      rule.services.push(values.join(" "));
      continue;
    }

    // 动作：action 后面跟 permit/deny
    if (key === "action") {
      rule.action = parts[index] ?? "";
      index += 1;
      continue;
    }

    // 不认识的字段，跳过直到遇到下一个关键字
    while (index < parts.length && !keys.has(parts[index])) {
      index += 1;
    }
  }
}

/**
 * 读取迪普地址定义
 * 支持三种格式：
 *   1. address-object 名称 → 返回 ["address-set", 名称]
 *   2. any             → 返回 ["any"]
 *   3. 10.1.1.1        → 返回 [IP]
 *
 * @param parts 当前行拆分后的 token 数组
 * @param index 地址字段起始位置（src-address/dst-address 后面的第一个 token）
 * @returns     解析后的地址数组和新的指针位置
 */
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
        matched: shouldMatch && matchesAnyTarget(entry.range, targetRanges),
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

/* ======================= 五元组查询 ======================= */

const PORT_MIN = 0;
const PORT_MAX = 65535;

/** 服务定义中的单条端口/协议条目 */
interface ServiceEntry {
  protocol: string; // tcp / udp / icmp / ip / any
  srcPort: RangeRecord;
  dstPort: RangeRecord;
}

type ServiceMap = Map<string, ServiceEntry[]>;

/** 常见预定义服务名到端口的映射（配置里未显式定义时兜底） */
const WELL_KNOWN_SERVICES: Record<string, ServiceEntry> = {
  ftp: makeService("tcp", 21),
  ssh: makeService("tcp", 22),
  telnet: makeService("tcp", 23),
  dns: makeService("udp", 53),
  http: makeService("tcp", 80),
  https: makeService("tcp", 443),
};

function makeService(protocol: string, port: number): ServiceEntry {
  return { protocol, srcPort: fullPort(), dstPort: portRange(port, port) };
}

function fullPort(): RangeRecord {
  return { start: PORT_MIN, end: PORT_MAX, label: "any" };
}

function portRange(start: number, end: number): RangeRecord {
  return { start, end, label: start === end ? `${start}` : `${start}-${end}` };
}

/**
 * 按查询条件搜索可覆盖需求的安全策略
 *
 * 覆盖语义：策略的源/目的区域、源/目的地址、服务端口范围都必须包含查询需求，
 * 查询条件留空的维度视为不限制（自动满足）。放行与拒绝策略都会返回并标注动作。
 */
export function queryPolicies(fileContent: string, query: PolicyQuery, vendor: FirewallVendor = "huawei"): QueryResult {
  const addressSets = parseAddressSets(fileContent, vendor);
  const serviceMap = parseServiceSets(fileContent, vendor);
  const rawRules = parseSecurityPolicies(fileContent, vendor);

  if (rawRules.length === 0) {
    throw new Error("配置文件格式无法识别，请检查厂商类型是否选择正确");
  }

  // 预解析查询条件
  const queryZoneSrc = query.sourceZone.trim().toLowerCase();
  const queryZoneDst = query.destinationZone.trim().toLowerCase();
  const querySrcRanges = query.sourceAddress.trim() ? parseTargetRanges(query.sourceAddress) : [];
  const queryDstRanges = query.destinationAddress.trim() ? parseTargetRanges(query.destinationAddress) : [];
  const querySrcPorts = parsePortQuery(query.sourcePort);
  const queryDstPorts = parsePortQuery(query.destinationPort);

  const rules: QueryResultRule[] = [];

  for (const raw of rawRules) {
    const detail: QueryMatchDetail = {
      sourceZone: isZoneCovered(queryZoneSrc, raw.sourceZone),
      destinationZone: isZoneCovered(queryZoneDst, raw.destinationZone),
      sourceAddress: isAddressCovered(querySrcRanges, raw.sourceAddresses, addressSets),
      destinationAddress: isAddressCovered(queryDstRanges, raw.destinationAddresses, addressSets),
      service: isServiceCovered(query, querySrcPorts, queryDstPorts, raw.services, serviceMap),
    };

    const fullyCovered =
      detail.sourceZone && detail.destinationZone && detail.sourceAddress && detail.destinationAddress && detail.service;

    if (!fullyCovered) continue;

    const normalized = normalizeRule(raw, addressSets, []);
    rules.push({ ...normalized, fullyCovered, detail });
  }

  return {
    success: true,
    mode: "query",
    totalRules: rawRules.length,
    matchedRules: rules.length,
    rules,
  };
}

/** 区域覆盖：查询留空、或策略未限制区域、或策略区域包含查询区域时命中 */
function isZoneCovered(queryZone: string, ruleZones: string[]): boolean {
  if (!queryZone) return true;
  if (ruleZones.length === 0) return true;
  return ruleZones.some((zone) => zone.toLowerCase() === queryZone);
}

/** 地址覆盖：查询留空、或策略地址为 any、或策略地址并集完全包含查询的每个地址范围 */
function isAddressCovered(queryRanges: RangeRecord[], rawAddresses: string[][], addressSets: AddressSetMap): boolean {
  if (queryRanges.length === 0) return true;

  const resolved = resolveAddressRanges(rawAddresses, addressSets);
  if (resolved.any) return true;
  if (resolved.ranges.length === 0) return false;

  return queryRanges.every((range) => isRangeCoveredBy(range, resolved.ranges));
}

/** 把策略里的原始地址解析为 IP 区间集合，any 表示不限制 */
function resolveAddressRanges(rawAddresses: string[][], addressSets: AddressSetMap): { any: boolean; ranges: RangeRecord[] } {
  if (rawAddresses.length === 0) return { any: true, ranges: [] };

  const ranges: RangeRecord[] = [];

  for (const parts of rawAddresses) {
    if (parts[0] === "any") return { any: true, ranges: [] };

    if (parts[0] === "address-set" && parts[1]) {
      const name = parts.slice(1).join(" ");
      const entries = addressSets.get(name) ?? [];
      if (entries.length === 0) {
        const direct = safeParse(() => parseAddressToken(name));
        if (direct) ranges.push(direct);
      } else {
        entries.forEach((entry) => ranges.push(entry.range));
      }
      continue;
    }

    const range = safeParse(() => (parts.length === 1 ? parseAddressToken(parts[0]) : parseFirewallAddress(parts)));
    if (range) ranges.push(range);
  }

  return { any: false, ranges };
}

/** 服务覆盖：查询未限制协议和端口时直接命中，否则要求策略服务端口范围覆盖查询 */
function isServiceCovered(
  query: PolicyQuery,
  querySrcPorts: RangeRecord[],
  queryDstPorts: RangeRecord[],
  ruleServices: string[],
  serviceMap: ServiceMap,
): boolean {
  const noProtocol = query.protocol === "any";
  if (noProtocol && querySrcPorts.length === 0 && queryDstPorts.length === 0) return true;

  // 策略无服务字段视为 any，覆盖一切
  if (ruleServices.length === 0) return true;

  const entries = resolveServiceEntries(ruleServices, serviceMap);
  if (entries.length === 0) return false;

  const relevant = entries.filter((entry) => matchProtocol(entry.protocol, query.protocol));
  if (relevant.length === 0) return false;

  if (queryDstPorts.length > 0) {
    const dstRanges = relevant.map((entry) => entry.dstPort);
    if (!queryDstPorts.every((range) => isRangeCoveredBy(range, dstRanges))) return false;
  }

  if (querySrcPorts.length > 0) {
    const srcRanges = relevant.map((entry) => entry.srcPort);
    if (!querySrcPorts.every((range) => isRangeCoveredBy(range, srcRanges))) return false;
  }

  return true;
}

function matchProtocol(entryProtocol: string, queryProtocol: string): boolean {
  if (entryProtocol === "ip" || entryProtocol === "any") return true;
  if (queryProtocol === "any") return true;
  return entryProtocol === queryProtocol;
}

/** 把策略引用的服务名解析成端口条目 */
function resolveServiceEntries(ruleServices: string[], serviceMap: ServiceMap): ServiceEntry[] {
  const result: ServiceEntry[] = [];

  for (const raw of ruleServices) {
    // 迪普格式：service-object 名称
    const name = raw.replace(/^service-object\s+/i, "").trim();
    const entries = serviceMap.get(name) ?? serviceMap.get(raw.trim());
    if (entries && entries.length > 0) {
      result.push(...entries);
      continue;
    }

    const known = WELL_KNOWN_SERVICES[name.toLowerCase()];
    if (known) result.push(known);
  }

  return result;
}

/** 解析查询里的端口输入，支持 "80"、"80-90"、"80,443" */
function parsePortQuery(text: string): RangeRecord[] {
  const trimmed = text.trim();
  if (!trimmed) return [];

  const ranges: RangeRecord[] = [];
  for (const part of trimmed.split(/\s*,\s*/).filter(Boolean)) {
    const rangeMatch = part.match(/^(\d+)\s*-\s*(\d+)$/);
    if (rangeMatch) {
      ranges.push(portRange(Number(rangeMatch[1]), Number(rangeMatch[2])));
      continue;
    }
    if (/^\d+$/.test(part)) {
      ranges.push(portRange(Number(part), Number(part)));
    }
  }

  return ranges;
}

function safeParse(fn: () => RangeRecord | null): RangeRecord | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

/* ======================= 服务定义解析 ======================= */

function parseServiceSets(content: string, vendor: FirewallVendor): ServiceMap {
  if (vendor === "h3c") return parseH3cServiceSets(content);
  if (vendor === "dptech") return parseDptechServiceSets(content);
  return parseHuaweiServiceSets(content);
}

/**
 * 华为服务集
 *   ip service-set BJlianb type object
 *    service 0 protocol tcp destination-port 22
 *    service 3 protocol tcp destination-port 1803 to 1893
 */
function parseHuaweiServiceSets(content: string): ServiceMap {
  const map: ServiceMap = new Map();
  let currentName: string | null = null;

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = line.match(/^ip\s+service-set\s+(\S+)\s+type\s+object/i);

    if (header) {
      currentName = header[1];
      map.set(currentName, []);
      continue;
    }

    if (line === "#") {
      currentName = null;
      continue;
    }

    if (!currentName || !line.startsWith("service ")) continue;

    const protocolMatch = line.match(/protocol\s+(\S+)/i);
    if (!protocolMatch) continue;
    const protocol = protocolMatch[1].toLowerCase();

    const entry: ServiceEntry = {
      protocol,
      srcPort: parsePortClause(line, "source-port") ?? fullPort(),
      dstPort: parsePortClause(line, "destination-port") ?? fullPort(),
    };
    map.get(currentName)!.push(entry);
  }

  return map;
}

/** 解析华为 "destination-port 3300 to 3330" / "source-port 22" 端口子句 */
function parsePortClause(line: string, keyword: string): RangeRecord | null {
  const range = line.match(new RegExp(`${keyword}\\s+(\\d+)\\s+to\\s+(\\d+)`, "i"));
  if (range) return portRange(Number(range[1]), Number(range[2]));
  const single = line.match(new RegExp(`${keyword}\\s+(\\d+)`, "i"));
  if (single) return portRange(Number(single[1]), Number(single[1]));
  return null;
}

/**
 * 华三服务组
 *   object-group service dst_yinhangyunhua
 *    0 service tcp destination range 18070 18071
 *    1 service tcp destination eq 25406
 *    0 service tcp destination gt 1024
 *    0 service icmp
 */
function parseH3cServiceSets(content: string): ServiceMap {
  const map: ServiceMap = new Map();
  let currentName: string | null = null;

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const header = line.match(/^object-group\s+service\s+(.+)$/i);

    if (header) {
      currentName = stripQuotes(header[1].trim());
      map.set(currentName, []);
      continue;
    }

    if (line === "#") {
      currentName = null;
      continue;
    }

    if (!currentName) continue;
    const parts = line.split(/\s+/);
    if (!/^\d+$/.test(parts[0]) || parts[1] !== "service") continue;

    const protocol = parts[2]?.toLowerCase();
    if (!protocol) continue;

    const entry: ServiceEntry = {
      protocol,
      srcPort: parseH3cPortOperator(parts, "source") ?? fullPort(),
      dstPort: parseH3cPortOperator(parts, "destination") ?? fullPort(),
    };
    map.get(currentName)!.push(entry);
  }

  return map;
}

/** 解析华三 "destination eq 22" / "destination range 18070 18071" / "destination gt 1024" */
function parseH3cPortOperator(parts: string[], direction: string): RangeRecord | null {
  const index = parts.indexOf(direction);
  if (index < 0) return null;

  const operator = parts[index + 1];
  const value = Number(parts[index + 2]);

  if (operator === "eq") return portRange(value, value);
  if (operator === "gt") return portRange(value + 1, PORT_MAX);
  if (operator === "lt") return portRange(PORT_MIN, value - 1);
  if (operator === "range") return portRange(value, Number(parts[index + 3]));
  return null;
}

/**
 * 迪普服务对象
 *   service-object TCP80 protocol tcp src-port 0 to 65535 dst-port 80 to 80
 */
function parseDptechServiceSets(content: string): ServiceMap {
  const map: ServiceMap = new Map();

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("service-object ")) continue;

    const parts = line.split(/\s+/);
    const name = parts[1];
    const protocolMatch = line.match(/protocol\s+(\S+)/i);
    if (!name || !protocolMatch) continue;

    const entry: ServiceEntry = {
      protocol: protocolMatch[1].toLowerCase(),
      srcPort: parseDptechPort(line, "src-port") ?? fullPort(),
      dstPort: parseDptechPort(line, "dst-port") ?? fullPort(),
    };

    const entries = map.get(name) ?? [];
    entries.push(entry);
    map.set(name, entries);
  }

  return map;
}

/** 解析迪普 "dst-port 80 to 80" / "src-port 0 to 65535" */
function parseDptechPort(line: string, keyword: string): RangeRecord | null {
  const match = line.match(new RegExp(`${keyword}\\s+(\\d+)\\s+to\\s+(\\d+)`, "i"));
  if (match) return portRange(Number(match[1]), Number(match[2]));
  return null;
}

function stripQuotes(value: string): string {
  return value.replace(/^"(.*)"$/, "$1");
}

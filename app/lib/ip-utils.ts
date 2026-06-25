import { Address4 } from "ip-address";

const IPV4_MAX = 0xffffffff;

export function parseTargetRanges(target: string): RangeRecord[] {
  return target
    .split(/\s*,\s*/)
    .filter(Boolean)
    .map((item) => {
      const trimmed = item.trim();
      if (trimmed.includes("-")) {
        const [start, end] = trimmed.split("-").map((part) => part.trim());
        return rangeFromIps(start, end, trimmed);
      }
      if (trimmed.includes("/")) {
        return cidrToRange(trimmed);
      }
      return cidrToRange(`${trimmed}/32`);
    });
}

export function isValidTargetRange(target: string): boolean {
  try {
    parseTargetRanges(target);
    return true;
  } catch {
    return false;
  }
}

export function parseFirewallAddress(parts: string[]): RangeRecord | null {
  if (parts[0] === "range" && parts[1] && parts[2]) {
    return rangeFromIps(parts[1], parts[2], `${parts[1]}-${parts[2]}`);
  }

  if (parts[0] === "network") {
    return parseH3cObjectAddress(parts.slice(1));
  }

  const ip = parts[0];
  if (!ip) return null;

  if (parts[1] === "mask" && parts[2]) {
    const prefix = maskToPrefix(parts[2]);
    return cidrToRange(`${ip}/${prefix}`);
  }

  if (parts[1] === "wildcard" && parts[2]) {
    const prefix = wildcardToPrefix(parts[2]);
    return cidrToRange(`${ip}/${prefix}`);
  }

  if (parts[1] && isIPv4(parts[1])) {
    const prefix = wildcardToPrefix(parts[1]);
    return cidrToRange(`${ip}/${prefix}`);
  }

  if (ip.includes("/")) {
    return cidrToRange(ip);
  }

  const value = ipToNumber(ip);
  return { start: value, end: value, label: `${ip}/32` };
}

export function parseAddressToken(value: string): RangeRecord | null {
  const text = value.trim();
  if (!text || text === "any") return null;

  const dashIndex = text.indexOf("-");
  if (dashIndex > 0) {
    const start = text.slice(0, dashIndex).trim();
    const endOrSuffix = text.slice(dashIndex + 1).trim();
    const end = endOrSuffix.match(/^\d+$/) && start.includes(".") ? `${start.substring(0, start.lastIndexOf(".") + 1)}${endOrSuffix}` : endOrSuffix;

    if (isIPv4(start) && isIPv4(end)) return rangeFromIps(start, end, text);
  }

  if (text.includes("/")) return cidrToRange(text);
  if (isIPv4(text)) return parseFirewallAddress([text]);
  return null;
}

export function doRangesOverlap(a: RangeRecord, b: RangeRecord): boolean {
  return a.start <= b.end && b.start <= a.end;
}

function parseH3cObjectAddress(parts: string[]): RangeRecord | null {
  if (parts[0] === "host" && parts[1] === "address" && parts[2]) {
    return parseFirewallAddress([parts[2]]);
  }
  if (parts[0] === "range" && parts[1] && parts[2]) {
    return rangeFromIps(parts[1], parts[2], `${parts[1]}-${parts[2]}`);
  }
  if (parts[0] === "subnet" && parts[1] && parts[2]) {
    const prefix = maskToPrefix(parts[2]);
    return cidrToRange(`${parts[1]}/${prefix}`);
  }
  return null;
}

function cidrToRange(cidr: string): RangeRecord {
  const slashIndex = cidr.indexOf("/");
  if (slashIndex > 0 && cidr.substring(slashIndex + 1).includes(".")) {
    const mask = cidr.substring(slashIndex + 1);
    const prefix = maskToPrefix(mask);
    return cidrToRange(`${cidr.substring(0, slashIndex)}/${prefix}`);
  }

  if (!Address4.isValid(cidr)) {
    throw new Error(`invalid cidr: ${cidr}`);
  }
  const address = new Address4(cidr);

  return {
    start: addressToNumber(address.startAddress()),
    end: addressToNumber(address.endAddress()),
    label: cidr,
  };
}

function rangeFromIps(startIp: string, endIp: string, label: string): RangeRecord {
  const start = ipToNumber(startIp);
  const end = ipToNumber(endIp);
  if (start > end) {
    throw new Error("invalid range");
  }
  return { start, end, label };
}

function ipToNumber(ip: string): number {
  if (!isIPv4(ip)) {
    throw new Error("invalid ip");
  }
  return addressToNumber(new Address4(ip));
}

function addressToNumber(address: Address4): number {
  return Number(address.bigInteger().toString());
}

function isIPv4(value: string): boolean {
  return Address4.isValid(value);
}

function maskToPrefix(mask: string): number {
  const value = ipToNumber(mask);
  let prefix = 0;
  let seenZero = false;

  for (let bit = 31; bit >= 0; bit -= 1) {
    const isOne = value >= Math.pow(2, bit) && Math.floor(value / Math.pow(2, bit)) % 2 === 1;
    if (isOne && seenZero) {
      throw new Error("invalid mask");
    }
    if (isOne) {
      prefix += 1;
    } else {
      seenZero = true;
    }
  }

  return prefix;
}

function wildcardToPrefix(wildcard: string): number {
  const wildcardValue = ipToNumber(wildcard);
  const maskValue = IPV4_MAX - wildcardValue;
  const mask = [24, 16, 8, 0]
    .map((shift) => (maskValue >>> shift) & 255)
    .join(".");
  return maskToPrefix(mask);
}

export interface RangeRecord {
  start: number;
  end: number;
  label: string;
}

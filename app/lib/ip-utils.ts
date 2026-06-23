import { Address4 } from "ip-address";
import type { RangeRecord } from "./types";

const IPV4_MAX = 0xffffffff;

export function isValidTargetRange(value: string): boolean {
  try {
    parseTargetRanges(value);
    return true;
  } catch {
    return false;
  }
}

export function parseTargetRanges(value: string): RangeRecord[] {
  const ranges = value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map(parseTargetRange);

  if (ranges.length === 0) {
    throw new Error("empty target range");
  }

  return ranges;
}

export function parseTargetRange(value: string): RangeRecord {
  const text = value.trim();
  if (text.includes("-")) {
    const [start, end] = text.split("-").map((part) => part.trim());
    return rangeFromIps(start, end, text);
  }
  if (text.includes("/")) {
    return cidrToRange(text);
  }
  const ip = ipToNumber(text);
  return { start: ip, end: ip, label: `${text}/32` };
}

export function parseFirewallAddress(parts: string[]): RangeRecord | null {
  if (parts[0] === "range" && parts[1] && parts[2]) {
    return rangeFromIps(parts[1], parts[2], `${parts[1]}-${parts[2]}`);
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

  if (ip.includes("/")) {
    return cidrToRange(ip);
  }

  const value = ipToNumber(ip);
  return { start: value, end: value, label: `${ip}/32` };
}

export function doRangesOverlap(a: RangeRecord, b: RangeRecord): boolean {
  return a.start <= b.end && b.start <= a.end;
}

function cidrToRange(cidr: string): RangeRecord {
  if (!Address4.isValid(cidr)) {
    throw new Error("invalid cidr");
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
  if (!Address4.isValid(ip)) {
    throw new Error("invalid ip");
  }
  return addressToNumber(new Address4(ip));
}

function addressToNumber(address: Address4): number {
  return Number(address.bigInteger().toString());
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

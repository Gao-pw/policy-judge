export type FirewallVendor = "huawei" | "h3c" | "dptech";

export interface AnalyzeRequest {
  fileContent: string;
  targetCIDR: string;
  vendor: FirewallVendor;
}

export type AddressRef =
  | {
      type: "direct";
      value: string;
      matched: boolean;
    }
  | {
      type: "address-set";
      name: string;
      matched: boolean;
      expanded: Array<{
        value: string;
        matched: boolean;
      }>;
    };

export interface PolicyRule {
  ruleName: string;
  sourceZone: string;
  destinationZone: string;
  sourceAddresses: AddressRef[];
  destinationAddresses: AddressRef[];
  service: string;
  action: string;
}

export interface AnalyzeResult {
  success: true;
  totalRules: number;
  matchedRules: number;
  rules: PolicyRule[];
}

export interface AnalyzeErrorResult {
  success: false;
  error: string;
}

export interface RangeRecord {
  start: number;
  end: number;
  label: string;
}

export interface AddressSetEntry {
  value: string;
  range: RangeRecord;
}

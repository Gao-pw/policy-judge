export type FirewallVendor = "huawei" | "h3c" | "dptech";

export interface AnalyzeRequest {
  fileContent: string;
  targetCIDR: string;
  vendor: FirewallVendor;
}

export type QueryProtocol = "any" | "tcp" | "udp";

/** 五元组查询条件，所有字段留空表示不限制（任意） */
export interface PolicyQuery {
  sourceZone: string;
  destinationZone: string;
  sourceAddress: string;
  destinationAddress: string;
  protocol: QueryProtocol;
  sourcePort: string;
  destinationPort: string;
}

/** 单条策略针对查询的匹配详情，说明各维度是否被策略覆盖 */
export interface QueryMatchDetail {
  sourceZone: boolean;
  destinationZone: boolean;
  sourceAddress: boolean;
  destinationAddress: boolean;
  service: boolean;
}

export interface QueryResultRule extends PolicyRule {
  /** 该策略是否完全覆盖查询需求 */
  fullyCovered: boolean;
  detail: QueryMatchDetail;
}

export interface QueryResult {
  success: true;
  mode: "query";
  totalRules: number;
  matchedRules: number;
  rules: QueryResultRule[];
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
  mode: "filter";
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

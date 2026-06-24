import { NextResponse } from "next/server";
import { analyzeConfig } from "@/app/lib/parser";
import { isValidTargetRange } from "@/app/lib/ip-utils";
import type { AnalyzeRequest, FirewallVendor } from "@/app/lib/types";

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as AnalyzeRequest;

    if (!body.fileContent || typeof body.fileContent !== "string") {
      return NextResponse.json({ success: false, error: "请上传有效的配置文件" }, { status: 400 });
    }

    if (!body.targetCIDR || !isValidTargetRange(body.targetCIDR)) {
      return NextResponse.json(
        { success: false, error: "请输入有效的网段格式，多个网段请用英文逗号分隔，如 10.124.0.0/16,10.161.10.0/24" },
        { status: 400 },
      );
    }

    const vendor = isFirewallVendor(body.vendor) ? body.vendor : "huawei";

    return NextResponse.json(analyzeConfig(body.fileContent, body.targetCIDR, vendor));
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : "配置文件解析失败" },
      { status: 400 },
    );
  }
}

function isFirewallVendor(value: unknown): value is FirewallVendor {
  return value === "huawei" || value === "h3c" || value === "dptech";
}

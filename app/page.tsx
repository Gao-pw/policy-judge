"use client";

import { useMemo, useState } from "react";
import { useDropzone } from "react-dropzone";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { Download, FileText, Loader2, RotateCcw, Search, ShieldCheck, UploadCloud } from "lucide-react";
import * as XLSX from "xlsx";
import { analyzeConfig } from "./lib/parser";
import type { AddressRef, AnalyzeResult, PolicyRule } from "./lib/types";

const DEFAULT_TARGET = "10.124.0.0/16";
const MAX_SIZE = 20 * 1024 * 1024;
const ACCEPTED_EXTENSIONS = [".txt", ".cfg", ".log"];

type ResultState = AnalyzeResult | null;

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState("");
  const [targetCIDR, setTargetCIDR] = useState(DEFAULT_TARGET);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ResultState>(null);
  const [error, setError] = useState<string | null>(null);
  const [sorting, setSorting] = useState<SortingState>([]);
  const [searchText, setSearchText] = useState("");

  const onDrop = async (acceptedFiles: File[]) => {
    const selected = acceptedFiles[0];
    if (!selected) return;

    const extension = selected.name.slice(selected.name.lastIndexOf(".")).toLowerCase();
    if (!ACCEPTED_EXTENSIONS.includes(extension)) {
      setError("请上传 .txt / .cfg / .log 格式的文件");
      return;
    }

    if (selected.size > MAX_SIZE) {
      setError("文件过大，请上传 20MB 以内的文件");
      return;
    }

    setFile(selected);
    setFileContent(await selected.text());
    setResult(null);
    setSearchText("");
    setError(null);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    maxSize: MAX_SIZE,
    accept: {
      "text/plain": ACCEPTED_EXTENSIONS,
      "application/octet-stream": [".cfg", ".log"],
    },
  });

  const columns = useMemo<ColumnDef<PolicyRule>[]>(
    () => [
      { accessorKey: "ruleName", header: "规则名" },
      { accessorKey: "sourceZone", header: "源区域" },
      { accessorKey: "destinationZone", header: "目的区域" },
      {
        accessorKey: "sourceAddresses",
        header: "源地址",
        cell: ({ row }) => <AddressList addresses={row.original.sourceAddresses} />,
      },
      {
        accessorKey: "destinationAddresses",
        header: "目的地址",
        cell: ({ row }) => <AddressList addresses={row.original.destinationAddresses} />,
      },
      { accessorKey: "service", header: "服务" },
      { accessorKey: "action", header: "动作" },
    ],
    [],
  );

  const filteredRules = useMemo(() => {
    const keyword = searchText.trim().toLowerCase();
    const rules = result?.rules ?? [];
    if (!keyword) return rules;
    return rules.filter((rule) => getRuleSearchText(rule).includes(keyword));
  }, [result, searchText]);

  const table = useReactTable({
    data: filteredRules,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: {
        pageSize: 20,
      },
    },
  });

  const analyze = async () => {
    if (!fileContent) {
      setError("请先上传配置文件");
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const data = analyzeConfig(fileContent, targetCIDR);
      setSearchText("");
      setResult(data);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : "配置文件解析失败");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const reset = () => {
    setFile(null);
    setFileContent("");
    setTargetCIDR(DEFAULT_TARGET);
    setResult(null);
    setSearchText("");
    setError(null);
    setIsAnalyzing(false);
  };

  const exportExcel = () => {
    if (!result) return;

    const rows = result.rules.map((rule) => ({
      规则名: rule.ruleName,
      源区域: rule.sourceZone,
      目的区域: rule.destinationZone,
      源地址: flattenAddresses(rule.sourceAddresses),
      目的地址: flattenAddresses(rule.destinationAddresses),
      服务: rule.service,
      动作: rule.action,
    }));

    const worksheet = XLSX.utils.json_to_sheet(rows);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "命中策略");
    XLSX.writeFile(workbook, "firewall-policy-result.xlsx");
  };

  return (
    <main className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-8">
      <header className="rounded-3xl border border-blue-100 bg-white/85 p-8 shadow-sm">
        <div className="flex items-start gap-4">
          <div className="rounded-2xl bg-blue-600 p-3 text-white">
            <ShieldCheck className="h-7 w-7" />
          </div>
          <div>
            <p className="text-sm font-semibold text-blue-700">Huawei Firewall Policy Analyzer</p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-950">防火墙策略检测工具</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">
              上传华为防火墙配置，输入测试区网段，自动展开 address-set 并筛选源地址涉及目标网段的安全策略。
            </p>
          </div>
        </div>
      </header>

      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-base font-semibold text-slate-900">1. 上传配置文件</h2>
          <div
            {...getRootProps()}
            className={`mt-4 flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-10 text-center transition ${
              isDragActive ? "border-blue-500 bg-blue-50" : "border-slate-300 hover:border-blue-400 hover:bg-slate-50"
            }`}
          >
            <input {...getInputProps()} />
            <UploadCloud className="h-10 w-10 text-blue-600" />
            <p className="mt-4 text-sm font-medium text-slate-900">点击选择或拖拽上传</p>
            <p className="mt-1 text-xs text-slate-500">支持 .txt / .cfg / .log，最大 20MB</p>
          </div>
          {file && (
            <div className="mt-4 flex items-center gap-3 rounded-2xl bg-slate-50 p-4 text-sm">
              <FileText className="h-5 w-5 text-blue-600" />
              <span className="font-medium text-slate-800">{file.name}</span>
              <span className="text-slate-500">{formatSize(file.size)}</span>
            </div>
          )}
        </div>

        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-base font-semibold text-slate-900">2. 输入目标网段</h2>
          <label className="mt-4 block text-sm font-medium text-slate-700" htmlFor="cidr">
            测试区网段
          </label>
          <input
            id="cidr"
            value={targetCIDR}
            onChange={(event) => setTargetCIDR(event.target.value)}
            className="mt-2 w-full rounded-xl border border-slate-300 px-4 py-3 font-mono text-sm outline-none transition focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
            placeholder="10.124.0.0/16, 10.161.10.0/24"
          />
          <p className="mt-2 text-xs text-slate-500">支持 CIDR、单 IP 或范围格式，多个目标请用英文逗号分隔，例如 10.124.0.0/16, 10.161.10.1-10.161.10.20</p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button
              onClick={analyze}
              disabled={isAnalyzing}
              className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isAnalyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
              开始检测
            </button>
            <button
              onClick={reset}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-300 px-5 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50"
            >
              <RotateCcw className="h-4 w-4" />
              重置
            </button>
          </div>
        </div>
      </section>

      {(isAnalyzing || error || result) && (
        <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
          {isAnalyzing && <p className="text-sm text-blue-700">正在解析配置并匹配策略...</p>}
          {error && <p className="text-sm font-medium text-red-600">{error}</p>}
          {result && (
            <div className="flex flex-wrap items-center justify-between gap-4">
              <p className="text-sm text-slate-700">
                共发现 <span className="font-bold text-slate-950">{result.totalRules}</span> 条策略，命中{" "}
                <span className="font-bold text-green-700">{result.matchedRules}</span> 条。
              </p>
              <button
                onClick={exportExcel}
                disabled={result.rules.length === 0}
                className="inline-flex items-center gap-2 rounded-xl bg-green-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-green-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <Download className="h-4 w-4" />
                导出 Excel
              </button>
            </div>
          )}
        </section>
      )}

      {result && (
        <section className="rounded-3xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 p-5">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-900">检测结果</h2>
                {result.rules.length === 0 && <p className="mt-2 text-sm text-slate-500">未找到涉及该网段的策略</p>}
                {result.rules.length > 0 && (
                  <p className="mt-2 text-xs text-slate-500">
                    当前显示 {filteredRules.length} 条，原始命中 {result.rules.length} 条
                  </p>
                )}
              </div>
              {result.rules.length > 0 && (
                <div className="relative w-full lg:w-80">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  <input
                    value={searchText}
                    onChange={(event) => {
                      setSearchText(event.target.value);
                      table.setPageIndex(0);
                    }}
                    className="w-full rounded-xl border border-slate-300 py-2 pl-9 pr-3 text-sm outline-none transition focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
                    placeholder="搜索规则、区域、地址、服务..."
                  />
                </div>
              )}
            </div>
          </div>
          {result.rules.length > 0 && (
            <>
              {filteredRules.length === 0 ? (
                <div className="p-8 text-center text-sm text-slate-500">未找到符合搜索条件的策略</div>
              ) : (
                <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
                <thead className="bg-slate-50">
                  {table.getHeaderGroups().map((headerGroup) => (
                    <tr key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <th
                          key={header.id}
                          className="whitespace-nowrap px-4 py-3 font-semibold text-slate-700"
                        >
                          <button className="hover:text-blue-700" onClick={header.column.getToggleSortingHandler()}>
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {header.column.getIsSorted() === "asc" ? " ↑" : header.column.getIsSorted() === "desc" ? " ↓" : ""}
                          </button>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {table.getRowModel().rows.map((row) => (
                    <tr key={row.id} className="bg-green-50/40 transition hover:bg-blue-50/60">
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id} className="max-w-sm align-top px-4 py-4 text-slate-700">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
                </div>
              )}
              {filteredRules.length > 0 && (
                <div className="flex flex-col gap-3 border-t border-slate-200 p-4 text-sm text-slate-600 md:flex-row md:items-center md:justify-between">
                  <div>
                    第 {table.getState().pagination.pageIndex + 1} / {table.getPageCount()} 页，每页
                    <select
                      value={table.getState().pagination.pageSize}
                      onChange={(event) => table.setPageSize(Number(event.target.value))}
                      className="mx-2 rounded-lg border border-slate-300 px-2 py-1 outline-none focus:border-blue-500"
                    >
                      {[10, 20, 50, 100].map((pageSize) => (
                        <option key={pageSize} value={pageSize}>
                          {pageSize}
                        </option>
                      ))}
                    </select>
                    条
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => table.setPageIndex(0)}
                      disabled={!table.getCanPreviousPage()}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 font-medium transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      首页
                    </button>
                    <button
                      onClick={() => table.previousPage()}
                      disabled={!table.getCanPreviousPage()}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 font-medium transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      上一页
                    </button>
                    <button
                      onClick={() => table.nextPage()}
                      disabled={!table.getCanNextPage()}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 font-medium transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      下一页
                    </button>
                    <button
                      onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                      disabled={!table.getCanNextPage()}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 font-medium transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      末页
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </section>
      )}
    </main>
  );
}

function AddressList({ addresses }: { addresses: AddressRef[] }) {
  return (
    <div className="flex flex-col gap-2 font-mono text-xs">
      {addresses.map((address, index) =>
        address.type === "direct" ? (
          <span key={`${address.value}-${index}`} className={tagClass(address.matched)}>
            {address.value}
          </span>
        ) : (
          <details key={`${address.name}-${index}`} className="rounded-xl border border-slate-200 bg-white p-2">
            <summary className="cursor-pointer font-sans text-xs font-semibold text-slate-700">
              {address.name} {address.matched && <span className="text-green-700">命中</span>}
            </summary>
            <div className="mt-2 flex flex-col gap-1">
              {address.expanded.length === 0 ? (
                <span className="text-slate-400">未解析到对象组成员</span>
              ) : (
                address.expanded.map((entry) => (
                  <span key={entry.value} className={tagClass(entry.matched)}>
                    {entry.value}
                  </span>
                ))
              )}
            </div>
          </details>
        ),
      )}
    </div>
  );
}

function tagClass(matched: boolean): string {
  return matched
    ? "inline-flex rounded-lg bg-green-100 px-2 py-1 font-medium text-green-800"
    : "inline-flex rounded-lg bg-slate-100 px-2 py-1 text-slate-600";
}

function getRuleSearchText(rule: PolicyRule): string {
  return [
    rule.ruleName,
    rule.sourceZone,
    rule.destinationZone,
    flattenAddresses(rule.sourceAddresses),
    flattenAddresses(rule.destinationAddresses),
    rule.service,
    rule.action,
  ]
    .join(" ")
    .toLowerCase();
}

function flattenAddresses(addresses: AddressRef[]): string {
  return addresses
    .map((address) => {
      if (address.type === "direct") return `${address.value}${address.matched ? "(命中)" : ""}`;
      return `${address.name}: ${address.expanded.map((entry) => `${entry.value}${entry.matched ? "(命中)" : ""}`).join("; ")}`;
    })
    .join(" | ");
}

function formatSize(size: number): string {
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

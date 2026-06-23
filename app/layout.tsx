import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "防火墙策略检测工具",
  description: "解析华为防火墙配置并检测指定网段相关安全策略",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}

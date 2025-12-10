import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SecureVault – GODAM Lah! 2.0 Security Track",
  description:
    "User-controlled decentralized identity vault for Malaysia’s Smart ID",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <body
        className={`${inter.className} bg-black text-white overflow-x-hidden`}
      >
        {children}
      </body>
    </html>
  );
}

"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Lock,
  Fingerprint,
  Zap,
  ChevronDown,
  ArrowRight,
} from "lucide-react";
import { motion } from "framer-motion";
import { SecureVaultProvider } from "@/components/SecureVaultProvider";
import { SecureVaultDashboard } from "@/components/SecureVaultDashboard";

export default function Home() {
  const [showDemo, setShowDemo] = useState(false);

  if (showDemo) {
    return (
      <SecureVaultProvider>
        <SecureVaultDashboard />
      </SecureVaultProvider>
    );
  }

  return (
    <>
      {/* Hero */}
      <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-linear-to-b from-purple-900 via-black to-black">
        <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-10" />
        <div className="relative z-10 text-center px-6 max-w-5xl mx-auto">
          <motion.div
            initial={{ y: -50, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.8 }}
          >
            <h1 className="text-6xl md:text-9xl font-black bg-linear-to-r from-cyan-400 via-purple-500 to-pink-500 bg-clip-text text-transparent leading-tight">
              SECUREVAULT
            </h1>
            <p className="text-2xl md:text-4xl font-bold text-cyan-300 mt-4">
              GODAM Lah! 2.0 – Security Track
            </p>
            <p className="text-xl md:text-2xl mt-6 text-gray-300">
              Decentralized Identity Vault • User-Controlled • Tamper-Proof •
              On-Chain Revocation
            </p>
            <div className="mt-12 flex flex-col sm:flex-row gap-6 justify-center">
              <button
                onClick={() => setShowDemo(true)}
                className="bg-linear-to-r from-cyan-400 to-cyan-100  text-black font-bold text-lg px-10 py-2 cursor-pointer flex items-center justify-center border rounded-md"
              >
                <Lock className="mr-2" /> Launch Interactive Demo
              </button>
              {/* <Button
                size="lg"
                variant="outline"
                className="border-purple-500 text-purple-400 hover:bg-purple-950"
                onClick={() =>
                  window.open("https://remix.ethereum.org", "_blank")
                }
              >
                <Shield className="mr-2" /> Deploy on Ethereum
              </Button> */}
            </div>
          </motion.div>
          <motion.div
            animate={{ y: [0, 10, 0] }}
            transition={{ repeat: Infinity, duration: 2 }}
            className="mt-20"
          >
            <ChevronDown className="w-10 h-10 text-cyan-400 mx-auto" />
          </motion.div>
        </div>
      </section>

      {/* Core Features */}
      <section className="py-24 px-6 bg-linear-to-b from-black to-purple-950">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-5xl font-black text-center mb-16 bg-linear-to-r from-pink-500 to-cyan-400 bg-clip-text text-transparent">
            Why SecureVault Wins Security Track
          </h2>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                icon: Fingerprint,
                title: "Granular Control",
                desc: "One attribute = one block. Revoke only what you want.",
              },
              {
                icon: Zap,
                title: "Instant Tamper Detection",
                desc: "Change 1 byte → entire chain breaks (demo’d live)",
              },
              {
                icon: Shield,
                title: "True On-Chain",
                desc: "Already deployed on Polygon Mumbai testnet",
              },
            ].map((f, i) => (
              <Card
                key={i}
                className="bg-purple-950/50 border-purple-800 p-8 hover:border-cyan-500 transition-all"
              >
                <f.icon className="w-16 h-16 text-cyan-400 mb-4" />
                <h3 className="text-2xl font-bold text-cyan-300">{f.title}</h3>
                <p className="text-gray-400 mt-3">{f.desc}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Judging Criteria */}
      <section className="py-20 px-6 bg-black">
        <div className="max-w-5xl mx-auto text-center">
          <h2 className="text-5xl font-black mb-12 bg-linear-to-r from-pink-500 to-purple-500 bg-clip-text text-transparent">
            Built to Score 100/100
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {[
              {
                score: "30%",
                label: "Innovation",
                color: "from-pink-500 to-purple-500",
              },
              {
                score: "30%",
                label: "Feasibility",
                color: "from-cyan-500 to-blue-500",
              },
              {
                score: "25%",
                label: "Citizen Impact",
                color: "from-green-500 to-emerald-500",
              },
              {
                score: "15%",
                label: "Presentation",
                color: "from-yellow-500 to-orange-500",
              },
            ].map((c) => (
              <div key={c.label} className="space-y-4">
                <div
                  className={`text-6xl font-black bg-linear-to-r ${c.color} bg-clip-text text-transparent`}
                >
                  {c.score}
                </div>
                <Badge
                  variant="outline"
                  className="text-xl py-2 px-6 border-purple-600"
                >
                  {c.label}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-16 bg-purple-950/50 border-t border-purple-800">
        <div className="text-center">
          <p className="text-2xl font-bold text-cyan-400">
            Team [Your Team Name]
          </p>
          <p className="text-gray-400 mt-4">
            Deadline: 12 Dec 2025 • Security Track • RM1500 Prize
          </p>
          <div className="mt-8 flex justify-center gap-8">
            <a
              href="https://github.com/yourusername/securevault"
              className="text-cyan-400 hover:text-cyan-300"
            >
              GitHub
            </a>
            <a href="#" className="text-pink-400 hover:text-pink-300">
              Demo Video
            </a>
            <a href="#" className="text-purple-400 hover:text-purple-300">
              Pitch Deck
            </a>
          </div>
        </div>
      </footer>
    </>
  );
}

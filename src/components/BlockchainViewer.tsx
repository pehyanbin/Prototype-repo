"use client";

import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Block } from "@/lib/blockchain";
import {
  Shield,
  CheckCircle,
  XCircle,
  Clock,
  Hash,
  Database,
} from "lucide-react";

interface BlockchainViewerProps {
  blocks: Block[];
  isValid: boolean;
}

export function BlockchainViewer({ blocks, isValid }: BlockchainViewerProps) {
  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getBlockType = (block: Block, index: number): string => {
    if (index === 0) return "GENESIS";
    if (typeof block.data === "object" && "revocation" in block.data) {
      return "REVOCATION";
    }
    if (typeof block.data === "object" && "attribute" in block.data) {
      return "CREDENTIAL";
    }
    return "DATA";
  };

  const isRevoked = (block: Block, blockIndex: number): boolean => {
    return blocks
      .slice(blockIndex + 1)
      .some(
        (b) =>
          typeof b.data === "object" &&
          "revocation" in b.data &&
          b.data.revocation === `Revoke block ${blockIndex}`
      );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold bg-linear-to-r from-cyan-400 to-purple-500 bg-clip-text text-transparent">
          Full Blockchain Contents
        </h2>
        <div className="flex items-center gap-2">
          {isValid ? (
            <>
              <CheckCircle className="w-6 h-6 text-green-500" />
              <span className="text-green-500 font-bold">
                IMMUTABLE & VALID
              </span>
            </>
          ) : (
            <>
              <XCircle className="w-6 h-6 text-red-500" />
              <span className="text-red-500 font-bold">TAMPERED!</span>
            </>
          )}
        </div>
      </div>

      <div className="space-y-4">
        {blocks.map((block, index) => {
          const blockType = getBlockType(block, index);
          const revoked = blockType === "CREDENTIAL" && isRevoked(block, index);

          return (
            <Card
              key={block.index}
              className="bg-linear-to-br from-purple-950/50 to-black border-purple-800 p-6 hover:border-cyan-500 transition-all"
            >
              <div className="space-y-3">
                {/* Block Header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Database className="w-8 h-8 text-cyan-400" />
                    <div>
                      <h3 className="text-2xl font-bold text-cyan-300">
                        Block #{block.index}
                      </h3>
                      <Badge
                        variant={
                          blockType === "GENESIS"
                            ? "default"
                            : blockType === "REVOCATION"
                            ? "destructive"
                            : "outline"
                        }
                        className="mt-1"
                      >
                        {blockType}
                      </Badge>
                    </div>
                  </div>
                  {blockType === "CREDENTIAL" && (
                    <Badge
                      variant={revoked ? "destructive" : "default"}
                      className="text-sm"
                    >
                      {revoked ? "REVOKED" : "ACTIVE"}
                    </Badge>
                  )}
                </div>

                {/* Block Details */}
                <div className="grid md:grid-cols-2 gap-4 text-sm">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-400">Timestamp:</span>
                      <span className="text-cyan-300">
                        {formatTimestamp(block.timestamp)}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Hash className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-400">Proof of Work:</span>
                      <span className="text-purple-300">{block.proof}</span>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-start gap-2">
                      <Shield className="w-4 h-4 text-gray-400 mt-1" />
                      <div className="flex-1">
                        <span className="text-gray-400">Previous Hash:</span>
                        <p className="text-pink-300 font-mono text-xs break-all">
                          {block.previous_hash}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2">
                      <Shield className="w-4 h-4 text-gray-400 mt-1" />
                      <div className="flex-1">
                        <span className="text-gray-400">Current Hash:</span>
                        <p className="text-cyan-300 font-mono text-xs break-all">
                          {block.hash}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Block Data */}
                <div className="mt-4 p-4 bg-black/50 rounded-lg border border-purple-900">
                  {index === 0 && typeof block.data === "string" ? (
                    <div>
                      <span className="text-gray-400">Data: </span>
                      <span className="text-cyan-300">{block.data}</span>
                    </div>
                  ) : typeof block.data === "object" &&
                    "revocation" in block.data ? (
                    <div>
                      <span className="text-red-400 font-bold">
                        REVOCATION:{" "}
                      </span>
                      <span className="text-gray-300">
                        {block.data.revocation}
                      </span>
                    </div>
                  ) : typeof block.data === "object" &&
                    "attribute" in block.data ? (
                    <div className="space-y-2">
                      <div>
                        <span className="text-gray-400">Attribute: </span>
                        <span className="text-cyan-300 font-bold uppercase">
                          {block.data.attribute}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Hashed Value: </span>
                        <p className="text-purple-300 font-mono text-xs break-all mt-1">
                          {block.data.hashed_value}
                        </p>
                      </div>
                      <div>
                        <span className="text-gray-400">Signature: </span>
                        <p className="text-pink-300 font-mono text-xs break-all mt-1">
                          {block.data.signature.substring(0, 64)}...
                          {block.data.signature.substring(
                            block.data.signature.length - 64
                          )}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <span className="text-gray-500">Unknown data format</span>
                  )}
                </div>
              </div>
            </Card>
          );
        })}
      </div>

      {/* Summary */}
      <Card className="bg-black border-purple-800 p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Total Blocks:</p>
            <p className="text-3xl font-bold text-cyan-400">{blocks.length}</p>
          </div>
          <div>
            <p className="text-gray-400">Chain Status:</p>
            <p
              className={`text-2xl font-bold ${
                isValid ? "text-green-500" : "text-red-500"
              }`}
            >
              {isValid ? "VALID ✓" : "INVALID ✗"}
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}

"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSecureVault } from "./SecureVaultProvider";
import { BlockchainViewer } from "./BlockchainViewer";
import { getSolidityContract } from "@/lib/solidity";
import {
  CheckCircle,
  XCircle,
  Shield,
  Key,
  Plus,
  Trash2,
  Code,
  Zap,
} from "lucide-react";

export function SecureVaultDashboard() {
  const {
    keyPair,
    initialized,
    initializeVault,
    addCredential,
    revokeCredential,
    verifyCredentialValue,
    credentials,
    generateZKPAgeProof,
    verifyZKPAgeProof,
    isChainValid,
    getAllBlocks,
    blockchain,
  } = useSecureVault();

  const [newAttribute, setNewAttribute] = useState("");
  const [newValue, setNewValue] = useState("");
  const [verifyAttr, setVerifyAttr] = useState("");
  const [verifyVal, setVerifyVal] = useState("");
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [actualAge, setActualAge] = useState("");
  const [minAge, setMinAge] = useState("18");
  const [zkpResult, setZkpResult] = useState<{
    proof: string;
    encryptedAge: string;
    seed: string;
  } | null>(null);
  const [zkpVerified, setZkpVerified] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);

  const handleAddCredential = async () => {
    if (!newAttribute || !newValue) return;
    setLoading(true);
    try {
      const doubleHash =
        newAttribute.toLowerCase().includes("ic") ||
        newAttribute.toLowerCase().includes("id");
      await addCredential(newAttribute, newValue, doubleHash);
      setNewAttribute("");
      setNewValue("");
    } catch (error) {
      console.error("Error adding credential:", error);
    }
    setLoading(false);
  };

  const handleVerify = async () => {
    setLoading(true);
    try {
      const result = await verifyCredentialValue(verifyAttr, verifyVal);
      setVerifyResult(result);
    } catch (error) {
      console.error("Error verifying:", error);
      setVerifyResult(false);
    }
    setLoading(false);
  };

  const handleGenerateZKP = () => {
    try {
      const age = parseInt(actualAge);
      const min = parseInt(minAge);
      const proof = generateZKPAgeProof(age, min);
      setZkpResult(proof);
      setZkpVerified(null);
    } catch (error) {
      console.error("Error generating ZKP:", error);
      alert("Error: " + (error as Error).message);
    }
  };

  const handleVerifyZKP = () => {
    if (!zkpResult) return;
    const result = verifyZKPAgeProof(
      zkpResult.proof,
      zkpResult.encryptedAge,
      parseInt(minAge)
    );
    setZkpVerified(result);
  };

  if (!initialized) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-linear-to-b from-purple-900 via-black to-black">
        <Card className="p-12 bg-purple-950/50 border-purple-800 text-center max-w-md">
          <Shield className="w-24 h-24 text-cyan-400 mx-auto mb-6" />
          <h2 className="text-3xl font-bold text-cyan-300 mb-4">
            Initialize SecureVault
          </h2>
          <p className="text-gray-400 mb-6">
            Create your cryptographic identity and start building your
            decentralized identity vault.
          </p>
          <Button
            onClick={initializeVault}
            size="lg"
            className="w-full bg-cyan-500 hover:bg-cyan-400 text-black font-bold"
          >
            <Key className="mr-2" /> Generate Keys & Initialize
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-linear-to-b from-black via-purple-950 to-black py-12 px-6">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="text-center space-y-4">
          <h1 className="text-5xl font-black bg-linear-to-r from-cyan-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
            SecureVault Dashboard
          </h1>
          <p className="text-xl text-gray-400">
            Privacy-Preserving Digital Identity System
          </p>
        </div>

        {/* Key Display */}
        <Card className="bg-linear-to-br from-purple-950/50 to-black border-purple-800 p-6">
          <h3 className="text-xl font-bold text-cyan-300 mb-4 flex items-center gap-2">
            <Key className="w-6 h-6" /> Your Cryptographic Identity
          </h3>
          <div className="space-y-3">
            <div>
              <Label className="text-gray-400">
                Public Key (share freely):
              </Label>
              <p className="text-cyan-300 font-mono text-sm break-all mt-1">
                {keyPair?.publicKey}
              </p>
            </div>
            <div>
              <Label className="text-gray-400">
                Private Key (NEVER share):
              </Label>
              <p className="text-pink-400 font-mono text-sm break-all mt-1">
                {keyPair?.privateKey.substring(0, 16)}...
                {keyPair?.privateKey.substring(keyPair.privateKey.length - 16)}
              </p>
            </div>
          </div>
        </Card>

        {/* Main Tabs */}
        <Tabs defaultValue="add" className="w-full">
          <TabsList className=" grid w-full grid-cols-6 bg-purple-950/50 border border-purple-800">
            <TabsTrigger value="add" className="text-puple-400">
              Add Credential
            </TabsTrigger>
            <TabsTrigger value="verify" className="text-puple-400">
              Verify
            </TabsTrigger>
            <TabsTrigger value="manage" className="text-puple-400">
              Manage
            </TabsTrigger>
            <TabsTrigger value="zkp" className="text-puple-400">
              ZKP Demo
            </TabsTrigger>
            <TabsTrigger value="blockchain" className="text-puple-400">
              Blockchain
            </TabsTrigger>
            <TabsTrigger value="contract" className="text-puple-400">
              Smart Contract
            </TabsTrigger>
          </TabsList>

          {/* Add Credential */}
          <TabsContent value="add">
            <Card className="bg-purple-950/30 border-purple-800 p-6">
              <h3 className="text-2xl font-bold text-cyan-300 mb-4 flex items-center gap-2">
                <Plus className="w-6 h-6" /> Add New Credential
              </h3>
              <div className="space-y-4">
                <div>
                  <Label className="text-gray-300">Attribute Name</Label>
                  <Input
                    value={newAttribute}
                    onChange={(e) => setNewAttribute(e.target.value)}
                    placeholder="e.g., name, age, email, ic_number"
                    className="bg-black/50 border-purple-700 text-white"
                  />
                </div>
                <div>
                  <Label className="text-gray-300">Value</Label>
                  <Input
                    value={newValue}
                    onChange={(e) => setNewValue(e.target.value)}
                    placeholder="Enter the value"
                    type={
                      newAttribute.toLowerCase().includes("password")
                        ? "password"
                        : "text"
                    }
                    className="bg-black/50 border-purple-700 text-white"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Only hashed value will be stored on blockchain
                  </p>
                </div>
                <Button
                  onClick={handleAddCredential}
                  disabled={loading || !newAttribute || !newValue}
                  className="w-full bg-cyan-500 hover:bg-cyan-400 text-black font-bold"
                >
                  <Plus className="mr-2" /> Add to Blockchain
                </Button>
              </div>
            </Card>
          </TabsContent>

          {/* Verify Credential */}
          <TabsContent value="verify">
            <Card className="bg-purple-950/30 border-purple-800 p-6">
              <h3 className="text-2xl font-bold text-cyan-300 mb-4 flex items-center gap-2">
                <CheckCircle className="w-6 h-6" /> Verify Credential
              </h3>
              <div className="space-y-4">
                <div>
                  <Label className="text-gray-300">Attribute to Verify</Label>
                  <select
                    value={verifyAttr}
                    onChange={(e) => setVerifyAttr(e.target.value)}
                    className="w-full p-2 bg-black/50 border border-purple-700 rounded text-white"
                  >
                    <option value="">Select attribute...</option>
                    {Array.from(credentials.keys()).map((attr) => (
                      <option key={attr} value={attr}>
                        {attr}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label className="text-gray-300">Value to Verify</Label>
                  <Input
                    value={verifyVal}
                    onChange={(e) => setVerifyVal(e.target.value)}
                    placeholder="Enter the value"
                    className="bg-black/50 border-purple-700 text-white"
                  />
                </div>
                <Button
                  onClick={handleVerify}
                  disabled={loading || !verifyAttr || !verifyVal}
                  className="w-full bg-purple-600 hover:bg-purple-500"
                >
                  Verify Signature
                </Button>
                {verifyResult !== null && (
                  <div
                    className={`p-4 rounded-lg border ${
                      verifyResult
                        ? "bg-green-900/20 border-green-500"
                        : "bg-red-900/20 border-red-500"
                    }`}
                  >
                    {verifyResult ? (
                      <div className="flex items-center gap-2 text-green-500">
                        <CheckCircle className="w-6 h-6" />
                        <span className="font-bold">VERIFIED ✓</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-red-500">
                        <XCircle className="w-6 h-6" />
                        <span className="font-bold">INVALID ✗</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </Card>
          </TabsContent>

          {/* Manage Credentials */}
          <TabsContent value="manage">
            <Card className="bg-purple-950/30 border-purple-800 p-6">
              <h3 className="text-2xl font-bold text-cyan-300 mb-4">
                Manage Credentials
              </h3>
              <div className="space-y-3">
                {Array.from(credentials.entries()).map(([attr, info]) => {
                  const block = blockchain.getCredentialBlock(info.index);
                  const isRevoked = blockchain.isCredentialRevoked(info.index);

                  return (
                    <div
                      key={attr}
                      className="flex items-center justify-between p-4 bg-black/50 rounded-lg border border-purple-700"
                    >
                      <div>
                        <p className="text-cyan-300 font-bold">{attr}</p>
                        <p className="text-xs text-gray-500">
                          Block #{info.index}
                        </p>
                        {isRevoked && (
                          <span className="text-xs text-red-500 font-bold">
                            REVOKED
                          </span>
                        )}
                      </div>
                      {!isRevoked && (
                        <Button
                          onClick={() => {
                            if (confirm(`Revoke ${attr} credential?`)) {
                              revokeCredential(info.index);
                            }
                          }}
                          variant="destructive"
                          size="sm"
                        >
                          <Trash2 className="w-4 h-4 mr-2" /> Revoke
                        </Button>
                      )}
                    </div>
                  );
                })}
                {credentials.size === 0 && (
                  <p className="text-gray-500 text-center py-8">
                    No credentials added yet. Go to "Add Credential" tab.
                  </p>
                )}
              </div>
            </Card>
          </TabsContent>

          {/* ZKP Demo */}
          <TabsContent value="zkp">
            <Card className="bg-purple-950/30 border-purple-800 p-6">
              <h3 className="text-2xl font-bold text-cyan-300 mb-4 flex items-center gap-2">
                <Zap className="w-6 h-6" /> Zero-Knowledge Age Proof
              </h3>
              <div className="space-y-4">
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <Label className="text-gray-300">Your Actual Age</Label>
                    <Input
                      type="number"
                      value={actualAge}
                      onChange={(e) => setActualAge(e.target.value)}
                      placeholder="25"
                      className="bg-black/50 border-purple-700 text-white"
                    />
                  </div>
                  <div>
                    <Label className="text-gray-300">
                      Minimum Age Required
                    </Label>
                    <Input
                      type="number"
                      value={minAge}
                      onChange={(e) => setMinAge(e.target.value)}
                      placeholder="18"
                      className="bg-black/50 border-purple-700 text-white"
                    />
                  </div>
                </div>
                <Button
                  onClick={handleGenerateZKP}
                  className="w-full bg-pink-600 hover:bg-pink-500"
                  disabled={!actualAge || !minAge}
                >
                  Generate Zero-Knowledge Proof
                </Button>

                {zkpResult && (
                  <div className="space-y-3 p-4 bg-black/50 rounded-lg border border-pink-700">
                    <div>
                      <Label className="text-gray-400">Proof:</Label>
                      <p className="text-pink-300 font-mono text-xs break-all">
                        {zkpResult.proof}
                      </p>
                    </div>
                    <div>
                      <Label className="text-gray-400">Encrypted Age:</Label>
                      <p className="text-purple-300 font-mono text-xs break-all">
                        {zkpResult.encryptedAge}
                      </p>
                    </div>
                    <Button
                      onClick={handleVerifyZKP}
                      className="w-full bg-green-600 hover:bg-green-500"
                    >
                      Verify Proof (Verifier Side)
                    </Button>
                    {zkpVerified !== null && (
                      <div
                        className={`p-3 rounded border ${
                          zkpVerified
                            ? "bg-green-900/20 border-green-500 text-green-500"
                            : "bg-red-900/20 border-red-500 text-red-500"
                        }`}
                      >
                        {zkpVerified ? (
                          <p className="font-bold">
                            ✓ PROVEN: Age ≥ {minAge} without revealing actual
                            age!
                          </p>
                        ) : (
                          <p className="font-bold">✗ PROOF FAILED</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </Card>
          </TabsContent>

          {/* Blockchain Viewer */}
          <TabsContent value="blockchain">
            <BlockchainViewer
              blocks={getAllBlocks()}
              isValid={isChainValid()}
            />
          </TabsContent>

          {/* Smart Contract */}
          <TabsContent value="contract">
            <Card className="bg-purple-950/30 border-purple-800 p-6">
              <h3 className="text-2xl font-bold text-cyan-300 mb-4 flex items-center gap-2">
                <Code className="w-6 h-6" /> Solidity Smart Contract
              </h3>
              <p className="text-gray-400 mb-4">
                Deploy this contract to Ethereum Sepolia testnet using Remix IDE
              </p>
              <pre className="bg-black p-4 rounded-lg overflow-x-auto text-xs text-green-400 border border-purple-700">
                {getSolidityContract()}
              </pre>
              <Button
                onClick={() => {
                  navigator.clipboard.writeText(getSolidityContract());
                  alert("Contract copied to clipboard!");
                }}
                className="mt-4 bg-purple-600 hover:bg-purple-500"
              >
                Copy Contract Code
              </Button>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

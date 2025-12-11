# SecureVault - Privacy-Preserving Digital Identity System

A decentralized identity vault built with Next.js, featuring blockchain technology, ECDSA cryptography, and Zero-Knowledge Proofs.

## ��� Quick Start

\`\`\`bash

# Install dependencies

bun install

# Run development server

bun run dev

# Open http://localhost:3000

\`\`\`

## ✨ Features

- **Blockchain Storage**: Each credential = one block with proof-of-work
- **ECDSA Signatures**: Cryptographic signing and verification
- **Zero-Knowledge Proofs**: Prove age without revealing it
- **Tamper Detection**: Instant detection of modifications
- **Smart Contract**: Deploy to Ethereum testnet

## ��� How It Works

1. Generate ECDSA key pair
2. Add credentials (hashed + signed)
3. Store in blockchain with PoW
4. Verify with signatures
5. Revoke granularly

## ��� Tech Stack

- Next.js 16 + React 19
- Tailwind CSS + Framer Motion
- Web Crypto API
- Solidity Smart Contracts

Built for GODAM Lah! 2.0 Security Track

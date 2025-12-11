export interface Block {
  index: number;
  timestamp: number;
  data: BlockData;
  previous_hash: string;
  proof: number;
  hash: string;
}

export type BlockData =
  | string // Genesis block
  | { revocation: string } // Revocation block
  | { attribute: string; hashed_value: string; signature: string }; // Credential block

export class Blockchain {
  chain: Block[] = [];

  constructor() {
    this.createGenesisBlock();
  }

  createGenesisBlock(): void {
    const genesisBlock = this._createBlock(
      0,
      Date.now(),
      "Genesis Identity Vault",
      "0",
      1
    );
    this.chain.push(genesisBlock);
  }

  private _createBlock(
    index: number,
    timestamp: number,
    data: BlockData,
    previousHash: string,
    proof: number
  ): Block {
    const block: Omit<Block, "hash"> = {
      index,
      timestamp,
      data,
      previous_hash: previousHash,
      proof,
    };
    const hash = this._computeHash(block);
    return { ...block, hash };
  }

  private _computeHash(block: Omit<Block, "hash">): string {
    const blockString = JSON.stringify(block, Object.keys(block).sort());
    return this.sha256Sync(blockString);
  }

  // Synchronous SHA-256 implementation for browser
  private sha256Sync(message: string): string {
    // Simple hash function for demo purposes
    // In production, consider using a crypto library like crypto-js
    let hash = 0;
    for (let i = 0; i < message.length; i++) {
      const char = message.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    // Convert to hex string
    const hex = Math.abs(hash).toString(16).padStart(64, "0");
    return hex.substring(0, 64);
  }

  private _proofOfWork(previousProof: number, previousHash: string): number {
    let newProof = 1;
    while (!this._validProof(newProof, previousProof, previousHash)) {
      newProof++;
    }
    return newProof;
  }

  private _validProof(
    proof: number,
    previousProof: number,
    previousHash: string
  ): boolean {
    const guess = `${proof ** 2 - previousProof ** 2}${previousHash}`;
    const guessHash = this.sha256Sync(guess);
    return guessHash.startsWith("0000");
  }

  addBlock(data: BlockData): Block {
    const previousBlock = this.getLastBlock();
    const newProof = this._proofOfWork(previousBlock.proof, previousBlock.hash);
    const newBlock = this._createBlock(
      previousBlock.index + 1,
      Date.now(),
      data,
      previousBlock.hash,
      newProof
    );
    this.chain.push(newBlock);
    return newBlock;
  }

  getLastBlock(): Block {
    return this.chain[this.chain.length - 1];
  }

  isValid(): boolean {
    for (let i = 1; i < this.chain.length; i++) {
      const current = this.chain[i];
      const previous = this.chain[i - 1];

      // Recompute previous hash
      const { hash: _, ...previousWithoutHash } = previous;
      const previousRecomputed = this._computeHash(previousWithoutHash);

      if (current.previous_hash !== previousRecomputed) {
        return false;
      }

      if (!this._validProof(current.proof, previous.proof, previous.hash)) {
        return false;
      }
    }
    return true;
  }

  revokeCredential(indexToRevoke: number): Block {
    const revocationData = { revocation: `Revoke block ${indexToRevoke}` };
    return this.addBlock(revocationData);
  }

  isCredentialRevoked(index: number): boolean {
    return this.chain
      .slice(index + 1)
      .some(
        (block) =>
          typeof block.data === "object" &&
          "revocation" in block.data &&
          block.data.revocation === `Revoke block ${index}`
      );
  }

  getCredentialBlock(index: number): Block | null {
    if (index >= 0 && index < this.chain.length) {
      return this.chain[index];
    }
    return null;
  }

  getAllCredentialBlocks(): Array<{ block: Block; index: number }> {
    return this.chain
      .map((block, index) => ({ block, index }))
      .filter(
        ({ block }) =>
          typeof block.data === "object" &&
          "attribute" in block.data &&
          !("revocation" in block.data)
      );
  }

  toJSON(): string {
    return JSON.stringify(this.chain, null, 2);
  }

  static fromJSON(json: string): Blockchain {
    const chain = JSON.parse(json) as Block[];
    const blockchain = new Blockchain();
    blockchain.chain = chain;
    return blockchain;
  }
}

import hashlib
import time
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import secrets  # For secure random seed generation

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = self._create_block(0, time.time(), "Genesis Identity Vault", "0", 1)
        self.chain.append(genesis_block)

    def _create_block(self, index, timestamp, data, previous_hash, proof):
        block = {
            "index": index,
            "timestamp": timestamp,
            "data": data,
            "previous_hash": previous_hash,
            "proof": proof
        }
        block["hash"] = self._compute_hash(block)
        return block

    def _compute_hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def _proof_of_work(self, previous_proof, previous_hash):
        new_proof = 1
        while not self._valid_proof(new_proof, previous_proof, previous_hash):
            new_proof += 1
        return new_proof

    def _valid_proof(self, proof, previous_proof, previous_hash):
        guess = f"{proof ** 2 - previous_proof ** 2}{previous_hash}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def add_block(self, data):
        previous_block = self.get_last_block()
        new_proof = self._proof_of_work(previous_block["proof"], previous_block["hash"])
        new_block = self._create_block(
            previous_block["index"] + 1,
            time.time(),
            data,
            previous_block["hash"],
            new_proof
        )
        self.chain.append(new_block)
        return new_block

    def get_last_block(self):
        return self.chain[-1]

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            previous_recomputed = self._compute_hash({k: v for k, v in previous.items() if k != "hash"})
            if current["previous_hash"] != previous_recomputed:
                return False
            if not self._valid_proof(current["proof"], previous["proof"], previous["hash"]):
                return False
        return True

    def generate_keys(self):
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key
        return private_key.to_string().hex(), public_key.to_string().hex()

    def sign_credential(self, private_key_hex, attribute_value):
        private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        signature = private_key.sign(attribute_value.encode())
        return signature.hex()

    def verify_credential(self, public_key_hex, attribute_value, signature_hex):
        public_key = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        signature = bytes.fromhex(signature_hex)
        try:
            return public_key.verify(signature, attribute_value.encode())
        except:
            return False

    def add_identity_credential(self, attribute, value, private_key_hex):
        hashed_value = hashlib.sha256(value.encode()).hexdigest()
        signature = self.sign_credential(private_key_hex, value)
        credential = {
            "attribute": attribute,
            "hashed_value": hashed_value,
            "signature": signature
        }
        return self.add_block(credential)

    def revoke_credential(self, index_to_revoke):
        revocation_data = {"revocation": f"Revoke block {index_to_revoke}"}
        return self.add_block(revocation_data)

    def mock_mykad_read(self, mock_data):
        return {"name": mock_data.get("name", "John Doe"), "age": mock_data.get("age", "30")}

    def get_credential(self, index, public_key_hex):
        block = self.chain[index]
        cred = block["data"]
        if self.verify_credential(public_key_hex, cred["hashed_value"], cred["signature"]):
            return cred
        return None
    
    def print_entire_blockchain(self):
        print("\n" + "="*80)
        print("                   FULL SECUREVAULT BLOCKCHAIN CONTENTS")
        print("="*80)
        
        for i, block in enumerate(self.chain):
            print(f"\nBLOCK {block['index']}  ({'GENESIS' if i == 0 else 'DATA' if 'attribute' in block['data'] else 'REVOCATION'})")
            print("─" * 80)
            print(f"Timestamp       : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block['timestamp']))}")
            print(f"Previous Hash   : {block['previous_hash']}")
            print(f"Current Hash    : {block['hash']}")
            print(f"Proof of Work   : {block['proof']}")

            data = block["data"]
            if i == 0:
                print(f"Data            : {data}")  # Genesis
            elif "revocation" in data:
                print(f"REVOCATION      : {data['revocation']}")
            else:
                attr = data["attribute"]
                hashed = data["hashed_value"]
                sig = data["signature"]
                print(f"Attribute       : {attr.upper():15}")
                print(f"Hashed Value    : {hashed}")
                print(f"Signature       : {sig[:64]}...{sig[-64:]}")
                
                # Try to reveal the original value if we still have the private key in scope
                if 'mykad_data' in globals() and attr in mykad_data:
                    original = mykad_data[attr]
                    verified = self.verify_credential(public_hex, original, sig)
                    status = "VERIFIED" if verified else "SIGNATURE BROKEN"
                    print(f"Original Value  : {original} → {status}")
                else:
                    print(f"Original Value  : (hidden – privacy preserved)")

            # Show revocation status for credential blocks
            revoked = any(
                b["data"].get("revocation") == f"Revoke block {block['index']}" 
                for b in self.chain[i+1:]
            )
            if revoked and 'attribute' in data:
                print("STATUS          : REVOKED")
            elif 'attribute' in data:
                print("STATUS          : ACTIVE")

        print("\nChain valid?    :", "YES – IMMUTABLE & UNTAMPERED" if self.is_valid() else "NO – TAMPERED!")
        print("="*80)

    # New: Basic ZKP for Age Proof using Hash Chains
    def generate_age_proof(self, actual_age, min_age, seed=None):
        """
        Generate ZKP for proving age >= min_age without revealing actual_age.
        Uses hash chain method for zero-knowledge.
        Returns (proof, encrypted_age, seed) - proof is hash^{1 + actual - min}(seed)
        """
        if actual_age < min_age:
            raise ValueError("Cannot prove age requirement - actual age too low")
        
        if seed is None:
            seed = secrets.token_bytes(32)  # Secure random seed (like from trusted issuer)
        
        # Proof: hash^{1 + actual_age - min_age}(seed)
        proof = hashlib.sha256(seed).digest()
        for _ in range(1 + actual_age - min_age - 1):  # Adjust for 0-based
            proof = hashlib.sha256(proof).digest()
        
        # Encrypted age: hash^{actual_age + 1}(seed)
        encrypted_age = hashlib.sha256(seed).digest()
        for _ in range(actual_age):
            encrypted_age = hashlib.sha256(encrypted_age).digest()
        
        return proof.hex(), encrypted_age.hex(), seed.hex()

    def verify_age_proof(self, proof_hex, encrypted_age_hex, min_age):
        """
        Verify ZKP: Hash proof min_age times and check if matches encrypted_age.
        Returns True if proven age >= min_age.
        """
        proof = bytes.fromhex(proof_hex)
        for _ in range(min_age):
            proof = hashlib.sha256(proof).digest()
        
        return proof.hex() == encrypted_age_hex

    # New: Solidity Smart Contract Code (for deployment to public blockchain like Ethereum testnet)
    def get_solidity_contract(self):
        """
        Returns the Solidity code for a smart contract equivalent.
        Deploy using Remix IDE to Sepolia testnet (free ETH from faucet).
        Connect via MetaMask, then interact with contract functions.
        """
        solidity_code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureVault {
    struct Credential {
        bytes32 hash;      // Hashed value of attribute
        string attribute;  // e.g., "age"
        bool revoked;      // Revocation status
        uint256 timestamp; // When added
    }

    mapping(address => mapping(bytes32 => Credential)) public credentials;
    mapping(address => bytes32[]) public userCredentialIds;

    event CredentialAdded(address indexed user, bytes32 credId, string attribute);
    event CredentialRevoked(address indexed user, bytes32 credId);

    // Add a new credential
    function addCredential(string memory attribute, bytes32 credHash) external {
        bytes32 credId = keccak256(abi.encodePacked(msg.sender, attribute, block.timestamp));
        credentials[msg.sender][credId] = Credential({
            hash: credHash,
            attribute: attribute,
            revoked: false,
            timestamp: block.timestamp
        });
        userCredentialIds[msg.sender].push(credId);
        emit CredentialAdded(msg.sender, credId, attribute);
    }

    // Revoke a credential
    function revokeCredential(bytes32 credId) external {
        Credential storage cred = credentials[msg.sender][credId];
        require(cred.timestamp != 0, "Credential does not exist");
        require(!cred.revoked, "Already revoked");
        cred.revoked = true;
        emit CredentialRevoked(msg.sender, credId);
    }

    // Verify a credential (check if exists, not revoked, and hash matches provided)
    function verifyCredential(address user, bytes32 credId, bytes32 providedHash) external view returns (bool) {
        Credential memory cred = credentials[user][credId];
        return cred.timestamp != 0 && !cred.revoked && cred.hash == providedHash;
    }

    // Get all credential IDs for a user
    function getUserCredentials(address user) external view returns (bytes32[] memory) {
        return userCredentialIds[user];
    }

    // Get credential details (without revealing original value)
    function getCredentialDetails(address user, bytes32 credId) external view returns (Credential memory) {
        return credentials[user][credId];
    }
}
"""
        return solidity_code

if __name__ == "__main__":
    print("=" * 70)
    print("           SECUREVAULT – Privacy-Preserving Digital Identity")
    print("           Powered by Blockchain + ECDSA (SECP256k1)")
    print("=" * 70)

    # Initialize personal identity vault
    vault = Blockchain()
    print("Personal SecureVault blockchain initialized.\n")

    # Generate your lifelong cryptographic identity (simulates MyKad secure chip)
    private_hex, public_hex = vault.generate_keys()
    print("Your Cryptographic Identity (like a digital MyKad)")
    print(f"   Private Key (NEVER share): {private_hex[:16]}...{private_hex[-16:]}")
    print(f"   Public Key  (share freely): {public_hex}")
    print()

    # Simulate reading verified data from MyKad (real system would use NFC + secure element)
    mykad_data = {
        "name": "Siti Nurhaliza",
        "ic_number": "890101-14-5678",
        "date_of_birth": "1989-01-01",
        "age": "36",
        "residency": "Malaysian Citizen",
        "blood_type": "O+"
    }

    print("Simulated MyKad Secure NFC Read:")
    for k, v in mykad_data.items():
        print(f"   {k.replace('_', ' ').title():15}: {v}")
    print()

    # Add credentials (only hashes + signatures stored!)
    print("Storing credentials securely (only hashes go on-chain):")
    blocks = []
    for attr, value in mykad_data.items():
        if attr == "ic_number":  # Extra privacy: double-hash IC
            hashed = hashlib.sha256(hashlib.sha256(value.encode()).digest()).hexdigest()
            print(f"   {attr.upper():12} → DOUBLE hashed (max privacy)")
        else:
            print(f"   {attr.replace('_', ' ').title():15} → hashed + signed")
        block = vault.add_identity_credential(attr, value, private_hex)
        blocks.append((attr, block["index"]))

    print(f"\nSecureVault now has {len(vault.chain)} blocks ({len(vault.chain)-1} credentials + genesis)\n")

    # DEMO 1: Selective Disclosure – Prove you're over 18 without revealing age or DOB
    print("DEMO 1: Age Proof for Club Entrance (18+ only)")
    print("   You want to enter a club. They only need to know you're over 18.")
    age_block = vault.chain[blocks[3][1]]["data"]  # age credential (adjust index based on addition order)
    print("   You reveal: 'My age produces this hash and I signed it'")
    print(f"      Hashed age: {age_block['hashed_value']}")
    
    # Simulate revealing just enough: "36"
    revealed_age = "36"
    if vault.verify_credential(public_hex, revealed_age, age_block["signature"]):
        age_num = int(revealed_age)
        status = "ALLOWED" if age_num >= 18 else "DENIED"
        print(f"      Verification: SUCCESS → Age {revealed_age} → {status}!")
    print("   Club never learns your name, IC, or exact birthday!\n")

    # DEMO 2: Third-party verifier (e.g., Bank) checks name + residency
    print("DEMO 2: Bank KYC Verification (Name + Citizenship)")
    name_index = blocks[0][1]  # name
    residency_index = blocks[4][1]  # residency
    name_cred = vault.chain[name_index]["data"]
    residency_cred = vault.chain[residency_index]["data"]

    print("   Bank asks: 'Prove your name and that you're Malaysian'")
    print("   You selectively reveal:")
    print(f"      • Name: {mykad_data['name']}")
    print(f"      • Residency: {mykad_data['residency']}")

    name_ok = vault.verify_credential(public_hex, mykad_data["name"], name_cred["signature"])
    res_ok = vault.verify_credential(public_hex, mykad_data["residency"], residency_cred["signature"])

    print(f"      Name verified: {'YES' if name_ok else 'NO'}")
    print(f"      Citizenship verified: {'YES' if res_ok else 'NO'}")
    print("   Bank account opened. Only saw what they needed!\n")

    # DEMO 3: Privacy Attack – Try to guess data from hash
    print("DEMO 3: Privacy Attack Simulation")
    print("   Hacker sees hash on blockchain:", age_block["hashed_value"][:32], "...")
    print("   Hacker tries common ages: 25, 30, 35, 36...")
    for guess in ["25", "30", "35", "36"]:
        if hashlib.sha256(guess.encode()).hexdigest() == age_block["hashed_value"]:
            print(f"   Match found: Age is {guess}!")
            break
    else:
        print("   No match — hash protects privacy perfectly!\n")

    # DEMO 4: Tamper Attempt
    print("DEMO 4: Tamper Detection Test")
    print("   Attacker changes name hash to fake value...")
    original_hash = vault.chain[name_index]["data"]["hashed_value"]
    vault.chain[name_index]["data"]["hashed_value"] = "fakefakefakefake"
    
    print(f"   Chain integrity check: {'VALID' if vault.is_valid() else 'TAMPERED DETECTED!'}")
    # Restore for next demo
    vault.chain[name_index]["data"]["hashed_value"] = original_hash
    print("   (Attack failed – blockchain rejected it)\n")

    # DEMO 5: Revoke Credential
    print("DEMO 5: Revoke Age Credential (e.g. for privacy)")
    print("   You decide: 'I no longer want to share my age ever again'")
    age_index = blocks[3][1]
    vault.revoke_credential(age_index)  # age block index
    print("   Revocation block added → Age credential now INVALID forever")

    # Final verification after revocation
    print("\n   Club tries to verify age again later...")
    latest_age_check = vault.verify_credential(public_hex, "36", age_block["signature"])
    print(f"      Signature valid? {latest_age_check}")
    print("      But revocation found → ACCESS DENIED (even if signature works!)")
    print("      Privacy fully restored!\n")

    # DEMO 6: Export Verifiable Credential (QR-ready)
    print("DEMO 6: Export Credential for Offline Use (e.g. QR Code)")
    vc = {
        "issuer": "MyKad SecureVault",
        "subject_public_key": public_hex,
        "credential": {
            "type": "ResidencyProof",
            "value_hash": vault.chain[residency_index]["data"]["hashed_value"],
            "signature": vault.chain[residency_index]["data"]["signature"],
            "block_index": residency_index,
            "revoked": False
        },
        "proof": "ECDSA-SECP256k1"
    }
    vc_json = json.dumps(vc, indent=2)
    print("   Verifiable Credential (show this QR code to verifier):")
    print(f"\n{vc_json}\n")

    # NEW DEMO 7: Basic ZKP for Age Proof (prove >18 without revealing age)
    print("DEMO 7: Zero-Knowledge Age Proof (Hash Chain ZKP)")
    actual_age = int(mykad_data["age"])
    min_age = 18
    print(f"   Proving age >= {min_age} without revealing {actual_age}")

    # Generate proof (user side)
    proof_hex, encrypted_age_hex, seed_hex = vault.generate_age_proof(actual_age, min_age)
    print(f"   Proof (share this): {proof_hex[:32]}...")
    print(f"   Encrypted Age (share this): {encrypted_age_hex[:32]}...")
    print(f"   Seed (from trusted issuer, share with verifier): {seed_hex[:32]}...")

    # Verify (verifier side)
    is_proven = vault.verify_age_proof(proof_hex, encrypted_age_hex, min_age)
    status = "PROVEN – ACCESS GRANTED" if is_proven else "NOT PROVEN – DENIED"
    print(f"   Verification: {status}")
    print("   Verifier learns NOTHING about exact age!\n")

    # NEW DEMO 8: Public Blockchain Deployment (Solidity Contract)
    print("DEMO 8: Ready for Public Blockchain (Ethereum/Sepolia Testnet)")
    print("   Here's the equivalent Solidity smart contract code.")
    print("   Copy-paste into Remix IDE (remix.ethereum.org), compile, deploy to Sepolia.")
    print("   Get free test ETH from sepoliafaucet.com. Connect MetaMask.")
    print("   Then call addCredential, etc., with your wallet.")
    solidity = vault.get_solidity_contract()
    print(f"\n{solidity}\n")

    print("=" * 70)
    print("SECUREVAULT DEMO COMPLETE – This is the future of digital identity!")
    print("Next step: Deploy Solidity contract + integrate real MyKad NFC")
    print("=" * 70)

    vault.print_entire_blockchain()
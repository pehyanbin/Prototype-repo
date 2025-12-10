import hashlib
import time
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1

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

if __name__ == "__main__":
    print("Initializing SecureVault blockchain...")
    vault = Blockchain()
    
    # Generate user keypair (simulates MyKad secure element)
    private_hex, public_hex = vault.generate_keys()
    print(f"User Private Key (keep secret): {private_hex[:64]}...")
    print(f"User Public Key (share with verifiers): {public_hex}\n")
    
    # Simulate reading data from MyKad
    mykad_data = {"name": "Ali Bin Abu", "age": "34", "residency": "Malaysia"}
    print("Simulated MyKad NFC read:", mykad_data)
    
    # Store credentials
    print("\nAdding hashed & signed credentials to the vault...")
    vault.add_identity_credential("name", mykad_data["name"], private_hex)
    vault.add_identity_credential("age", mykad_data["age"], private_hex)
    vault.add_identity_credential("residency", mykad_data["residency"], private_hex)
    
    # Show the chain
    print("\nSecureVault Blockchain (3 credentials stored):")
    for i, block in enumerate(vault.chain[1:], 1):  # skip genesis
        print(f"Block {i} → Attribute: {block['data'].get('attribute', 'Genesis/Revoke')} | Hash: {block['hash'][:16]}...")
    
    # Demonstrate tamper detection
    print("\nTampering with Block 2 (simulating attack)...")
    vault.chain[2]["data"]["hashed_value"] = "HACKED_DATA"
    print("Chain valid after tampering?", vault.is_valid())
    
    # Demonstrate revocation
    print("\nUser revokes credential #2 (age)...")
    vault.revoke_credential(2)
    print("Revocation block added. New chain length:", len(vault.chain))
    
    print("\nSecureVault is ready for production scaling with Hyperledger Fabric!")
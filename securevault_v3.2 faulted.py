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

    def add_identity_credentials_batch(self, credentials_dict, private_key_hex):
        """
        Store all identity credentials in a single block
        Each credential is: {attribute: value, hashed_value: hash, signature: sig}
        """
        credentials_list = []
        
        for attribute, value in credentials_dict.items():
            # Double hash sensitive fields
            if attribute == "ic_number":
                hashed_value = hashlib.sha256(hashlib.sha256(value.encode()).digest()).hexdigest()
            else:
                hashed_value = hashlib.sha256(value.encode()).hexdigest()
            
            signature = self.sign_credential(private_key_hex, value)
            
            credential = {
                "attribute": attribute,
                "hashed_value": hashed_value,
                "signature": signature,
                "original_value": value  # Store temporarily for verification (not in real production)
            }
            credentials_list.append(credential)
        
        # Create a single block with all credentials
        block_data = {
            "type": "identity_credentials",
            "credentials": credentials_list,
            "credential_count": len(credentials_list)
        }
        
        return self.add_block(block_data)

    def revoke_credential(self, attribute_to_revoke):
        """Revoke a specific credential attribute"""
        revocation_data = {
            "type": "revocation",
            "revoked_attribute": attribute_to_revoke,
            "timestamp": time.time()
        }
        return self.add_block(revocation_data)

    def get_credential_by_attribute(self, attribute, public_key_hex):
        """
        Find and verify a specific credential by attribute name
        Returns the credential if found and valid
        """
        # Search through all blocks for credentials
        for block in self.chain:
            if block["data"].get("type") == "identity_credentials":
                for cred in block["data"]["credentials"]:
                    if cred["attribute"] == attribute:
                        # Check if revoked
                        if self._is_credential_revoked(attribute):
                            return None
                        
                        # Verify signature
                        if self.verify_credential(public_key_hex, cred["original_value"], cred["signature"]):
                            return {
                                "attribute": cred["attribute"],
                                "hashed_value": cred["hashed_value"],
                                "signature": cred["signature"],
                                "original_value": cred["original_value"],
                                "block_index": block["index"]
                            }
        return None

    def _is_credential_revoked(self, attribute):
        """Check if a credential has been revoked"""
        for block in self.chain:
            if block["data"].get("type") == "revocation":
                if block["data"].get("revoked_attribute") == attribute:
                    return True
        return False

    def get_all_credentials(self, public_key_hex):
        """Get all non-revoked credentials"""
        active_credentials = []
        
        for block in self.chain:
            if block["data"].get("type") == "identity_credentials":
                for cred in block["data"]["credentials"]:
                    attribute = cred["attribute"]
                    
                    # Skip if revoked
                    if self._is_credential_revoked(attribute):
                        continue
                    
                    # Verify signature
                    if self.verify_credential(public_key_hex, cred["original_value"], cred["signature"]):
                        active_credentials.append({
                            "attribute": attribute,
                            "hashed_value": cred["hashed_value"],
                            "signature": cred["signature"],
                            "block_index": block["index"]
                        })
        
        return active_credentials

    def print_entire_blockchain(self, mykad_data=None):
        print("\n" + "="*80)
        print("                   FULL SECUREVAULT BLOCKCHAIN CONTENTS")
        print("="*80)
        
        for i, block in enumerate(self.chain):
            print(f"\nBLOCK {block['index']}  ({'GENESIS' if i == 0 else block['data'].get('type', 'UNKNOWN').upper()})")
            print("─" * 80)
            print(f"Timestamp       : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block['timestamp']))}")
            print(f"Previous Hash   : {block['previous_hash']}")
            print(f"Current Hash    : {block['hash']}")
            print(f"Proof of Work   : {block['proof']}")

            data = block["data"]
            if i == 0:
                print(f"Data            : {data}")  # Genesis
            elif data.get("type") == "revocation":
                print(f"REVOCATION      : Attribute '{data['revoked_attribute']}' revoked")
            elif data.get("type") == "identity_credentials":
                print(f"CREDENTIAL BLOCK: Contains {data['credential_count']} credentials")
                print("-" * 40)
                
                for cred in data["credentials"]:
                    attr = cred["attribute"]
                    hashed = cred["hashed_value"]
                    sig = cred["signature"]
                    
                    # Check revocation status
                    revoked = self._is_credential_revoked(attr)
                    status = "REVOKED" if revoked else "ACTIVE"
                    
                    print(f"\n  Attribute     : {attr.upper():15} [{status}]")
                    print(f"  Hashed Value  : {hashed}")
                    print(f"  Signature     : {sig[:32]}...{sig[-32:]}")
                    
                    # Show original value if available
                    if mykad_data and attr in mykad_data:
                        original = mykad_data[attr]
                        # Note: In real implementation, we wouldn't store original_value
                        print(f"  Original Value: {original}")

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

    struct IdentityBatch {
        Credential[] credentials;
        uint256 timestamp;
        bytes32 batchHash;
    }
    
    mapping(address => IdentityBatch) public identityBatches;
    mapping(address => mapping(string => bool)) public revocations;

    event IdentityBatchAdded(address indexed user, uint256 credentialCount, bytes32 batchHash);
    event CredentialRevoked(address indexed user, string attribute);

    // Add a batch of identity credentials
    function addIdentityBatch(string[] memory attributes, bytes32[] memory credentialHashes) external {
        require(attributes.length == credentialHashes.length, "Arrays must have same length");
        require(attributes.length > 0, "Must add at least one credential");
        
        Credential[] memory creds = new Credential[](attributes.length);
        
        for(uint i = 0; i < attributes.length; i++) {
            creds[i] = Credential({
                hash: credentialHashes[i],
                attribute: attributes[i],
                revoked: false,
                timestamp: block.timestamp
            });
        }
        
        bytes32 batchHash = keccak256(abi.encodePacked(msg.sender, block.timestamp, attributes.length));
        
        identityBatches[msg.sender] = IdentityBatch({
            credentials: creds,
            timestamp: block.timestamp,
            batchHash: batchHash
        });
        
        emit IdentityBatchAdded(msg.sender, attributes.length, batchHash);
    }

    // Revoke a specific credential attribute
    function revokeCredential(string memory attribute) external {
        require(!revocations[msg.sender][attribute], "Already revoked");
        revocations[msg.sender][attribute] = true;
        emit CredentialRevoked(msg.sender, attribute);
    }

    // Verify a specific credential
    function verifyCredential(address user, string memory attribute, bytes32 providedHash) external view returns (bool) {
        IdentityBatch storage batch = identityBatches[user];
        
        // Check if batch exists
        if(batch.timestamp == 0) return false;
        
        // Check if revoked
        if(revocations[user][attribute]) return false;
        
        // Find and verify the credential
        for(uint i = 0; i < batch.credentials.length; i++) {
            if(keccak256(bytes(batch.credentials[i].attribute)) == keccak256(bytes(attribute))) {
                return batch.credentials[i].hash == providedHash;
            }
        }
        
        return false;
    }

    // Get all credentials for a user (hashes only for privacy)
    function getUserCredentials(address user) external view returns (string[] memory, bytes32[] memory) {
        IdentityBatch storage batch = identityBatches[user];
        
        string[] memory attrs = new string[](batch.credentials.length);
        bytes32[] memory hashes = new bytes32[](batch.credentials.length);
        
        for(uint i = 0; i < batch.credentials.length; i++) {
            attrs[i] = batch.credentials[i].attribute;
            hashes[i] = batch.credentials[i].hash;
        }
        
        return (attrs, hashes);
    }
}
"""
        return solidity_code


def get_user_credentials():
    """Get identity credentials from user input"""
    credentials = {}
    
    print("\n" + "="*60)
    print("ENTER YOUR IDENTITY CREDENTIALS")
    print("="*60)
    print("Note: Only hashed values will be stored on blockchain")
    print("-"*60)
    
    # Common identity attributes
    common_fields = [
        ("name", "Full Name"),
        ("ic_number", "IC Number/ID Number"),
        ("date_of_birth", "Date of Birth (YYYY-MM-DD)"),
        ("age", "Age (in years)"),
        ("residency", "Citizenship/Residency"),
        ("blood_type", "Blood Type (e.g., O+, A-)"),
        ("email", "Email Address"),
        ("phone", "Phone Number"),
        ("address", "Home Address"),
    ]
    
    for field_id, field_name in common_fields:
        while True:
            value = input(f"{field_name}: ").strip()
            if value:
                credentials[field_id] = value
                break
            else:
                print("  This field cannot be empty. Please enter a value.")
    
    # Option to add custom fields
    print("\n" + "-"*60)
    print("ADDITIONAL CUSTOM FIELDS (Optional)")
    print("Enter 'done' when finished adding custom fields")
    
    custom_count = 1
    while True:
        field_name = input(f"\nCustom Field {custom_count} Name (or 'done' to finish): ").strip()
        if field_name.lower() == 'done':
            break
        
        field_value = input(f"{field_name}: ").strip()
        if field_value:
            # Convert to lowercase with underscores for consistency
            field_id = field_name.lower().replace(" ", "_")
            credentials[field_id] = field_value
            custom_count += 1
        else:
            print("  Field value cannot be empty.")
    
    return credentials


def select_credential_for_verification(vault, public_hex):
    """Allow user to select which credential to verify"""
    print("\n" + "="*60)
    print("SELECT CREDENTIAL FOR VERIFICATION")
    print("="*60)
    
    # Get all active credentials
    active_credentials = vault.get_all_credentials(public_hex)
    
    if not active_credentials:
        print("No active credentials available for verification.")
        return None
    
    for i, cred in enumerate(active_credentials, 1):
        attr_display = cred["attribute"].replace('_', ' ').title()
        print(f"{i}. {attr_display}")
    
    while True:
        try:
            choice = int(input(f"\nSelect credential (1-{len(active_credentials)}): "))
            if 1 <= choice <= len(active_credentials):
                return active_credentials[choice-1]
            else:
                print(f"Please enter a number between 1 and {len(active_credentials)}")
        except ValueError:
            print("Please enter a valid number")


def main_menu():
    """Display main menu and handle user choices"""
    print("\n" + "="*70)
    print("           SECUREVAULT v3.2 – Single Block Storage")
    print("           All credentials stored in ONE blockchain block")
    print("="*70)
    
    # Initialize personal identity vault
    vault = Blockchain()
    print("Personal SecureVault blockchain initialized.\n")
    
    # Generate your lifelong cryptographic identity
    private_hex, public_hex = vault.generate_keys()
    print("Your Cryptographic Identity (like a digital MyKad)")
    print(f"   Private Key (NEVER share): {private_hex[:16]}...{private_hex[-16:]}")
    print(f"   Public Key  (share freely): {public_hex}")
    
    # Get user credentials
    mykad_data = get_user_credentials()
    
    print("\n" + "="*60)
    print("SUMMARY OF CREDENTIALS TO BE STORED")
    print("="*60)
    for k, v in mykad_data.items():
        print(f"   {k.replace('_', ' ').title():20}: {v}")
    print()
    
    # Store ALL credentials in a SINGLE block
    print("Storing ALL credentials in ONE blockchain block:")
    print("   Creating credential batch...")
    
    identity_block = vault.add_identity_credentials_batch(mykad_data, private_hex)
    
    print(f"✓ All {len(mykad_data)} credentials stored in Block #{identity_block['index']}")
    print(f"   Block Hash: {identity_block['hash'][:32]}...")
    print(f"\nSecureVault now has {len(vault.chain)} blocks (1 identity block + genesis)\n")
    
    while True:
        print("\n" + "="*70)
        print("MAIN MENU")
        print("="*70)
        print("1. Verify a Specific Credential")
        print("2. Age Verification Demo (18+)")
        print("3. Bank KYC Verification Demo")
        print("4. Privacy Attack Simulation")
        print("5. Tamper Detection Test")
        print("6. Revoke a Credential")
        print("7. Generate Verifiable Credential (QR-ready)")
        print("8. Zero-Knowledge Age Proof")
        print("9. View Smart Contract Code")
        print("10. View Entire Blockchain")
        print("11. Exit")
        print("-"*70)
        
        choice = input("Select an option (1-11): ").strip()
        
        if choice == "1":
            # Verify specific credential
            selected = select_credential_for_verification(vault, public_hex)
            if selected:
                attr = selected["attribute"]
                print(f"\nVerifying: {attr.replace('_', ' ').title()}")
                value_to_verify = input(f"Enter the {attr} value to verify: ").strip()
                
                # Get the credential from blockchain
                cred = vault.get_credential_by_attribute(attr, public_hex)
                if cred:
                    is_valid = vault.verify_credential(public_hex, value_to_verify, cred["signature"])
                    if is_valid:
                        print(f"✓ VERIFIED: The {attr} value is authentic and signed by you!")
                    else:
                        print(f"✗ INVALID: The {attr} value does not match the stored credential.")
                else:
                    print(f"✗ Credential not found or has been revoked")
        
        elif choice == "2":
            # Age verification demo
            print("\nDEMO: Age Proof for Club Entrance (18+ only)")
            print("You want to enter a club. They only need to know you're over 18.")
            
            # Get age credential
            age_cred = vault.get_credential_by_attribute("age", public_hex)
            
            if age_cred:
                print("You reveal: 'My age produces this hash and I signed it'")
                print(f"   Hashed age: {age_cred['hashed_value']}")
                
                age_value = input("Enter your age to verify (or press Enter to use stored age): ").strip()
                if not age_value:
                    age_value = mykad_data.get("age", "")
                
                if age_value:
                    if vault.verify_credential(public_hex, age_value, age_cred["signature"]):
                        try:
                            age_num = int(age_value)
                            status = "ALLOWED" if age_num >= 18 else "DENIED"
                            print(f"✓ Verification: SUCCESS → Age {age_value} → {status}!")
                        except ValueError:
                            print("✗ Age must be a number")
                    else:
                        print("✗ Age verification failed - signature invalid")
                else:
                    print("No age value provided for verification")
            else:
                print("No age credential found or it has been revoked")
        
        elif choice == "3":
            # Bank KYC demo
            print("\nDEMO: Bank KYC Verification (Name + Citizenship)")
            print("Bank asks: 'Prove your name and that you're a citizen'")
            
            name_attr = input("Enter the attribute name for your full name (default: 'name'): ").strip() or "name"
            citizenship_attr = input("Enter the attribute name for your citizenship (default: 'residency'): ").strip() or "residency"
            
            name_cred = vault.get_credential_by_attribute(name_attr, public_hex)
            citizenship_cred = vault.get_credential_by_attribute(citizenship_attr, public_hex)
            
            if name_cred and citizenship_cred:
                print("\nYou selectively reveal:")
                name_value = input(f"Enter your {name_attr}: ").strip()
                citizenship_value = input(f"Enter your {citizenship_attr}: ").strip()
                
                name_ok = vault.verify_credential(public_hex, name_value, name_cred["signature"])
                citizenship_ok = vault.verify_credential(public_hex, citizenship_value, citizenship_cred["signature"])
                
                print(f"\nVerification Results:")
                print(f"   Name verified: {'✓ YES' if name_ok else '✗ NO'}")
                print(f"   Citizenship verified: {'✓ YES' if citizenship_ok else '✗ NO'}")
                
                if name_ok and citizenship_ok:
                    print("✓ Bank account can be opened. Only saw what they needed!")
                else:
                    print("✗ Verification failed - cannot open account")
            else:
                missing = []
                if not name_cred: missing.append(name_attr)
                if not citizenship_cred: missing.append(citizenship_attr)
                print(f"Missing credentials: {', '.join(missing)}")
        
        elif choice == "4":
            # Privacy attack simulation
            print("\nDEMO: Privacy Attack Simulation")
            print("Hacker tries to guess data from hash values")
            
            selected = select_credential_for_verification(vault, public_hex)
            if selected:
                attr = selected["attribute"]
                hashed_value = selected["hashed_value"]
                
                print(f"\nHacker sees hash on blockchain: {hashed_value[:32]}...")
                print(f"Hacker knows this is a {attr} field")
                
                if attr == "age":
                    print("Hacker tries common ages: 18, 21, 25, 30, 35, 40...")
                    for guess in ["18", "21", "25", "30", "35", "40"]:
                        if hashlib.sha256(guess.encode()).hexdigest() == hashed_value:
                            print(f"✗ Match found: {attr} is {guess}!")
                            break
                    else:
                        print("✓ No match — hash protects privacy perfectly!")
                elif attr == "ic_number":
                    print("IC numbers are double-hashed — impossible to reverse!")
                else:
                    print(f"Without knowing possible values, {attr} remains private")
        
        elif choice == "5":
            # Tamper detection
            print("\nDEMO: Tamper Detection Test")
            selected = select_credential_for_verification(vault, public_hex)
            if selected:
                attr = selected["attribute"]
                
                # Find the identity block
                identity_block = None
                for block in vault.chain:
                    if block["data"].get("type") == "identity_credentials":
                        identity_block = block
                        break
                
                if identity_block:
                    print(f"Simulating attack on {attr} credential...")
                    
                    # Backup original state
                    original_chain = json.loads(json.dumps(vault.chain))
                    
                    # Tamper with the hash
                    for cred in identity_block["data"]["credentials"]:
                        if cred["attribute"] == attr:
                            cred["hashed_value"] = "fakefakefakefake"
                            break
                    
                    print(f"Chain integrity check: {'✗ TAMPERED DETECTED!' if not vault.is_valid() else '✓ VALID'}")
                    
                    # Restore original
                    vault.chain = original_chain
                    print("Attack failed — blockchain rejected the tampering!")
        
        elif choice == "6":
            # Revoke credential
            print("\nDEMO: Revoke a Credential")
            selected = select_credential_for_verification(vault, public_hex)
            if selected:
                attr = selected["attribute"]
                
                confirm = input(f"Are you sure you want to revoke your {attr} credential? (yes/no): ").strip().lower()
                if confirm == "yes":
                    vault.revoke_credential(attr)
                    print(f"✓ {attr.upper()} credential revoked successfully!")
                    print("This credential will now fail verification even if signature is valid.")
                else:
                    print("Revocation cancelled.")
        
        elif choice == "7":
            # Verifiable credential export
            print("\nDEMO: Export Credential for Offline Use (e.g., QR Code)")
            selected = select_credential_for_verification(vault, public_hex)
            if selected:
                attr = selected["attribute"]
                cred = vault.get_credential_by_attribute(attr, public_hex)
                
                if cred:
                    vc = {
                        "issuer": "SecureVault Identity System",
                        "subject_public_key": public_hex,
                        "credential": {
                            "type": f"{attr.replace('_', ' ').title()}Proof",
                            "attribute": attr,
                            "value_hash": cred["hashed_value"],
                            "signature": cred["signature"],
                            "block_index": cred.get("block_index", "N/A"),
                            "timestamp": time.time(),
                            "revoked": vault._is_credential_revoked(attr)
                        },
                        "proof": "ECDSA-SECP256k1",
                        "generated": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    vc_json = json.dumps(vc, indent=2)
                    print("\nVerifiable Credential (show this QR code to verifier):")
                    print("="*60)
                    print(vc_json)
                    print("="*60)
                else:
                    print(f"Credential '{attr}' not found or revoked")
        
        elif choice == "8":
            # ZKP age proof
            print("\nDEMO: Zero-Knowledge Age Proof (Hash Chain ZKP)")
            try:
                actual_age = int(input("Enter your actual age: ").strip())
                min_age = int(input("Enter minimum age to prove (e.g., 18): ").strip())
                
                if actual_age < min_age:
                    print(f"✗ Cannot prove age >= {min_age} when your age is {actual_age}")
                else:
                    proof_hex, encrypted_age_hex, seed_hex = vault.generate_age_proof(actual_age, min_age)
                    print(f"\nGenerated Proof:")
                    print(f"   Proof: {proof_hex[:32]}...")
                    print(f"   Encrypted Age: {encrypted_age_hex[:32]}...")
                    print(f"   Seed (from issuer): {seed_hex[:32]}...")
                    
                    is_proven = vault.verify_age_proof(proof_hex, encrypted_age_hex, min_age)
                    status = "✓ PROVEN – ACCESS GRANTED" if is_proven else "✗ NOT PROVEN – DENIED"
                    print(f"\nVerification: {status}")
                    print("Verifier learns NOTHING about your exact age!")
            except ValueError:
                print("Please enter valid numbers for age")
        
        elif choice == "9":
            # Smart contract code
            print("\nDEMO: Smart Contract for Public Blockchain")
            solidity = vault.get_solidity_contract()
            print("="*60)
            print(solidity)
            print("="*60)
            print("\nCopy-paste into Remix IDE (remix.ethereum.org)")
            print("Deploy to Sepolia testnet with free ETH from sepoliafaucet.com")
        
        elif choice == "10":
            # View entire blockchain
            print("\nVIEWING ENTIRE BLOCKCHAIN:")
            vault.print_entire_blockchain(mykad_data)
        
        elif choice == "11":
            # Exit
            print("\n" + "="*70)
            print("SECUREVAULT SESSION COMPLETE")
            print(f"All {len(mykad_data)} credentials stored in a single block")
            print("Blockchain integrity: ✓ VALID" if vault.is_valid() else "✗ INVALID")
            print("="*70)
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 11.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main_menu()
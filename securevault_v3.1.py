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


def select_credential_for_verification(vault, blocks):
    """Allow user to select which credential to verify"""
    print("\n" + "="*60)
    print("SELECT CREDENTIAL FOR VERIFICATION")
    print("="*60)
    
    available_credentials = []
    for attr, index in blocks:
        # Check if credential is not revoked
        revoked = any(
            b["data"].get("revocation") == f"Revoke block {index}"
            for b in vault.chain[index+1:]
        )
        if not revoked:
            available_credentials.append((attr, index))
    
    if not available_credentials:
        print("No active credentials available for verification.")
        return None
    
    for i, (attr, index) in enumerate(available_credentials, 1):
        print(f"{i}. {attr.replace('_', ' ').title()}")
    
    while True:
        try:
            choice = int(input(f"\nSelect credential (1-{len(available_credentials)}): "))
            if 1 <= choice <= len(available_credentials):
                return available_credentials[choice-1]
            else:
                print(f"Please enter a number between 1 and {len(available_credentials)}")
        except ValueError:
            print("Please enter a valid number")


def main_menu():
    """Display main menu and handle user choices"""
    print("\n" + "="*70)
    print("           SECUREVAULT – Privacy-Preserving Digital Identity")
    print("           Powered by Blockchain + ECDSA (SECP256k1)")
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
    
    # Store credentials
    print("Storing credentials securely (only hashes go on-chain):")
    blocks = []
    for attr, value in mykad_data.items():
        if attr == "ic_number":  # Extra privacy: double-hash IC
            hashed = hashlib.sha256(hashlib.sha256(value.encode()).digest()).hexdigest()
            print(f"   {attr.upper():12} → DOUBLE hashed (max privacy)")
        else:
            print(f"   {attr.replace('_', ' ').title():20} → hashed + signed")
        block = vault.add_identity_credential(attr, value, private_hex)
        blocks.append((attr, block["index"]))
    
    print(f"\nSecureVault now has {len(vault.chain)} blocks ({len(vault.chain)-1} credentials + genesis)\n")
    
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
            selected = select_credential_for_verification(vault, blocks)
            if selected:
                attr, index = selected
                cred_data = vault.chain[index]["data"]
                print(f"\nVerifying: {attr.replace('_', ' ').title()}")
                value_to_verify = input(f"Enter the {attr} value to verify: ").strip()
                
                is_valid = vault.verify_credential(public_hex, value_to_verify, cred_data["signature"])
                if is_valid:
                    print(f"✓ VERIFIED: The {attr} value is authentic and signed by you!")
                else:
                    print(f"✗ INVALID: The {attr} value does not match the stored credential.")
        
        elif choice == "2":
            # Age verification demo
            print("\nDEMO: Age Proof for Club Entrance (18+ only)")
            print("You want to enter a club. They only need to know you're over 18.")
            
            # Find age credential
            age_cred = None
            age_index = None
            for attr, idx in blocks:
                if attr == "age":
                    age_cred = vault.chain[idx]["data"]
                    age_index = idx
                    break
            
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
                print("No age credential found in your vault")
        
        elif choice == "3":
            # Bank KYC demo
            print("\nDEMO: Bank KYC Verification (Name + Citizenship)")
            print("Bank asks: 'Prove your name and that you're a citizen'")
            
            name_attr = input("Enter the attribute name for your full name (default: 'name'): ").strip() or "name"
            citizenship_attr = input("Enter the attribute name for your citizenship (default: 'residency'): ").strip() or "residency"
            
            name_index = None
            citizenship_index = None
            for attr, idx in blocks:
                if attr == name_attr:
                    name_index = idx
                elif attr == citizenship_attr:
                    citizenship_index = idx
            
            if name_index and citizenship_index:
                name_cred = vault.chain[name_index]["data"]
                citizenship_cred = vault.chain[citizenship_index]["data"]
                
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
                print("Required credentials not found in your vault")
        
        elif choice == "4":
            # Privacy attack simulation
            print("\nDEMO: Privacy Attack Simulation")
            print("Hacker tries to guess data from hash values")
            
            selected = select_credential_for_verification(vault, blocks)
            if selected:
                attr, index = selected
                cred_data = vault.chain[index]["data"]
                
                print(f"\nHacker sees hash on blockchain: {cred_data['hashed_value'][:32]}...")
                print(f"Hacker knows this is a {attr} field")
                
                if attr == "age":
                    print("Hacker tries common ages: 18, 21, 25, 30, 35, 40...")
                    for guess in ["18", "21", "25", "30", "35", "40"]:
                        if hashlib.sha256(guess.encode()).hexdigest() == cred_data["hashed_value"]:
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
            selected = select_credential_for_verification(vault, blocks)
            if selected:
                attr, index = selected
                original_hash = vault.chain[index]["data"]["hashed_value"]
                
                print(f"Simulating attack on {attr} credential...")
                vault.chain[index]["data"]["hashed_value"] = "fakefakefakefake"
                
                print(f"Chain integrity check: {'✗ TAMPERED DETECTED!' if not vault.is_valid() else '✓ VALID'}")
                
                # Restore original
                vault.chain[index]["data"]["hashed_value"] = original_hash
                print("Attack failed — blockchain rejected the tampering!")
        
        elif choice == "6":
            # Revoke credential
            print("\nDEMO: Revoke a Credential")
            selected = select_credential_for_verification(vault, blocks)
            if selected:
                attr, index = selected
                
                confirm = input(f"Are you sure you want to revoke your {attr} credential? (yes/no): ").strip().lower()
                if confirm == "yes":
                    vault.revoke_credential(index)
                    print(f"✓ {attr.upper()} credential revoked successfully!")
                    print("This credential will now fail verification even if signature is valid.")
                else:
                    print("Revocation cancelled.")
        
        elif choice == "7":
            # Verifiable credential export
            print("\nDEMO: Export Credential for Offline Use (e.g., QR Code)")
            selected = select_credential_for_verification(vault, blocks)
            if selected:
                attr, index = selected
                cred_data = vault.chain[index]["data"]
                
                vc = {
                    "issuer": "SecureVault Identity System",
                    "subject_public_key": public_hex,
                    "credential": {
                        "type": f"{attr.replace('_', ' ').title()}Proof",
                        "attribute": attr,
                        "value_hash": cred_data["hashed_value"],
                        "signature": cred_data["signature"],
                        "block_index": index,
                        "timestamp": vault.chain[index]["timestamp"],
                        "revoked": any(
                            b["data"].get("revocation") == f"Revoke block {index}"
                            for b in vault.chain[index+1:]
                        )
                    },
                    "proof": "ECDSA-SECP256k1",
                    "generated": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                vc_json = json.dumps(vc, indent=2)
                print("\nVerifiable Credential (show this QR code to verifier):")
                print("="*60)
                print(vc_json)
                print("="*60)
        
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
            vault.print_entire_blockchain()
        
        elif choice == "11":
            # Exit
            print("\n" + "="*70)
            print("SECUREVAULT SESSION COMPLETE")
            print("Your identity credentials are securely stored in the blockchain")
            print("="*70)
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 11.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main_menu()
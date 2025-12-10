export const SOLIDITY_CONTRACT = `// SPDX-License-Identifier: MIT
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
}`;

export function getSolidityContract(): string {
  return SOLIDITY_CONTRACT;
}

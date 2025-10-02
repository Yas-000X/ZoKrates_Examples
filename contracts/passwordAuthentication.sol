// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./verifier.sol";

contract PasswordAuthentication {
    using Pairing for *;
    
    Verifier public verifier;
    
    // Store user password hashes
    mapping(address => uint256) public userPasswordHashes;
    
    // Track login attempts and timestamps
    mapping(address => uint256) public lastSuccessfulLogin;
    mapping(address => uint256) public failedAttempts;
    
    event UserRegistered(address indexed user, uint256 passwordHash);
    event LoginSuccessful(address indexed user);
    event LoginFailed(address indexed user);
    
    constructor(address _verifierAddress) {
        verifier = Verifier(_verifierAddress);
    }
    
    // Register a new user with password hash
    function registerUser(uint256 passwordHash) public {
        require(userPasswordHashes[msg.sender] == 0, "User already registered");
        userPasswordHashes[msg.sender] = passwordHash;
        emit UserRegistered(msg.sender, passwordHash);
    }
    
    // Login using zkSNARK proof (password remains private)
    function login(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[3] memory input // [publicStoredHash, computedHash, isValid] - 3 inputs!
    ) public returns (bool) {
        require(userPasswordHashes[msg.sender] != 0, "User not registered");
        require(input[0] == userPasswordHashes[msg.sender], "Invalid stored hash");
        
        // Create Proof struct in the format expected by the verifier
        Verifier.Proof memory proof = Verifier.Proof(
            Pairing.G1Point(a[0], a[1]),
            Pairing.G2Point([b[0][1], b[0][0]], [b[1][1], b[1][0]]),
            Pairing.G1Point(c[0], c[1])
        );
        
        // Verify the proof using verifyTx (which expects 3 inputs)
        bool proofValid = verifier.verifyTx(proof, input);
        
        if (proofValid) {
            // Successful login
            lastSuccessfulLogin[msg.sender] = block.timestamp;
            failedAttempts[msg.sender] = 0;
            emit LoginSuccessful(msg.sender);
            return true;
        } else {
            // Failed login
            failedAttempts[msg.sender]++;
            emit LoginFailed(msg.sender);
            return false;
        }
    }

    // Alternative login function that accepts the proof as a struct
    function loginWithProofStruct(
        Verifier.Proof memory proof,
        uint[3] memory input
    ) public returns (bool) {
       // require(userPasswordHashes[msg.sender] != 0, "User not registered");
       // require(input[0] == userPasswordHashes[msg.sender], "Invalid stored hash");
        
        bool proofValid = verifier.verifyTx(proof, input);
        
        if (proofValid) {
            lastSuccessfulLogin[msg.sender] = block.timestamp;
            failedAttempts[msg.sender] = 0;
            emit LoginSuccessful(msg.sender);
            return true;
        } else {
            failedAttempts[msg.sender]++;
            emit LoginFailed(msg.sender);
            return false;
        }
    }

    // Helper function to convert proof components to struct
    function createProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c
    ) public pure returns (Verifier.Proof memory) {
        return Verifier.Proof(
            Pairing.G1Point(a[0], a[1]),
            Pairing.G2Point([b[0][1], b[0][0]], [b[1][1], b[1][0]]),
            Pairing.G1Point(c[0], c[1])
        );
    }
    
    // Secure function that requires recent authentication
    function secureAction() public view returns (string memory) {
        require(userPasswordHashes[msg.sender] != 0, "Not registered");
        require(lastSuccessfulLogin[msg.sender] > 0, "Never logged in");
        require(block.timestamp - lastSuccessfulLogin[msg.sender] < 1 hours, "Session expired");
        
        return "Secure action performed successfully!";
    }
    
    // Get user status
    function getUserStatus(address user) public view returns (
        bool registered,
        uint256 lastLogin,
        uint256 failedAttemptsCount
    ) {
        return (
            userPasswordHashes[user] != 0,
            lastSuccessfulLogin[user],
            failedAttempts[user]
        );
    }

    // Update password hash (requires re-registration)
    function updatePasswordHash(uint256 newPasswordHash) public {
        require(userPasswordHashes[msg.sender] != 0, "User not registered");
        userPasswordHashes[msg.sender] = newPasswordHash;
        emit UserRegistered(msg.sender, newPasswordHash);
    }

    // Check if user is currently authenticated
    function isAuthenticated(address user) public view returns (bool) {
        return userPasswordHashes[user] != 0 && 
               lastSuccessfulLogin[user] > 0 &&
               block.timestamp - lastSuccessfulLogin[user] < 1 hours;
    }

    // Reset failed attempts (admin function)
    function resetFailedAttempts(address user) public {
        // In production, add access control
        failedAttempts[user] = 0;
    }

    // Get the verification key (for frontend use)
    function getVerifierAddress() public view returns (address) {
        return address(verifier);
    }
}

// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./interfaces/IStarknetCore.sol";

interface IPlonkVerifier {
    function verifyProof(bytes memory proof, uint256[] memory pubSignals)
        external
        view
        returns (bool);
}

interface IERC20 {
    function transfer(address recipient, uint256 amount)
        external
        returns (bool);
}

/// @title An example airdrop contract utilizing a zk-proof of MerkleTree inclusion.
contract PrivateAirdrop is Ownable {
    IPlonkVerifier verifier;

    bytes32 public root;

    mapping(bytes32 => bool) public nullifierSpent;

    uint256 constant SNARK_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IStarknetCore starknetCore;
    uint256 private l2ContractAddress;
    uint256 private CLAIM_SELECTOR;

    constructor(
        IPlonkVerifier _verifier,
        bytes32 _root,
        address starknetCore_
    ) {
        verifier = _verifier;
        root = _root;
        starknetCore = IStarknetCore(starknetCore_);
    }

    function setl2ContractAddress(uint256 _l2ContractAddress)
        external
        onlyOwner
    {
        l2ContractAddress = _l2ContractAddress;
    }

    function claimSelector() public view virtual returns (uint256) {
        return CLAIM_SELECTOR;
    }

    function setClaimSelector(uint256 _claimSelector) external onlyOwner {
        CLAIM_SELECTOR = _claimSelector;
    }

    /// @notice verifies the proof, collects the airdrop if valid, and prevents this proof from working again.
    function collectAirdrop(
        bytes calldata proof,
        bytes32 nullifierHash,
        uint256 l2_user
    ) public {
        require(
            uint256(nullifierHash) < SNARK_FIELD,
            "Nullifier is not within the field"
        );
        require(!nullifierSpent[nullifierHash], "Airdrop already redeemed");

        uint256[] memory pubSignals = new uint256[](3);
        pubSignals[0] = uint256(root);
        pubSignals[1] = uint256(nullifierHash);
        pubSignals[2] = uint256(uint160(msg.sender));
        require(
            verifier.verifyProof(proof, pubSignals),
            "Proof verification failed"
        );

        nullifierSpent[nullifierHash] = true;

        // Construct the deposit message's payload.
        uint256[] memory payload = new uint256[](3);
        payload[0] = l2_user;
        starknetCore.sendMessageToL2(
            l2ContractAddress,
            CLAIM_SELECTOR,
            payload
        );
    }

    /// @notice Allows the owner to update the root of the merkle tree.
    /// @dev Function can be removed to make the merkle tree immutable. If removed, the ownable extension can also be removed for gas savings.
    function updateRoot(bytes32 newRoot) public onlyOwner {
        root = newRoot;
    }
}

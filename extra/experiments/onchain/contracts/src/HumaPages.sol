// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {HumaFinal1024Verifier} from "./HumaFinal1024Verifier.sol";
import {HumaFinal4096Verifier} from "./HumaFinal4096Verifier.sol";
import {HumaFinal10000Verifier} from "./HumaFinal10000Verifier.sol";

interface IHumaVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// Public record of Huma pages whose complete proof verified on-chain.
///
/// A Huma page proof (integrations/noir/long, assurance-long-v2) is one proof per page: every part
/// of the writing session and every Touch ID signature is checked inside it. Its public inputs are
/// the page's statement (45 fields: text commitments, the timing summary, writing-rule results, the
/// signed-event digest and the capture key commitment) followed by the wallet it was made for.
/// This contract verifies the proof with the verifier for the page's text tier and records that
/// wallet and the block, keyed by the keccak of the statement. Anyone may submit. Only the device
/// that recorded the session can make a proof for a given wallet, so copying a proof claims nothing.
contract HumaPages {
    uint256 internal constant STATEMENT = 45; // statement fields; the owner follows them
    uint256 internal constant TIER = 14; // text_capacity
    uint256 internal constant RULES = 33; // the nine writing-rule results
    /// Rules a page must meet to be recorded (bit i = rule i): all nine. No imported text (0), every
    /// edit typed (1), at least 20 seconds of writing (2) and 30 key presses (3), natural key presses (4),
    /// key holds (5) and rhythm (6), at least one pause (7) and a human typing speed (8).
    uint256 internal constant REQUIRED_RULES = (1 << 9) - 1;

    struct Page {
        address owner;
        uint64 blockNumber;
    }

    IHumaVerifier public immutable verifier1024;
    IHumaVerifier public immutable verifier4096;
    IHumaVerifier public immutable verifier10000;
    /// keccak256 of the 45 statement fields => the wallet and block of its verification.
    mapping(bytes32 => Page) public pages;

    event PageVerified(bytes32 indexed statement, address indexed owner, uint256 tier);

    error AlreadyVerified();
    error InvalidProof();
    error InvalidStatement();

    constructor(IHumaVerifier v1024, IHumaVerifier v4096, IHumaVerifier v10000) {
        verifier1024 = v1024;
        verifier4096 = v4096;
        verifier10000 = v10000;
    }

    /// Verifies a page proof and records it. Only pages that met the required writing rules are recorded.
    function submit(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bytes32 statement) {
        if (publicInputs.length != STATEMENT + 1) revert InvalidStatement();
        for (uint256 i; i < 9; ++i) {
            if ((REQUIRED_RULES >> i) & 1 == 1 && uint256(publicInputs[RULES + i]) != 1) revert InvalidStatement();
        }
        uint256 wallet = uint256(publicInputs[STATEMENT]);
        if (wallet == 0 || wallet >> 160 != 0) revert InvalidStatement();
        uint256 tier = uint256(publicInputs[TIER]);
        IHumaVerifier verifier =
            tier == 1024 ? verifier1024 : tier == 4096 ? verifier4096 : tier == 10000 ? verifier10000 : IHumaVerifier(address(0));
        if (address(verifier) == address(0)) revert InvalidStatement();
        statement = keccak256(abi.encodePacked(publicInputs[:STATEMENT]));
        if (pages[statement].blockNumber != 0) revert AlreadyVerified();
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();
        address owner = address(uint160(wallet));
        pages[statement] = Page(owner, uint64(block.number));
        emit PageVerified(statement, owner, tier);
    }
}

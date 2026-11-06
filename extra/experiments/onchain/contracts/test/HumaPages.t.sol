// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {HumaPages, IHumaVerifier} from "../src/HumaPages.sol";
import {HumaFinal1024Verifier} from "../src/HumaFinal1024Verifier.sol";
import {HumaFinal4096Verifier} from "../src/HumaFinal4096Verifier.sol";
import {HumaFinal10000Verifier} from "../src/HumaFinal10000Verifier.sol";

interface Vm {
    function readFile(string calldata) external view returns (string memory);
    function parseJsonBytes(string calldata, string calldata) external pure returns (bytes memory);
    function parseJsonBytes32Array(string calldata, string calldata) external pure returns (bytes32[] memory);
    function roll(uint256) external;
    function expectRevert(bytes4) external;
    function expectRevert() external;
}

/// Fixture: a 600-character recording made in the Mac app (8 folded parts), its on-chain proof made by the
/// app's worker for wallet 0x19e7…ff2a (FoldedLongProofTests, HUMA_LONG_E2E=1).
contract HumaPagesTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    HumaPages pages;
    bytes proof;
    bytes32[] inputs;
    address constant OWNER = 0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A;

    function setUp() public {
        pages = new HumaPages(IHumaVerifier(address(new HumaFinal1024Verifier())),
            IHumaVerifier(address(new HumaFinal4096Verifier())), IHumaVerifier(address(new HumaFinal10000Verifier())));
        string memory json = vm.readFile("test/fixtures/page.json");
        proof = vm.parseJsonBytes(json, ".proof");
        inputs = vm.parseJsonBytes32Array(json, ".publicInputs");
    }

    function statementOf(bytes32[] memory values) internal pure returns (bytes32) {
        bytes32[] memory statement = new bytes32[](45);
        for (uint256 i = 0; i < 45; i++) statement[i] = values[i];
        return keccak256(abi.encodePacked(statement));
    }

    function test_recordsAVerifiedPageForItsWallet() public {
        vm.roll(42);
        bytes32 statement = pages.submit(proof, inputs);
        require(statement == statementOf(inputs), "statement key");
        (address owner, uint64 blockNumber) = pages.pages(statement);
        require(owner == OWNER && blockNumber == 42, "not recorded");
    }

    function test_aPageIsRecordedOnce() public {
        pages.submit(proof, inputs);
        vm.expectRevert(HumaPages.AlreadyVerified.selector);
        pages.submit(proof, inputs);
    }

    function test_aCopiedProofCannotNameAnotherWallet() public {
        inputs[45] = bytes32(uint256(uint160(address(0xBEEF))));
        vm.expectRevert();
        pages.submit(proof, inputs);
    }

    function test_rejectsATamperedProofOrStatement() public {
        bytes memory bad = proof;
        bad[400] ^= 0x01;
        vm.expectRevert();
        pages.submit(bad, inputs);
        inputs[13] = bytes32(uint256(inputs[13]) ^ 1); // canonical text commitment
        vm.expectRevert();
        pages.submit(proof, inputs);
    }

    function copy(bytes32[] memory a) internal pure returns (bytes32[] memory b) {
        b = new bytes32[](a.length);
        for (uint256 i; i < a.length; ++i) b[i] = a[i];
    }

    function test_onlyPagesThatMetTheRequiredRulesAndKnownTiers() public {
        bytes32[] memory rhythm = copy(inputs);
        rhythm[33 + 6] = 0; // typing rhythm is required
        vm.expectRevert(HumaPages.InvalidStatement.selector);
        pages.submit(proof, rhythm);
        bytes32[] memory imported = copy(inputs);
        imported[33] = 0; // started from imported text
        vm.expectRevert(HumaPages.InvalidStatement.selector);
        pages.submit(proof, imported);
        // Length, key count and pauses are required too, so a short burst of typing isn't recorded.
        uint8[3] memory lengthRules = [2, 3, 7];
        for (uint256 i; i < 3; ++i) {
            bytes32[] memory short = copy(inputs);
            short[33 + lengthRules[i]] = 0;
            vm.expectRevert(HumaPages.InvalidStatement.selector);
            pages.submit(proof, short);
        }
        bytes32[] memory tier = copy(inputs);
        tier[14] = bytes32(uint256(2048));
        vm.expectRevert(HumaPages.InvalidStatement.selector);
        pages.submit(proof, tier);
        bytes32[] memory nobody = copy(inputs);
        nobody[45] = 0;
        vm.expectRevert(HumaPages.InvalidStatement.selector);
        pages.submit(proof, nobody);
    }
}

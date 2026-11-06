// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";
import {HumaChunk1024Verifier} from "../src/HumaChunk1024Verifier.sol";
import {HumaFinal1024Verifier} from "../src/HumaFinal1024Verifier.sol";
import {HumaChunk4096Verifier} from "../src/HumaChunk4096Verifier.sol";
import {HumaFinal4096Verifier} from "../src/HumaFinal4096Verifier.sol";
import {HumaChunk10000Verifier} from "../src/HumaChunk10000Verifier.sol";
import {HumaFinal10000Verifier} from "../src/HumaFinal10000Verifier.sol";
import {HumaPagesV3, IHonkVerifier} from "../src/HumaPagesV3.sol";

/// Real EVM proofs (bb 5.2.1, `-t evm`) of the existing long3 circuits for long-case-400 (tier 1024, 4 parts + final),
/// and, when present, a tier-4096 case in ../proofs/<case>/.
contract HumaPagesV3Test is Test {
    string constant EVM = "test/fixtures/long-case-400/";
    string constant BROWSER = "test/fixtures/browser-long-case-400/";
    uint256 constant PARTS = 4;

    IHonkVerifier[6] v;
    HumaPagesV3 pages;
    bytes[] proofs;
    bytes32[3][] inputs;
    bytes finalProof;
    bytes32[] finalInputs;

    function setUp() public {
        v = [
            IHonkVerifier(address(new HumaChunk1024Verifier())),
            IHonkVerifier(address(new HumaFinal1024Verifier())),
            IHonkVerifier(address(new HumaChunk4096Verifier())),
            IHonkVerifier(address(new HumaFinal4096Verifier())),
            IHonkVerifier(address(new HumaChunk10000Verifier())),
            IHonkVerifier(address(new HumaFinal10000Verifier()))
        ];
        pages = new HumaPagesV3(v[0], v[1], v[2], v[3], v[4], v[5]);
        (proofs, inputs, finalProof, finalInputs) = load(EVM, PARTS);
    }

    function load(string memory dir, uint256 parts)
        internal
        view
        returns (bytes[] memory ps, bytes32[3][] memory ins, bytes memory fp, bytes32[] memory fi)
    {
        ps = new bytes[](parts);
        ins = new bytes32[3][](parts);
        for (uint256 i; i < parts; ++i) {
            string memory d = string.concat(dir, "part", vm.toString(i), "/");
            ps[i] = vm.readFileBinary(string.concat(d, "proof"));
            bytes32[] memory pi = fields(vm.readFileBinary(string.concat(d, "public_inputs")));
            ins[i] = [pi[0], pi[1], pi[2]];
        }
        fp = vm.readFileBinary(string.concat(dir, "final/proof"));
        fi = fields(vm.readFileBinary(string.concat(dir, "final/public_inputs")));
    }

    function fields(bytes memory raw) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](raw.length / 32);
        for (uint256 i; i < out.length; ++i) {
            bytes32 word;
            assembly { word := mload(add(add(raw, 32), mul(i, 32))) }
            out[i] = word;
        }
    }

    function three(bytes32[3] memory x) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](3);
        (pi[0], pi[1], pi[2]) = (x[0], x[1], x[2]);
    }

    function tryVerify(IHonkVerifier verifier, bytes memory proof, bytes32[] memory pi) internal view returns (bool) {
        try verifier.verify(proof, pi) returns (bool ok) { return ok; } catch { return false; }
    }

    function slice(uint256 from, uint256 to) internal view returns (bytes[] memory ps, bytes32[3][] memory ins) {
        ps = new bytes[](to - from);
        ins = new bytes32[3][](to - from);
        for (uint256 i = from; i < to; ++i) (ps[i - from], ins[i - from]) = (proofs[i], inputs[i]);
    }

    // ---- one transaction ----

    function test_EachProofVerifiesAndGas() public view {
        for (uint256 i; i < PARTS; ++i) {
            uint256 g = gasleft();
            assertTrue(v[0].verify(proofs[i], three(inputs[i])));
            console.log("tier 1024: verify part gas", i, g - gasleft());
        }
        uint256 g2 = gasleft();
        assertTrue(v[1].verify(finalProof, finalInputs));
        console.log("tier 1024: verify final gas", g2 - gasleft());
    }

    function test_SubmitValidPage() public {
        uint256 g = gasleft();
        bytes32 statement = pages.submit(proofs, inputs, finalProof, finalInputs);
        console.log("tier 1024: submit 4-part page gas (execution)", g - gasleft());
        assertEq(statement, keccak256(abi.encodePacked(finalInputs)));
        assertTrue(pages.verified(statement));
        (uint64 blockNumber, uint32 parts, uint32 tier, address submitter) = pages.pages(statement);
        assertEq(blockNumber, block.number);
        assertEq(parts, PARTS);
        assertEq(tier, 1024);
        assertEq(submitter, address(this));
    }

    function test_EmitsPageVerified() public {
        vm.expectEmit(true, true, false, true, address(pages));
        emit HumaPagesV3.PageVerified(keccak256(abi.encodePacked(finalInputs)), address(this), 1024, PARTS);
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectDoubleSubmit() public {
        pages.submit(proofs, inputs, finalProof, finalInputs);
        vm.expectRevert(HumaPagesV3.AlreadyVerified.selector);
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectTamperedPartProof() public {
        proofs[2][proofs[2].length / 2] ^= bytes1(0x01);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.InvalidPartProof.selector, 2));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectTamperedFinalProof() public {
        finalProof[finalProof.length / 2] ^= bytes1(0x01);
        vm.expectRevert(HumaPagesV3.InvalidFinalProof.selector);
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectTamperedStatement() public {
        // canonical_commitment (index 13): a different text claimed with the same proof.
        finalInputs[13] = bytes32(uint256(finalInputs[13]) + 1);
        vm.expectRevert(HumaPagesV3.InvalidFinalProof.selector);
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectTamperedPartInput() public {
        // A changed end root that still links up: part 3's start and the final state follow it, so only the proof catches it.
        bytes32 forged = bytes32(uint256(inputs[3][1]) + 1);
        inputs[3][1] = forged;
        finalInputs[2] = forged;
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.InvalidPartProof.selector, 3));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectReorderedParts() public {
        (bytes memory p1, bytes memory p2) = (proofs[1], proofs[2]);
        (bytes32[3] memory i1, bytes32[3] memory i2) = (inputs[1], inputs[2]);
        (proofs[1], proofs[2], inputs[1], inputs[2]) = (p2, p1, i2, i1);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 1));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectDroppedPart() public {
        proofs.pop();
        inputs.pop();
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 3));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectGenesisNotFirst() public {
        inputs[0][2] = bytes32(0);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 0));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectNoParts() public {
        bytes[] memory none;
        bytes32[3][] memory noInputs;
        vm.expectRevert(HumaPagesV3.NoParts.selector);
        pages.submit(none, noInputs, finalProof, finalInputs);
    }

    function test_RejectTooManyPartsInOneTx() public {
        uint256 n = pages.MAX_PARTS_PER_TX() + 1;
        bytes[] memory ps = new bytes[](n);
        bytes32[3][] memory ins = new bytes32[3][](n);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.TooManyParts.selector, n));
        pages.submit(ps, ins, finalProof, finalInputs);
    }

    function test_RejectWrongStatementLength() public {
        finalInputs.pop();
        vm.expectRevert(HumaPagesV3.InvalidStatement.selector);
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    // ---- tier routing ----

    function test_RejectTierChangedTo4096() public {
        // The statement claims a longer page: routed to the 4096 verifiers, which reject the 1024 circuit's proofs.
        finalInputs[14] = bytes32(uint256(4096));
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.InvalidPartProof.selector, 0));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectTierChangedTo10000() public {
        finalInputs[14] = bytes32(uint256(10000));
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.InvalidPartProof.selector, 0));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_RejectUnsupportedTier() public {
        finalInputs[14] = bytes32(uint256(2048));
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.UnsupportedTier.selector, 2048));
        pages.submit(proofs, inputs, finalProof, finalInputs);
    }

    function test_OtherTierVerifiersRejectTier1024Proofs() public view {
        assertFalse(tryVerify(v[2], proofs[0], three(inputs[0])), "chunk4096");
        assertFalse(tryVerify(v[4], proofs[0], three(inputs[0])), "chunk10000");
        assertFalse(tryVerify(v[3], finalProof, finalInputs), "final4096");
        assertFalse(tryVerify(v[5], finalProof, finalInputs), "final10000");
    }

    // ---- several transactions ----

    function test_MultiTxPage() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        (bytes[] memory b, bytes32[3][] memory bi) = slice(2, 4);
        uint256 g = gasleft();
        bytes32 session = pages.submitParts(genesis, 1024, 0, a, ai);
        console.log("tier 1024: submitParts 2 parts gas (execution)", g - gasleft());
        assertEq(session, keccak256(abi.encodePacked(address(this), genesis)));
        (bytes32 end, uint32 next, uint32 tier) = pages.progress(session);
        assertEq(end, inputs[1][1]);
        assertEq(next, 2);
        assertEq(tier, 1024);
        pages.submitParts(genesis, 1024, 2, b, bi);
        g = gasleft();
        bytes32 statement = pages.submitFinal(genesis, finalProof, finalInputs);
        console.log("tier 1024: submitFinal gas (execution)", g - gasleft());
        assertEq(statement, keccak256(abi.encodePacked(finalInputs)));
        (, uint32 parts,,) = pages.pages(statement);
        assertEq(parts, PARTS);
        (, next,) = pages.progress(session);
        assertEq(next, 0, "progress cleared");
        vm.expectRevert(HumaPagesV3.UnknownSession.selector);
        pages.submitFinal(genesis, finalProof, finalInputs);
    }

    function test_MultiTxRejectsGap() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        (bytes[] memory c, bytes32[3][] memory ci) = slice(3, 4);
        pages.submitParts(genesis, 1024, 0, a, ai);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 3));
        pages.submitParts(genesis, 1024, 3, c, ci);
    }

    function test_MultiTxRejectsWrongContinuation() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        pages.submitParts(genesis, 1024, 0, a, ai);
        // Part 3 sent as if it were part 2: it does not start where part 1 ended.
        (bytes[] memory c, bytes32[3][] memory ci) = slice(3, 4);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 2));
        pages.submitParts(genesis, 1024, 2, c, ci);
    }

    function test_MultiTxSessionsArePerSubmitter() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        (bytes[] memory b, bytes32[3][] memory bi) = slice(2, 4);
        pages.submitParts(genesis, 1024, 0, a, ai);
        vm.prank(address(0xBEEF));
        vm.expectRevert(HumaPagesV3.UnknownSession.selector);
        pages.submitParts(genesis, 1024, 2, b, bi);
        vm.prank(address(0xBEEF));
        vm.expectRevert(HumaPagesV3.UnknownSession.selector);
        pages.submitFinal(genesis, finalProof, finalInputs);
    }

    function test_MultiTxRejectsFinalBeforeAllParts() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        pages.submitParts(genesis, 1024, 0, a, ai);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 2));
        pages.submitFinal(genesis, finalProof, finalInputs);
    }

    function test_MultiTxRejectsTierMismatch() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory all, bytes32[3][] memory alli) = slice(0, 4);
        pages.submitParts(genesis, 1024, 0, all, alli);
        finalInputs[14] = bytes32(uint256(4096));
        vm.expectRevert(HumaPagesV3.InvalidStatement.selector);
        pages.submitFinal(genesis, finalProof, finalInputs);
    }

    function test_MultiTxPartsAtWrongTierRejected() public {
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.InvalidPartProof.selector, 0));
        pages.submitParts(inputs[0][0], 4096, 0, a, ai);
    }

    function test_MultiTxRejectsTamperedFinal() public {
        bytes32 genesis = inputs[0][0];
        (bytes[] memory all, bytes32[3][] memory alli) = slice(0, 4);
        pages.submitParts(genesis, 1024, 0, all, alli);
        finalProof[100] ^= bytes1(0x01);
        vm.expectRevert(HumaPagesV3.InvalidFinalProof.selector);
        pages.submitFinal(genesis, finalProof, finalInputs);
    }

    function test_MultiTxAfterSingleTxIsAlreadyVerified() public {
        pages.submit(proofs, inputs, finalProof, finalInputs);
        bytes32 genesis = inputs[0][0];
        (bytes[] memory all, bytes32[3][] memory alli) = slice(0, 4);
        pages.submitParts(genesis, 1024, 0, all, alli);
        vm.expectRevert(HumaPagesV3.AlreadyVerified.selector);
        pages.submitFinal(genesis, finalProof, finalInputs);
    }

    function test_MultiTxGenesisMustMatchSession() public {
        (bytes[] memory a, bytes32[3][] memory ai) = slice(0, 2);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.BrokenLinkage.selector, 0));
        pages.submitParts(bytes32(uint256(inputs[0][0]) + 1), 1024, 0, a, ai);
    }

    // ---- tier 4096: a real 1,500-character page (long-case-1500), 14 parts: more than one transaction holds ----

    string constant EVM4096 = "test/fixtures/long-case-1500/";
    uint256 constant PARTS4096 = 14;

    function test_Tier4096EachProofVerifies() public view {
        (bytes[] memory ps, bytes32[3][] memory ins, bytes memory fp, bytes32[] memory fi) = load(EVM4096, PARTS4096);
        assertEq(uint256(fi[14]), 4096);
        for (uint256 i; i < PARTS4096; ++i) {
            assertTrue(v[2].verify(ps[i], three(ins[i])));
            assertFalse(tryVerify(v[0], ps[i], three(ins[i])), "chunk1024 rejects a 4096 part");
        }
        assertTrue(v[3].verify(fp, fi));
        assertFalse(tryVerify(v[1], fp, fi), "final1024 rejects a 4096 final");
    }

    function test_Tier4096TooLongForOneTx() public {
        (bytes[] memory ps, bytes32[3][] memory ins, bytes memory fp, bytes32[] memory fi) = load(EVM4096, PARTS4096);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.TooManyParts.selector, PARTS4096));
        pages.submit(ps, ins, fp, fi);
    }

    function test_Tier4096MultiTxPage() public {
        (bytes[] memory ps, bytes32[3][] memory ins, bytes memory fp, bytes32[] memory fi) = load(EVM4096, PARTS4096);
        (bytes[] memory a, bytes32[3][] memory ai) = (new bytes[](7), new bytes32[3][](7));
        (bytes[] memory b, bytes32[3][] memory bi) = (new bytes[](7), new bytes32[3][](7));
        for (uint256 i; i < 7; ++i) (a[i], ai[i], b[i], bi[i]) = (ps[i], ins[i], ps[i + 7], ins[i + 7]);
        bytes32 genesis = ins[0][0];
        pages.submitParts(genesis, 4096, 0, a, ai);
        pages.submitParts(genesis, 4096, 7, b, bi);
        bytes32 statement = pages.submitFinal(genesis, fp, fi);
        (, uint32 parts, uint32 tier,) = pages.pages(statement);
        assertEq(parts, PARTS4096);
        assertEq(tier, 4096);
        assertTrue(pages.verified(statement));
    }

    function test_Tier4096PartsRejectedAsTier1024() public {
        (bytes[] memory ps, bytes32[3][] memory ins,,) = load(EVM4096, PARTS4096);
        (bytes[] memory a, bytes32[3][] memory ai) = (new bytes[](2), new bytes32[3][](2));
        (a[0], a[1], ai[0], ai[1]) = (ps[0], ps[1], ins[0], ins[1]);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV3.InvalidPartProof.selector, 0));
        pages.submitParts(ins[0][0], 1024, 0, a, ai);
    }

    function test_Tier4096FinalClaimingTier1024Rejected() public {
        (bytes[] memory ps, bytes32[3][] memory ins, bytes memory fp, bytes32[] memory fi) = load(EVM4096, PARTS4096);
        (bytes[] memory a, bytes32[3][] memory ai) = (new bytes[](12), new bytes32[3][](12));
        (bytes[] memory b, bytes32[3][] memory bi) = (new bytes[](2), new bytes32[3][](2));
        for (uint256 i; i < 12; ++i) (a[i], ai[i]) = (ps[i], ins[i]);
        for (uint256 i; i < 2; ++i) (b[i], bi[i]) = (ps[i + 12], ins[i + 12]);
        pages.submitParts(ins[0][0], 4096, 0, a, ai);
        pages.submitParts(ins[0][0], 4096, 12, b, bi);
        fi[14] = bytes32(uint256(1024));
        vm.expectRevert(HumaPagesV3.InvalidStatement.selector);
        pages.submitFinal(ins[0][0], fp, fi);
    }

    // ---- tier 10000: a real 4,200-character page (long-case-4200), 38 parts in four batches ----

    string constant EVM10000 = "test/fixtures/long-case-4200/";
    uint256 constant PARTS10000 = 38;

    function test_Tier10000MultiTxPage() public {
        (bytes[] memory ps, bytes32[3][] memory ins, bytes memory fp, bytes32[] memory fi) = load(EVM10000, PARTS10000);
        assertEq(uint256(fi[14]), 10000);
        bytes32 genesis = ins[0][0];
        uint256 batch = pages.MAX_PARTS_PER_TX();
        for (uint256 at; at < PARTS10000; at += batch) {
            uint256 n = PARTS10000 - at < batch ? PARTS10000 - at : batch;
            (bytes[] memory b, bytes32[3][] memory bi) = (new bytes[](n), new bytes32[3][](n));
            for (uint256 i; i < n; ++i) (b[i], bi[i]) = (ps[at + i], ins[at + i]);
            pages.submitParts(genesis, 10000, at, b, bi);
        }
        bytes32 statement = pages.submitFinal(genesis, fp, fi);
        (, uint32 parts, uint32 tier,) = pages.pages(statement);
        assertEq(parts, PARTS10000);
        assertEq(tier, 10000);
        assertFalse(tryVerify(v[2], ps[0], three(ins[0])), "chunk4096 rejects a 10000 part");
        assertFalse(tryVerify(v[3], fp, fi), "final4096 rejects a 10000 final");
    }

    // ---- the browser's current proofs ----

    /// The browser's existing proofs (noir-recursive: Poseidon2 transcript) of the SAME circuits, same public inputs.
    function test_BrowserProofsRejectedByEvmVerifiers() public view {
        for (uint256 i; i < PARTS; ++i) {
            bytes memory browser = vm.readFileBinary(string.concat(BROWSER, "part", vm.toString(i), "/proof"));
            bytes32[] memory pi = fields(vm.readFileBinary(string.concat(BROWSER, "part", vm.toString(i), "/public_inputs")));
            assertEq(keccak256(abi.encodePacked(pi)), keccak256(abi.encodePacked(three(inputs[i]))), "same public inputs");
            assertFalse(tryVerify(v[0], browser, pi));
        }
        assertFalse(tryVerify(v[1], vm.readFileBinary(string.concat(BROWSER, "final/proof")), finalInputs));
    }
}

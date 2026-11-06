// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {HumaChunk1024Verifier} from "../src/HumaChunk1024Verifier.sol";
import {HumaFinal1024Verifier} from "../src/HumaFinal1024Verifier.sol";
import {HumaChunk4096Verifier} from "../src/HumaChunk4096Verifier.sol";
import {HumaFinal4096Verifier} from "../src/HumaFinal4096Verifier.sol";
import {HumaChunk10000Verifier} from "../src/HumaChunk10000Verifier.sol";
import {HumaFinal10000Verifier} from "../src/HumaFinal10000Verifier.sol";
import {HumaPoseidon2} from "../src/HumaPoseidon2.sol";
import {HumaPagesV4, IHonkVerifier, IPoseidon2} from "../src/HumaPagesV4.sol";

/// Exposes the event and passkey checks, to test passkey pages with keys made here (no real passkey page is in the
/// fixtures).
contract HumaPagesV4Harness is HumaPagesV4 {
    constructor(IHonkVerifier[6] memory v, IPoseidon2 p) HumaPagesV4(v[0], v[1], v[2], v[3], v[4], v[5], p) {}

    function events(Writer calldata writer, Event[] calldata list, Assertion[] calldata assertions) external view returns (uint256 digest, uint256 counter) {
        Events memory e = _verifyEvents(writer, Events(0, 0, 0, 0, 0, 0), list, assertions);
        return (e.digest, e.counter);
    }

    function base64url(bytes32 value) external pure returns (bytes memory) {
        return _base64url(value);
    }
}

/// Real pages: EVM proofs (bb 5.2.1, `-t evm`) of the existing long3 circuits, and each session's signed events
/// (test/fixtures/<case>/evidence.json, scripts/evidence-fixtures.mjs). Base's P-256 precompile (RIP-7212, 0x100) is
/// stood in for by Foundry's own P-256 when the EVM version has it (osaka), see setUp.
contract HumaPagesV4Test is Test {
    HumaPagesV4Harness pages;
    IHonkVerifier[6] verifiers;

    function setUp() public {
        // Base's P-256 precompile (RIP-7212) at 0x100: where this EVM has none, Daimo's P256Verifier, which takes the same
        // input and answers the same (its runtime code from Base Sepolia, 0xc2b78104907F722DABAc4C69f826a522B2754De4).
        vm.etch(address(0x100), vm.parseBytes(vm.trim(vm.readFile("test/fixtures/p256-verifier.hex"))));
        verifiers = [
            IHonkVerifier(address(new HumaChunk1024Verifier())),
            IHonkVerifier(address(new HumaFinal1024Verifier())),
            IHonkVerifier(address(new HumaChunk4096Verifier())),
            IHonkVerifier(address(new HumaFinal4096Verifier())),
            IHonkVerifier(address(new HumaChunk10000Verifier())),
            IHonkVerifier(address(new HumaFinal10000Verifier()))
        ];
        pages = new HumaPagesV4Harness(verifiers, IPoseidon2(address(new HumaPoseidon2())));
    }

    // ---- fixtures ----

    function fields(bytes memory raw) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](raw.length / 32);
        for (uint256 i; i < out.length; ++i) {
            bytes32 w;
            assembly { w := mload(add(add(raw, 32), mul(i, 32))) }
            out[i] = w;
        }
    }

    function proofs(string memory name, uint256 parts) internal view returns (HumaPagesV4.Proofs memory p) {
        string memory dir = string.concat("test/fixtures/", name, "/");
        p.partProofs = new bytes[](parts);
        p.partInputs = new bytes32[3][](parts);
        for (uint256 i; i < parts; ++i) {
            string memory d = string.concat(dir, "part", vm.toString(i), "/");
            p.partProofs[i] = vm.readFileBinary(string.concat(d, "proof"));
            bytes32[] memory pi = fields(vm.readFileBinary(string.concat(d, "public_inputs")));
            p.partInputs[i] = [pi[0], pi[1], pi[2]];
        }
        p.finalProof = vm.readFileBinary(string.concat(dir, "final/proof"));
        p.finalInputs = fields(vm.readFileBinary(string.concat(dir, "final/public_inputs")));
    }

    function evidence(string memory name) internal view returns (HumaPagesV4.Evidence memory ev) {
        string memory json = vm.readFile(string.concat("test/fixtures/", name, "/evidence.json"));
        ev.writer.x = vm.parseJsonBytes32(json, ".x");
        ev.writer.y = vm.parseJsonBytes32(json, ".y");
        uint256[] memory kinds = vm.parseJsonUintArray(json, ".kinds");
        bytes32[] memory roots = vm.parseJsonBytes32Array(json, ".roots");
        bytes32[] memory r = vm.parseJsonBytes32Array(json, ".r");
        bytes32[] memory s = vm.parseJsonBytes32Array(json, ".s");
        ev.events = new HumaPagesV4.Event[](kinds.length);
        for (uint256 i; i < kinds.length; ++i) ev.events[i] = HumaPagesV4.Event(uint8(kinds[i]), roots[i], r[i], s[i]);
    }

    function slice(HumaPagesV4.Event[] memory list, uint256 from, uint256 to) internal pure returns (HumaPagesV4.Event[] memory out) {
        out = new HumaPagesV4.Event[](to - from);
        for (uint256 i = from; i < to; ++i) out[i - from] = list[i];
    }

    function noAssertions() internal pure returns (HumaPagesV4.Assertion[] memory) {
        return new HumaPagesV4.Assertion[](0);
    }

    // ---- whole pages ----

    function test_SubmitRealPage1024InOneTransaction() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        uint256 g = gasleft();
        bytes32 statement = pages.submit(p, ev);
        emit log_named_uint("gas, 1024 page (4 parts, 7 events), one tx", g - gasleft());
        assertEq(statement, keccak256(abi.encodePacked(p.finalInputs)));
        assertTrue(pages.verified(statement));
        (uint64 blockNumber, uint32 parts, uint32 tier, uint32 eventCount, bool passkey, address by) = pages.pages(statement);
        assertEq(blockNumber, block.number);
        assertEq(parts, 4);
        assertEq(tier, 1024);
        assertEq(eventCount, 7);
        assertFalse(passkey);
        assertEq(by, address(this));
        vm.expectRevert(HumaPagesV4.AlreadyVerified.selector);
        pages.submit(p, ev);
    }

    function submitInBatches(string memory name, uint256 parts, uint256 eventsPerBatch) internal returns (bytes32 statement) {
        HumaPagesV4.Proofs memory p = proofs(name, parts);
        HumaPagesV4.Evidence memory ev = evidence(name);
        bytes32 genesis = p.partInputs[0][0];
        uint256 tier = uint256(p.finalInputs[14]);
        uint256 g = gasleft();
        for (uint256 at; at < parts; at += 12) {
            uint256 end = at + 12 > parts ? parts : at + 12;
            bytes[] memory ps = new bytes[](end - at);
            bytes32[3][] memory ins = new bytes32[3][](end - at);
            for (uint256 i = at; i < end; ++i) (ps[i - at], ins[i - at]) = (p.partProofs[i], p.partInputs[i]);
            pages.submitParts(genesis, tier, at, ps, ins);
        }
        for (uint256 at; at < ev.events.length; at += eventsPerBatch) {
            uint256 end = at + eventsPerBatch > ev.events.length ? ev.events.length : at + eventsPerBatch;
            pages.submitEvents(genesis, at, HumaPagesV4.Evidence(ev.writer, slice(ev.events, at, end), noAssertions()));
        }
        statement = pages.submitFinal(genesis, p.finalProof, p.finalInputs);
        emit log_named_uint(string.concat("gas, ", name, ", batches"), g - gasleft());
        assertTrue(pages.verified(statement));
    }

    function test_SubmitRealPage4096InBatches() public {
        submitInBatches("long-case-1500", 14, 64);
    }

    function test_SubmitRealPage10000InBatchesWithSplitEvents() public {
        submitInBatches("long-case-4200", 38, 20);
    }

    // ---- what the reader would refuse ----

    function test_RejectWrongSignature() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        ev.events[3].r = bytes32(uint256(ev.events[3].r) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV4.InvalidSignature.selector, 3));
        pages.submit(p, ev);
    }

    function test_RejectChangedRoot() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        ev.events[2].root = bytes32(uint256(ev.events[2].root) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV4.InvalidSignature.selector, 2));
        pages.submit(p, ev);
    }

    function test_RejectMissingEvent() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        ev.events = slice(ev.events, 0, ev.events.length - 1);
        vm.expectRevert(HumaPagesV4.EventsDontMatch.selector);
        pages.submit(p, ev);
    }

    function test_RejectSwappedEvents() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        (ev.events[0], ev.events[1]) = (ev.events[1], ev.events[0]); // two checkpoints: still signed, out of order
        vm.expectRevert(HumaPagesV4.EventsDontMatch.selector);
        pages.submit(p, ev);
    }

    function test_RejectBadKind() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        ev.events[0].kind = 3;
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV4.InvalidEvent.selector, 0));
        pages.submit(p, ev);
    }

    /// Another key that validly signs every root: the events chain the same, but the nonce commits to the real key.
    function test_RejectAnotherKeySigningTheSameRoots() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        uint256 key = 0xA11CE;
        (ev.writer.x, ev.writer.y) = publicKey(key);
        for (uint256 i; i < ev.events.length; ++i) {
            bytes memory domain = ev.events[i].kind == 1 ? bytes("HUMA_LONG_ASSURANCE_CHECKPOINT_V1\x00") : bytes("HUMA_LONG_ASSURANCE_PRESENCE_V1\x00");
            (ev.events[i].r, ev.events[i].s) = vm.signP256(key, sha256(abi.encodePacked(domain, ev.events[i].root)));
        }
        vm.expectRevert(HumaPagesV4.NonceNotBound.selector);
        pages.submit(p, ev);
    }

    function test_RejectStatementTampered() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-400", 4);
        HumaPagesV4.Evidence memory ev = evidence("long-case-400");
        p.finalInputs[16] = bytes32(uint256(p.finalInputs[16]) + 1); // edits
        vm.expectRevert(HumaPagesV4.InvalidFinalProof.selector);
        pages.submit(p, ev);
    }

    function test_RejectWrongWriterInALaterBatch() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-1500", 14);
        HumaPagesV4.Evidence memory ev = evidence("long-case-1500");
        bytes32 genesis = p.partInputs[0][0];
        pages.submitEvents(genesis, 0, HumaPagesV4.Evidence(ev.writer, slice(ev.events, 0, 5), noAssertions()));
        HumaPagesV4.Writer memory other = ev.writer;
        other.y = bytes32(uint256(other.y) ^ 1);
        vm.expectRevert(HumaPagesV4.WrongWriter.selector);
        pages.submitEvents(genesis, 5, HumaPagesV4.Evidence(other, slice(ev.events, 5, 10), noAssertions()));
    }

    function test_RejectFinalBeforeEveryBatch() public {
        HumaPagesV4.Proofs memory p = proofs("long-case-1500", 14);
        vm.expectRevert(HumaPagesV4.UnknownSession.selector);
        pages.submitFinal(p.partInputs[0][0], p.finalProof, p.finalInputs);
    }

    // ---- passkey pages ----

    function publicKey(uint256 key) internal pure returns (bytes32 x, bytes32 y) {
        (uint256 px, uint256 py) = vm.publicKeyP256(key);
        return (bytes32(px), bytes32(py));
    }

    function test_Base64urlKnownVector() public view {
        assertEq(string(pages.base64url(sha256(""))), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    }

    uint256 constant WRITER = 0xB0B;
    uint256 constant PASSKEY = 0xCAFE;

    function client(bytes32 root, string memory origin, string memory extra) internal view returns (bytes memory) {
        string memory challenge = string(pages.base64url(sha256(abi.encodePacked("HUMA_PASSKEY_PRESENCE_V1\x00", root))));
        return abi.encodePacked('{"type":"webauthn.get","challenge":"', challenge, '","origin":"', origin, '"', extra, "}");
    }

    function approval(bytes32 root, bytes memory data, bytes memory clientData, HumaPagesV4.Writer memory w)
        internal
        view
        returns (HumaPagesV4.Assertion memory a)
    {
        a.authenticatorData = data;
        a.clientDataJSON = clientData;
        a.typeIndex = 1;
        a.challengeIndex = 23;
        a.originIndex = 23 + 13 + 43 + 2;
        (a.r, a.s) = vm.signP256(PASSKEY, sha256(abi.encodePacked(data, sha256(clientData))));
        bytes32 passkeyHash = sha256(abi.encodePacked(bytes1(0x04), w.passkeyX, w.passkeyY));
        (a.bindR, a.bindS) = vm.signP256(WRITER, sha256(abi.encodePacked("HUMA_PASSKEY_BIND_V1\x00", root, passkeyHash)));
    }

    function authData(bytes1 flags, uint32 counter) internal pure returns (bytes memory) {
        return abi.encodePacked(sha256("huma.social"), flags, counter);
    }

    function passkeyPage(uint32[] memory counters, bytes1 flags, string memory origin, string memory extra)
        internal
        view
        returns (HumaPagesV4.Writer memory w, HumaPagesV4.Event[] memory list, HumaPagesV4.Assertion[] memory assertions)
    {
        (w.x, w.y) = publicKey(WRITER);
        (w.passkeyX, w.passkeyY) = publicKey(PASSKEY);
        w.passkey = true;
        list = new HumaPagesV4.Event[](counters.length);
        assertions = new HumaPagesV4.Assertion[](counters.length);
        for (uint256 i; i < counters.length; ++i) {
            bytes32 root = bytes32(uint256(keccak256(abi.encode(i))) % 21888242871839275222246405745257275088548364400416034343698204186575808495617);
            (bytes32 r, bytes32 s) = vm.signP256(WRITER, sha256(abi.encodePacked("HUMA_LONG_ASSURANCE_PRESENCE_V1\x00", root)));
            list[i] = HumaPagesV4.Event(2, root, r, s);
            assertions[i] = approval(root, authData(flags, counters[i]), client(root, origin, extra), w);
        }
    }

    function counters(uint32 a, uint32 b) internal pure returns (uint32[] memory c) {
        c = new uint32[](2);
        (c[0], c[1]) = (a, b);
    }

    function test_PasskeyApprovalsAccepted() public view {
        (HumaPagesV4.Writer memory w, HumaPagesV4.Event[] memory list, HumaPagesV4.Assertion[] memory a) =
            passkeyPage(counters(1, 2), 0x05, "https://huma.social", ',"crossOrigin":false');
        (, uint256 counter) = pages.events(w, list, a);
        assertEq(counter, 2);
        (w, list, a) = passkeyPage(counters(0, 0), 0x05, "https://huma.social", ""); // authenticators that keep no counter
        pages.events(w, list, a);
    }

    function expectPasskeyRefused(HumaPagesV4.Writer memory w, HumaPagesV4.Event[] memory list, HumaPagesV4.Assertion[] memory a, uint256 index) internal {
        vm.expectRevert(abi.encodeWithSelector(HumaPagesV4.InvalidPasskey.selector, index));
        pages.events(w, list, a);
    }

    function test_PasskeyRefusals() public {
        (HumaPagesV4.Writer memory w, HumaPagesV4.Event[] memory list, HumaPagesV4.Assertion[] memory a) =
            passkeyPage(counters(1, 1), 0x05, "https://huma.social", ""); // counter not rising
        expectPasskeyRefused(w, list, a, 1);
        (w, list, a) = passkeyPage(counters(1, 2), 0x01, "https://huma.social", ""); // user not verified
        expectPasskeyRefused(w, list, a, 0);
        (w, list, a) = passkeyPage(counters(1, 2), 0x05, "https://evil.example", ""); // another origin
        expectPasskeyRefused(w, list, a, 0);
        (w, list, a) = passkeyPage(counters(1, 2), 0x05, "https://huma.social", ',"crossOrigin":true');
        expectPasskeyRefused(w, list, a, 0);
        (w, list, a) = passkeyPage(counters(1, 2), 0x05, "https://huma.social", ',"challenge":"x"'); // a second challenge
        expectPasskeyRefused(w, list, a, 0);
        (w, list, a) = passkeyPage(counters(1, 2), 0x05, "https://huma.social", "");
        a[1].bindS = bytes32(uint256(a[1].bindS) ^ 1); // the writer key didn't bind this passkey
        expectPasskeyRefused(w, list, a, 1);
        (w, list, a) = passkeyPage(counters(1, 2), 0x05, "https://huma.social", "");
        a[0].r = bytes32(uint256(a[0].r) ^ 1); // the passkey didn't sign it
        expectPasskeyRefused(w, list, a, 0);
        (w, list, a) = passkeyPage(counters(1, 2), 0x05, "https://huma.social", "");
        HumaPagesV4.Assertion[] memory one = new HumaPagesV4.Assertion[](1);
        one[0] = a[0];
        expectPasskeyRefused(w, list, one, 1); // a check-in without its approval
    }
}

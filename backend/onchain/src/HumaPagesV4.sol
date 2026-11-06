// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;


/// @notice The interface every verifier bb generates (`bb write_solidity_verifier -t evm --optimized`) implements.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Huma's Poseidon2 sponge (HumaPoseidon2).
interface IPoseidon2 {
    function hash(uint256[] calldata input) external pure returns (uint256);
}

/// @title HumaPagesV4
/// @notice Public record of Huma pages (assurance-long-v3) verified on-chain: every zero-knowledge proof AND everything
/// Huma's reader checks outside the proofs (backend/integrations/noir/long/reader.mjs, v3 and v3-passkey).
/// @dev The proofs are the browser's own, made in the EVM format, for Huma's EXISTING circuits (chunk<T> per part, final<T>
/// for the statement; T = 1024, 4096 or 10000 characters), and checked by the six verifiers bb generated (HumaPagesV3's).
/// On top of them, as the reader:
///  1. Parts: genesis first and only first, each part starts where the last ended, the final state is the last end.
///  2. Statement sanity: the journal's bounds (nonce halves under 2^128, counts that agree, times in range, ...).
///  3. Writer key: every checkpoint and check-in root is signed by the page's P-256 capture key (Base's P-256
///     precompile, RIP-7212), in order; the Poseidon2 event digest of (kind, root) equals the statement's; there are
///     checkpoint_count checkpoints and `approved` check-ins, ending with a checkpoint.
///  4. The session nonce commits to that key: nonce[1] = Poseidon2(NONCE, device_root(key), nonce[0]) mod 2^128.
///  5. Passkey pages: every approved check-in has a WebAuthn assertion of one passkey for https://huma.social over
///     SHA-256(PRESENCE domain || root), user present and verified, counters rising, bound to the page by the writer key.
/// Then it records keccak256(statement) => (block, parts, tier, events, passkey, submitter).
/// Not checked here, as nowhere but by whoever holds it: the text itself (its commitments are in the statement).
/// A page that fits goes in one transaction (`submit`); a longer one in batches (`submitParts`, `submitEvents`) closed
/// by `submitFinal`. Batches are kept per submitter and session (the genesis part's start root).
contract HumaPagesV4 {
    uint256 internal constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant FINAL_INPUTS = 44;
    /// @notice Per transaction, so one stays under a 2^24 gas cap (EIP-7825) at every tier.
    uint256 public constant MAX_PARTS_PER_TX = 12;
    uint256 public constant MAX_EVENTS_PER_TX = 64;
    address internal constant P256 = address(0x100);
    uint256 internal constant DEVICE = 0x48554d410801;
    uint256 internal constant NONCE = 0x48554d410802;
    uint256 internal constant EVENT = 0x48554d410703;
    bytes internal constant CHECKPOINT_DOMAIN = "HUMA_LONG_ASSURANCE_CHECKPOINT_V1\x00";
    bytes internal constant PRESENCE_DOMAIN = "HUMA_LONG_ASSURANCE_PRESENCE_V1\x00";
    bytes internal constant PASSKEY_DOMAIN = "HUMA_PASSKEY_PRESENCE_V1\x00";
    bytes internal constant BIND_DOMAIN = "HUMA_PASSKEY_BIND_V1\x00";
    /// @notice The relying party a passkey approval must be for, as the reader's default (huma.social).
    bytes32 public constant RP_ID_HASH = sha256("huma.social");
    bytes internal constant TYPE_GET = '"type":"webauthn.get"';
    bytes internal constant ORIGIN = '"origin":"https://huma.social"';
    bytes internal constant CHALLENGE = '"challenge":"';

    // Statement fields (reader.mjs FINAL, the public order of `struct Final` in prover.nr).
    uint256 internal constant NONCE0 = 0;
    uint256 internal constant NONCE1 = 1;
    uint256 internal constant STATE_ROOT = 2;
    uint256 internal constant RAW_SCALARS = 8;
    uint256 internal constant CANONICAL_SCALARS = 9;
    uint256 internal constant RAW_BYTES = 10;
    uint256 internal constant CANONICAL_BYTES = 11;
    uint256 internal constant TEXT_CAPACITY = 14;
    uint256 internal constant SAMPLES = 17;
    uint256 internal constant START_UNIX = 20;
    uint256 internal constant END_UNIX = 21;
    uint256 internal constant CHECKPOINT_COUNT = 24;
    uint256 internal constant PRESENCE_COUNT = 25;
    uint256 internal constant APPROVED = 26;
    uint256 internal constant ON_TIME = 27;
    uint256 internal constant MISSED = 28;
    uint256 internal constant ORIGIN_PRESENT = 31;
    uint256 internal constant ORIGIN_HID = 32;
    uint256 internal constant EVENT_DIGEST = 43;

    /// @notice The page's capture key (uncompressed P-256, x and y), and the passkey that approved its check-ins, if any.
    struct Writer {
        bytes32 x;
        bytes32 y;
        bool passkey;
        bytes32 passkeyX;
        bytes32 passkeyY;
    }
    /// @notice One signed event, in the session's order: kind 1 a checkpoint, 2 an approved check-in; (r, s) its signature.
    struct Event {
        uint8 kind;
        bytes32 root;
        bytes32 r;
        bytes32 s;
    }
    /// @notice A passkey approval of a check-in (WebAuthn), and the writer key's binding of it. The indices say where
    /// in clientDataJSON its type, challenge and origin members start.
    struct Assertion {
        bytes authenticatorData;
        bytes clientDataJSON;
        uint256 typeIndex;
        uint256 challengeIndex;
        uint256 originIndex;
        bytes32 r;
        bytes32 s;
        bytes32 bindR;
        bytes32 bindS;
    }
    struct Page {
        uint64 blockNumber;
        uint32 parts;
        uint32 tier;
        uint32 events;
        bool passkey;
        address submitter;
    }
    /// @notice A page's proofs in the EVM format: one per part, in order, and the final one with its statement.
    struct Proofs {
        bytes[] partProofs;
        bytes32[3][] partInputs;
        bytes finalProof;
        bytes32[] finalInputs;
    }
    /// @notice What the reader checks besides the proofs: the writer, its signed events in order, and (passkey pages) one
    /// approval per check-in among them, in order.
    struct Evidence {
        Writer writer;
        Event[] events;
        Assertion[] assertions;
    }
    /// @dev What the parts left for the final step: the tier, where they ended, and how many there were.
    struct Close {
        uint256 tier;
        bytes32 end;
        uint256 parts;
    }
    /// @dev A page sent in batches: its parts so far, and its events so far under one writer key.
    struct Session {
        bytes32 partsEnd;
        uint32 partsNext;
        uint32 tier;
        uint32 eventsNext;
        uint32 checkpoints;
        uint32 presences;
        uint32 counter;
        uint8 lastKind;
        bool passkey;
        uint256 digest;
        bytes32 x;
        bytes32 y;
        bytes32 passkeyX;
        bytes32 passkeyY;
    }
    /// @dev Where a run of events leaves the session's event state.
    struct Events {
        uint256 digest;
        uint32 next;
        uint32 checkpoints;
        uint32 presences;
        uint32 counter;
        uint8 lastKind;
    }

    IHonkVerifier public immutable chunk1024;
    IHonkVerifier public immutable final1024;
    IHonkVerifier public immutable chunk4096;
    IHonkVerifier public immutable final4096;
    IHonkVerifier public immutable chunk10000;
    IHonkVerifier public immutable final10000;
    IPoseidon2 public immutable poseidon2;

    /// @notice keccak256 of a page's 44 statement fields => when and by whom it was verified.
    mapping(bytes32 => Page) public pages;
    /// @notice keccak256(submitter, the first part's start root) => a page sent in batches, so far.
    mapping(bytes32 => Session) public sessions;

    event PageVerified(bytes32 indexed statement, address indexed submitter, uint256 tier, uint256 parts, uint256 events, bytes32 keyHash, bool passkey);
    event BatchVerified(bytes32 indexed session, address indexed submitter, uint256 partsNext, uint256 eventsNext);

    error AlreadyVerified();
    error NoParts();
    error TooMany(uint256 count);
    error UnsupportedTier(uint256 tier);
    error InvalidStatement(uint256 field);
    error BrokenLinkage(uint256 part);
    error InvalidPartProof(uint256 part);
    error InvalidFinalProof();
    error UnknownSession();
    error InvalidEvent(uint256 index);
    error InvalidSignature(uint256 index);
    error InvalidPasskey(uint256 index);
    error WrongWriter();
    error EventsDontMatch();
    error NonceNotBound();

    constructor(
        IHonkVerifier chunk1024_,
        IHonkVerifier final1024_,
        IHonkVerifier chunk4096_,
        IHonkVerifier final4096_,
        IHonkVerifier chunk10000_,
        IHonkVerifier final10000_,
        IPoseidon2 poseidon2_
    ) {
        (chunk1024, final1024) = (chunk1024_, final1024_);
        (chunk4096, final4096) = (chunk4096_, final4096_);
        (chunk10000, final10000) = (chunk10000_, final10000_);
        poseidon2 = poseidon2_;
    }

    // ---- One transaction ----

    /// @notice Verifies a whole page (up to MAX_PARTS_PER_TX parts and MAX_EVENTS_PER_TX events) and records it.
    /// @return statement keccak256 of the 44 statement fields, the page's key in `pages`.
    function submit(Proofs calldata p, Evidence calldata ev) external returns (bytes32 statement) {
        uint256 parts = p.partProofs.length;
        if (parts == 0) revert NoParts();
        if (parts > MAX_PARTS_PER_TX) revert TooMany(parts);
        if (ev.events.length > MAX_EVENTS_PER_TX) revert TooMany(ev.events.length);
        if (p.partInputs.length != parts) revert BrokenLinkage(parts);
        uint256 tier = _tier(p.finalInputs);
        Close memory c = Close(tier, _verifyParts(_chunk(tier), 0, bytes32(0), p.partProofs, p.partInputs), parts);
        Writer memory writer = ev.writer;
        Events memory e = _verifyEvents(writer, Events(0, 0, 0, 0, 0, 0), ev.events, ev.assertions);
        statement = _close(c, e, writer, p.finalProof, p.finalInputs);
    }

    // ---- Batches ----

    /// @notice Verifies a run of a long page's parts. The first run starts at part 0 (the genesis part); each next run
    /// starts where the last ended. `genesisRoot` (part 0's start root) names the session.
    function submitParts(bytes32 genesisRoot, uint256 tier, uint256 startIndex, bytes[] calldata partProofs, bytes32[3][] calldata partInputs)
        external
        returns (bytes32 session)
    {
        uint256 parts = partProofs.length;
        if (parts == 0) revert NoParts();
        if (parts > MAX_PARTS_PER_TX) revert TooMany(parts);
        if (partInputs.length != parts) revert BrokenLinkage(startIndex);
        IHonkVerifier verifier = _chunk(tier);
        session = keccak256(abi.encodePacked(msg.sender, genesisRoot));
        Session storage s = sessions[session];
        bytes32 previousEnd;
        if (startIndex == 0) {
            if (partInputs[0][0] != genesisRoot) revert BrokenLinkage(0);
            s.tier = uint32(tier);
        } else {
            if (s.partsNext == 0) revert UnknownSession();
            if (s.partsNext != startIndex || s.tier != tier) revert BrokenLinkage(startIndex);
            previousEnd = s.partsEnd;
        }
        s.partsEnd = _verifyParts(verifier, startIndex, previousEnd, partProofs, partInputs);
        s.partsNext = uint32(startIndex + parts);
        emit BatchVerified(session, msg.sender, s.partsNext, s.eventsNext);
    }

    /// @notice Verifies a run of a long page's signed events, in order. The first run (startEvent 0) fixes the writer
    /// key (and passkey) for the session; each next run must give the same and start where the last ended.
    function submitEvents(bytes32 genesisRoot, uint256 startEvent, Evidence calldata ev) external returns (bytes32 session) {
        if (ev.events.length == 0 || ev.events.length > MAX_EVENTS_PER_TX) revert TooMany(ev.events.length);
        session = keccak256(abi.encodePacked(msg.sender, genesisRoot));
        Session storage s = sessions[session];
        Writer memory writer = ev.writer;
        Events memory e;
        if (startEvent == 0) {
            _keep(s, writer);
        } else {
            if (s.eventsNext == 0) revert UnknownSession();
            if (s.eventsNext != startEvent) revert InvalidEvent(startEvent);
            if (s.x != writer.x || s.y != writer.y || s.passkey != writer.passkey || s.passkeyX != writer.passkeyX || s.passkeyY != writer.passkeyY) revert WrongWriter();
            e = _events(s);
        }
        e = _verifyEvents(writer, e, ev.events, ev.assertions);
        _save(s, e);
        emit BatchVerified(session, msg.sender, s.partsNext, s.eventsNext);
    }

    /// @notice Closes a page sent in batches: its statement and final proof against everything verified so far.
    function submitFinal(bytes32 genesisRoot, bytes calldata finalProof, bytes32[] calldata finalInputs) external returns (bytes32 statement) {
        bytes32 session = keccak256(abi.encodePacked(msg.sender, genesisRoot));
        Session storage s = sessions[session];
        if (s.partsNext == 0 || s.eventsNext == 0) revert UnknownSession();
        Close memory c = Close(_tier(finalInputs), s.partsEnd, s.partsNext);
        if (c.tier != s.tier) revert InvalidStatement(TEXT_CAPACITY);
        Events memory e = _events(s);
        Writer memory writer = Writer(s.x, s.y, s.passkey, s.passkeyX, s.passkeyY);
        delete sessions[session];
        statement = _close(c, e, writer, finalProof, finalInputs);
    }

    function _keep(Session storage s, Writer memory writer) internal {
        s.x = writer.x;
        s.y = writer.y;
        s.passkey = writer.passkey;
        s.passkeyX = writer.passkeyX;
        s.passkeyY = writer.passkeyY;
    }

    function _save(Session storage s, Events memory e) internal {
        s.digest = e.digest;
        s.eventsNext = e.next;
        s.checkpoints = e.checkpoints;
        s.presences = e.presences;
        s.counter = e.counter;
        s.lastKind = e.lastKind;
    }

    function _events(Session storage s) internal view returns (Events memory) {
        return Events(s.digest, s.eventsNext, s.checkpoints, s.presences, s.counter, s.lastKind);
    }

    /// @notice Whether a page with this statement hash has verified on-chain.
    function verified(bytes32 statement) external view returns (bool) {
        return pages[statement].blockNumber != 0;
    }

    // ---- Checks ----

    /// @dev The statement's checks (sanity, events, nonce binding), the final proof, and the record.
    function _close(Close memory c, Events memory e, Writer memory writer, bytes calldata finalProof, bytes32[] calldata finalInputs)
        internal
        returns (bytes32 statement)
    {
        statement = keccak256(abi.encodePacked(finalInputs));
        if (pages[statement].blockNumber != 0) revert AlreadyVerified();
        if (finalInputs[STATE_ROOT] != c.end) revert BrokenLinkage(c.parts);
        _checkStatement(finalInputs);
        // Every checkpoint and approved check-in, and nothing else: the digest chains them all, in order.
        if (
            e.checkpoints != uint256(finalInputs[CHECKPOINT_COUNT]) || e.presences != uint256(finalInputs[APPROVED]) || e.lastKind != 1
                || e.digest != uint256(finalInputs[EVENT_DIGEST])
        ) revert EventsDontMatch();
        // The nonce commits to the capture key, so these roots can't be signed again by another key and shown as its page.
        uint256[] memory h = new uint256[](3);
        (h[0], h[1], h[2]) = (NONCE, _deviceRoot(writer.x, writer.y), uint256(finalInputs[NONCE0]));
        if (poseidon2.hash(h) % (1 << 128) != uint256(finalInputs[NONCE1])) revert NonceNotBound();
        if (!_verifyCalldata(_final(c.tier), finalProof, finalInputs)) revert InvalidFinalProof();
        pages[statement] = Page(uint64(block.number), uint32(c.parts), uint32(c.tier), uint32(e.next), writer.passkey, msg.sender);
        emit PageVerified(statement, msg.sender, c.tier, c.parts, e.next, sha256(abi.encodePacked(bytes1(0x04), writer.x, writer.y)), writer.passkey);
    }

    /// @dev The statement's tier, after checking it has 44 fields and a tier this contract has verifiers for.
    function _tier(bytes32[] calldata finalInputs) internal pure returns (uint256 tier) {
        if (finalInputs.length != FINAL_INPUTS) revert InvalidStatement(FINAL_INPUTS);
        tier = uint256(finalInputs[TEXT_CAPACITY]);
        if (tier != 1024 && tier != 4096 && tier != 10000) revert UnsupportedTier(tier);
    }

    /// @dev The reader's sanity rules on the journal.
    function _checkStatement(bytes32[] calldata f) internal pure {
        uint256 v = 1 << 128;
        if (uint256(f[NONCE0]) >= v) revert InvalidStatement(NONCE0);
        if (uint256(f[NONCE1]) >= v) revert InvalidStatement(NONCE1);
        if (uint256(f[CANONICAL_SCALARS]) < 1) revert InvalidStatement(CANONICAL_SCALARS);
        if (uint256(f[RAW_SCALARS]) > uint256(f[TEXT_CAPACITY])) revert InvalidStatement(RAW_SCALARS);
        if (uint256(f[CANONICAL_SCALARS]) > uint256(f[RAW_SCALARS])) revert InvalidStatement(CANONICAL_SCALARS);
        if (uint256(f[CANONICAL_BYTES]) > uint256(f[RAW_BYTES])) revert InvalidStatement(CANONICAL_BYTES);
        if (uint256(f[APPROVED]) < 1) revert InvalidStatement(APPROVED);
        if (uint256(f[ON_TIME]) > uint256(f[PRESENCE_COUNT]) || uint256(f[MISSED]) != uint256(f[PRESENCE_COUNT]) - uint256(f[ON_TIME])) {
            revert InvalidStatement(MISSED);
        }
        if (uint256(f[CHECKPOINT_COUNT]) < 2) revert InvalidStatement(CHECKPOINT_COUNT);
        if (uint256(f[ORIGIN_HID]) > uint256(f[ORIGIN_PRESENT])) revert InvalidStatement(ORIGIN_HID);
        if (uint256(f[ORIGIN_PRESENT]) > uint256(f[SAMPLES])) revert InvalidStatement(ORIGIN_PRESENT);
        if (uint256(f[START_UNIX]) > 253402300799999) revert InvalidStatement(START_UNIX);
        if (uint256(f[END_UNIX]) > 253402300799999) revert InvalidStatement(END_UNIX);
    }

    /// @dev A run of events: each root under the field, signed by the writer key for its kind, chained into the digest;
    /// a check-in on a passkey page also has its approval (assertions, one per check-in in this run, in order).
    function _verifyEvents(Writer memory writer, Events memory e, Event[] calldata events, Assertion[] calldata assertions)
        internal
        view
        returns (Events memory)
    {
        uint256 used;
        uint256[] memory h = new uint256[](4);
        h[0] = EVENT;
        for (uint256 i; i < events.length; ++i) {
            Event calldata ev = events[i];
            _checkEvent(writer, ev, e.next + i);
            h[1] = e.digest;
            h[2] = ev.kind;
            h[3] = uint256(ev.root);
            e.digest = poseidon2.hash(h);
            if (ev.kind == 1) {
                ++e.checkpoints;
            } else {
                ++e.presences;
                if (writer.passkey) {
                    if (used == assertions.length) revert InvalidPasskey(e.next + i);
                    e.counter = _verifyPasskey(writer, ev.root, assertions[used++], e.counter, e.next + i);
                }
            }
            e.lastKind = ev.kind;
        }
        if (used != assertions.length) revert InvalidPasskey(e.next + events.length);
        e.next += uint32(events.length);
        return e;
    }

    /// @dev An event's kind and root, and the writer key's signature of it under its kind's domain.
    function _checkEvent(Writer memory writer, Event calldata ev, uint256 index) internal view {
        if ((ev.kind != 1 && ev.kind != 2) || uint256(ev.root) >= FIELD) revert InvalidEvent(index);
        bytes memory domain = ev.kind == 1 ? CHECKPOINT_DOMAIN : PRESENCE_DOMAIN;
        if (!_p256(sha256(abi.encodePacked(domain, ev.root)), ev.r, ev.s, writer.x, writer.y)) revert InvalidSignature(index);
    }

    /// @dev One passkey approval, as the reader: bound by the writer key, type webauthn.get, the check-in's challenge,
    /// origin https://huma.social and not cross-origin, the party's id hash, user present and verified, the counter
    /// rising (0 = none kept), and the passkey's signature. Returns the counter to compare the next one with.
    function _verifyPasskey(Writer memory writer, bytes32 root, Assertion calldata a, uint32 counter, uint256 index) internal view returns (uint32) {
        bytes32 passkeyHash = sha256(abi.encodePacked(bytes1(0x04), writer.passkeyX, writer.passkeyY));
        if (!_p256(sha256(abi.encodePacked(BIND_DOMAIN, root, passkeyHash)), a.bindR, a.bindS, writer.x, writer.y)) revert InvalidPasskey(index);
        counter = _checkAuthenticator(a.authenticatorData, counter, index);
        if (!_checkClient(a, root)) revert InvalidPasskey(index);
        if (!_p256(sha256(abi.encodePacked(a.authenticatorData, sha256(a.clientDataJSON))), a.r, a.s, writer.passkeyX, writer.passkeyY)) {
            revert InvalidPasskey(index);
        }
        return counter;
    }

    /// @dev Authenticator data: the party's id hash, user present and verified (flags 0x05), the counter rising.
    function _checkAuthenticator(bytes calldata data, uint32 counter, uint256 index) internal pure returns (uint32) {
        if (data.length < 37 || data.length > 1024) revert InvalidPasskey(index);
        if (bytes32(data[0:32]) != RP_ID_HASH || uint8(data[32]) & 0x05 != 0x05) revert InvalidPasskey(index);
        uint32 count = uint32(bytes4(data[33:37]));
        if (count == 0) return counter;
        if (count <= counter) revert InvalidPasskey(index);
        return count;
    }

    /// @dev Client data: type webauthn.get, this check-in's challenge, origin https://huma.social, each once, and not
    /// cross-origin.
    function _checkClient(Assertion calldata a, bytes32 root) internal pure returns (bool) {
        bytes calldata client = a.clientDataJSON;
        if (client.length < 2 || client.length > 4096) return false;
        bytes memory challenge = abi.encodePacked(CHALLENGE, _base64url(sha256(abi.encodePacked(PASSKEY_DOMAIN, root))), '"');
        return _at(client, a.typeIndex, TYPE_GET) && _at(client, a.challengeIndex, challenge) && _at(client, a.originIndex, ORIGIN)
            && _count(client, '"type"') == 1 && _count(client, '"challenge"') == 1 && _count(client, '"origin"') == 1
            && _count(client, '"crossOrigin":true') == 0;
    }

    /// @dev Commitment to an uncompressed P-256 key, as device_root in prover.nr: its halves of 16 bytes.
    function _deviceRoot(bytes32 x, bytes32 y) internal view returns (uint256) {
        uint256[] memory h = new uint256[](5);
        (h[0], h[1], h[2], h[3], h[4]) = (DEVICE, uint256(x) >> 128, uint256(x) & type(uint128).max, uint256(y) >> 128, uint256(y) & type(uint128).max);
        return poseidon2.hash(h);
    }

    /// @dev ECDSA P-256 over a SHA-256 digest, by the precompile (RIP-7212): it answers 1, or nothing for a bad signature.
    function _p256(bytes32 digest, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
        (bool ok, bytes memory out) = P256.staticcall(abi.encode(digest, r, s, x, y));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    function _at(bytes calldata data, uint256 at, bytes memory text) internal pure returns (bool) {
        if (at > data.length || data.length - at < text.length) return false;
        return keccak256(data[at:at + text.length]) == keccak256(text);
    }

    function _count(bytes calldata data, bytes memory text) internal pure returns (uint256 n) {
        if (data.length < text.length) return 0;
        bytes32 want = keccak256(text);
        for (uint256 i; i <= data.length - text.length; ++i) {
            if (data[i] == text[0] && keccak256(data[i:i + text.length]) == want) ++n;
        }
    }

    /// @dev base64url, unpadded, of 32 bytes: 43 characters.
    function _base64url(bytes32 value) internal pure returns (bytes memory out) {
        bytes memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        out = new bytes(43);
        uint256 v = uint256(value);
        // 32 bytes = 256 bits: ten groups of 24 bits (40 characters), then 16 bits (3 characters).
        for (uint256 g; g < 10; ++g) {
            uint256 chunk = (v >> (256 - 24 * (g + 1))) & 0xffffff;
            out[g * 4] = table[(chunk >> 18) & 63];
            out[g * 4 + 1] = table[(chunk >> 12) & 63];
            out[g * 4 + 2] = table[(chunk >> 6) & 63];
            out[g * 4 + 3] = table[chunk & 63];
        }
        uint256 last = (v & 0xffff) << 2;
        out[40] = table[(last >> 12) & 63];
        out[41] = table[(last >> 6) & 63];
        out[42] = table[last & 63];
    }

    // ---- Proofs ----

    function _chunk(uint256 tier) internal view returns (IHonkVerifier) {
        if (tier == 1024) return chunk1024;
        if (tier == 4096) return chunk4096;
        if (tier == 10000) return chunk10000;
        revert UnsupportedTier(tier);
    }

    function _final(uint256 tier) internal view returns (IHonkVerifier) {
        return tier == 1024 ? final1024 : tier == 4096 ? final4096 : final10000; // tier checked by _tier
    }

    /// @dev Linkage (part 0 is the genesis part; every other part is not, and starts where the one before it ended,
    /// `previousEnd` for the run's first) and each part's proof. Returns the run's last end.
    function _verifyParts(IHonkVerifier verifier, uint256 firstIndex, bytes32 previousEnd, bytes[] calldata partProofs, bytes32[3][] calldata partInputs)
        internal
        view
        returns (bytes32)
    {
        bytes32[] memory inputs = new bytes32[](3);
        for (uint256 i; i < partProofs.length; ++i) {
            uint256 index = firstIndex + i;
            bytes32 start = partInputs[i][0];
            uint256 genesis = uint256(partInputs[i][2]);
            if (index == 0 ? genesis != 1 : (genesis != 0 || start != (i == 0 ? previousEnd : partInputs[i - 1][1]))) revert BrokenLinkage(index);
            (inputs[0], inputs[1], inputs[2]) = (start, partInputs[i][1], partInputs[i][2]);
            if (!_verify(verifier, partProofs[i], inputs)) revert InvalidPartProof(index);
        }
        return partInputs[partProofs.length - 1][1];
    }

    // The generated verifiers revert (SumcheckFailed, ShpleminiFailed, ...) on a bad proof; either way it is invalid.
    function _verify(IHonkVerifier verifier, bytes calldata proof, bytes32[] memory inputs) internal view returns (bool) {
        try verifier.verify(proof, inputs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    function _verifyCalldata(IHonkVerifier verifier, bytes calldata proof, bytes32[] calldata inputs) internal view returns (bool) {
        try verifier.verify(proof, inputs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

# World ID (IDKit) in Huma

World ID is how writers **sign in** to Huma in the browser, and Huma's **human check for writing**: a writer finishes a
document only once World ID shows **one real, unique person** writes under their account. The account is the World
ID's own (one per person, the same on every device), and every page it shares shows the same anonymous World ID, so a writer can claim their pages ("these are mine") without
saying who they are. Readers see "Verified human · World ID <fingerprint>" beside the writer and on the writer's page
(huma.social/@handle), and can check the proof themselves. Huma's own proof says how the page was typed; World ID says a
verified human is its author. It never says who.

## The trust event

The first Finish. Until then a Huma account proves nothing about who uses it: anyone can make many accounts, but only
one World ID exists per person, and here one World ID links to one account.

## The credential, and why it is the minimum that works

**Proof of Human** (`proofOfHuman` preset, World ID 4.0, with the Orb fallback of 3.0). The badge claims *a unique
human*, so the credential must make a person one-of-a-kind:

| Credential | What it shows | Enough for "one unique person"? |
| --- | --- | --- |
| Selfie Check | a live face | No: shows liveness, not uniqueness |
| Passport / NFC | a real document | Not as strong: one person can hold several documents |
| **Proof of Human** | a unique, verified human | **Yes** |

The server accepts only `proof_of_human` (or the 3.0 `orb`) and refuses any other credential, so a weaker one can never
earn the badge.

## How it works

1. **Sign In** (or **Finish**, signed out) opens the World ID dialog. Privy sign-in is off for now, on the web and the
   Mac; its code is kept, commented out, in `../frontend/write/account.mjs` and `../frontend/share/src/main.jsx` (`Approval.jsx`).
2. The page asks the server for a signed request (`POST /api/worldid/context`). The signing key never leaves the server
   (`../frontend/worldid-verify.mjs`).
3. IDKit (`@worldcoin/idkit-core`, in `../frontend/write/worldid.mjs`) shows a QR and an *Open World App* link. The proof's
   **signal** is `huma-account:<this browser's publishing key>`, so it can sign in only this browser.
4. The page sends the proof to `POST /api/worldid/signin`, signed by its publishing key. The **server** checks the
   environment, action, credential and signal, then asks World's verify endpoint (`/api/v4/verify/{rp_id}`). The
   browser's answer is never trusted by itself.
5. The account is made from the World ID's nullifier (`worldIDAccount` in `../frontend/publications.mjs`), so the same person
   gets the same account on every browser, and the browser's publishing key is linked to it, as a Privy sign-in linked
   it. The account keeps the verified record (`../frontend/documents.mjs`).
6. **Every document is started and finished by a verified human.** At **Start Recording** the page asks for a World ID
   made for that writing session: signal `huma-session:<session nonce>:<publishing key>`, sent signed to
   `POST /api/worldid/session`. The server checks the session is live and unused, checks the proof with World, keeps it
   with the session (`../frontend/sessions.mjs`), and signs a writer in who isn't yet, so a new writer scans once. **Writing
   starts as soon as World App answers**: the page sends the scan while the writer is already typing (World's check and
   Arkiv take a few seconds), tries again if the connection drops, and stops the recording if the server refuses it;
   Finish waits for that answer. The prover starts warming up when Start is pressed, so its start-up (about 8 s) runs
   during the scan, not while the writer types. At **Finish**,
   once the page is proved, it asks again for a World ID made for the finished page: signal
   `huma-page:<text hash>:<proof hash>`, sent with the share.
7. When a page written in a browser is shared, the server requires both, from the **same person**, and that person is
   the account's (`confirmWorldID` in `../frontend/publications.mjs`); it keeps both with the page. Readers get a short
   fingerprint of the nullifier and when it was started (`GET /api/publications/<id>/receipt`, and
   `GET /api/writers/<handle>`) and, with the page's link, both proofs (`GET /api/publications/<id>/worldid`) plus the
   `curl` command to re-check them with World. Pages from the Mac follow the same rule (see "The Mac app" below).

## Paths shown

- **Success:** World ID at Start, then again at Finish; the page is proved and shared with the badge, which says the
  same human started and finished it.
- **Cancelled, declined or timed out at Start:** *Cancel*, a rejection in World App, or five minutes without a scan.
  **Nothing starts recording**; Start Recording can be pressed again. Nothing is stored.
- **Refused by the server after the Start scan** (World rejects it, or the session has ended): the recording stops,
  and the page is kept, view only; it can't be shared. A dropped connection is retried first.
- **Cancelled, declined or timed out at Finish:** the page is proved and kept, but **not shared**: its link waits until
  the writer presses Share and scans again. With `HUMA_WORLD_REQUIRED=false` World ID is only a badge and neither scan
  is asked.
- **A different person at Finish:** a World ID that isn't the one the page was started with is refused (403).
- **Taken:** a World ID already linked to another account can't be linked again.
- **The Mac app** signs in with World ID too: **Sign In** in Huma opens `/share/signin` (`../frontend/share/src/WorldSignIn.jsx`)
  with a secret code and the Mac's publishing key. After checking the code matches, the person scans with World App;
  the proof is made for the Mac's key (`huma-account:<key>`) and posted with the code to `/api/publications/signin`,
  which links the key to the World ID's account. Huma reads it back with the code, as it did with Privy.
- **The Mac app starts and finishes every page with World ID too,** in a small window of its own (`WorldIDWindow.swift`,
  a web view of the same page). **Start Recording** gets a session from the host (`/api/sessions`) and opens the page
  with it (`#<code>.<key>.<nonce>`): the World ID is made for that session and the Mac's key, and the recording uses
  the host's nonce as its own (`ExperimentalCompactCapture`, `sessionNonce`), so the proof names that session. As soon
  as World App answers, the page hands the proof to Huma (`huma://started?proof=…`, which closes the window), Touch ID
  and the recording start, and Huma sends the proof to the host meanwhile (`/api/publications/signin` with the code and
  the nonce, kept with the session); a refusal stops the recording, view only. **Get Link** waits for that, then opens
  the page for the waiting page (`#finish.<id>.<ticket>`): the World ID is made for its text and proof and comes back
  the same way (`huma://finished?proof=…`), and goes with the upload (`publish-device`). The server then applies the
  same rule as for a browser page.
- **Refused at share:** a browser page without its Start scan (started before this, or elsewhere), or without its
  Finish scan, isn't shared (403). A badge is never half-given.

## Setup

Create an app and an action in the World Developer Portal (action `verify-publisher`, unlimited verifications per
person, since one writer shares many pages), then set `HUMA_WORLD_APP_ID`, `HUMA_WORLD_RP_ID` and
`WORLD_RP_SIGNING_KEY` (see `.env.example`). With any of the three missing, World ID is off and nothing changes (and nothing is required). `HUMA_WORLD_REQUIRED=false`
turns the requirement into an optional badge. Use
`HUMA_WORLD_ENVIRONMENT=staging` with the World ID simulator (https://simulator.worldcoin.org/).

## Tests

`cd frontend && node --test test/worldid.test.mjs` — the verifier, the signing, the badge data, the routes, linking an
account (one World ID per account) and the share path end to end against the real registry (World's endpoint stubbed, the page's own proof check replaced by a made-up
page so it runs without the Rust and Noir tools).

## Integration debrief

- IDKit's core package fits a vanilla page well; the signing helper (`@worldcoin/idkit-core/signing`) runs in plain Node.
- Binding the signal to the page hash was the useful design choice: a World ID proof then means something about *this*
  document, not just about a login.
- The part to watch is the action's verification limit in the portal. A fixed action with a limit of one would stop a
  writer sharing a second page.
- The IDKit code adds about 350 KB to the write page script.
- The same human across pages is shown by the account's World ID fingerprint on each page and on the writer's page. Not yet done: an onchain check.

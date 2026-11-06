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
   Mac; its code is kept, commented out, in `frontend/write/account.mjs` and `frontend/share/src/main.jsx` (`Approval.jsx`).
2. The page asks the server for a signed request (`POST /api/worldid/context`). The signing key never leaves the server
   (`frontend/worldid-verify.mjs`).
3. IDKit (`@worldcoin/idkit-core`, in `frontend/write/worldid.mjs`) shows a QR and an *Open World App* link. The proof's
   **signal** is `huma-account:<this browser's publishing key>`, so it can sign in only this browser.
4. The page sends the proof to `POST /api/worldid/signin`, signed by its publishing key. The **server** checks the
   environment, action, credential and signal, then asks World's verify endpoint (`/api/v4/verify/{rp_id}`). The
   browser's answer is never trusted by itself.
5. The account is made from the World ID's nullifier (`worldIDAccount` in `frontend/publications.mjs`), so the same person
   gets the same account on every browser, and the browser's publishing key is linked to it, as a Privy sign-in linked
   it. The account keeps the verified record (`frontend/documents.mjs`). Signing in is once per browser; Finish then goes
   straight through.
6. When a page is shared, the server adds the account's record to it (`frontend/publications.mjs`). Readers get a short
   fingerprint of the nullifier (`GET /api/publications/<id>/receipt`, and `GET /api/writers/<handle>`) and, with the
   page's link, the full proof (`GET /api/publications/<id>/worldid`) plus the `curl` command to re-check it with World.

A proof made at a share for that page alone (signal `huma-page:<master hash>:<proof hash>`) is still accepted.

## Paths shown

- **Success:** the account is linked; the document is finished, proved and shared with the badge.
- **Cancelled, declined or timed out:** *Cancel*, a rejection in World App, or five minutes without a scan. **The
  document isn't finished**: the writer keeps writing and is told World ID is required. Nothing is stored. With
  `HUMA_WORLD_REQUIRED=false` it is only a badge: *Finish Without It* finishes the page without one.
- **Taken:** a World ID already linked to another account can't be linked again.
- **The Mac app** signs in with World ID too: **Sign In** in Huma opens `/share/signin` (`frontend/share/src/WorldSignIn.jsx`)
  with a secret code and the Mac's publishing key. After checking the code matches, the person scans with World App;
  the proof is made for the Mac's key (`huma-account:<key>`) and posted with the code to `/api/publications/signin`,
  which links the key to the World ID's account. Huma reads it back with the code, as it did with Privy, so the Mac app
  needed no change. Its pages carry the account's World ID like any other.
- **Refused at share:** a browser page from an account with no World ID, and no proof of its own, isn't shared (403).
  A badge is never half-given.

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

# Growth Backlog

Every idea so far that isn't a blog post, roughly in order of impact. **Owner:** "you" means Swayam, "Claude" means it's code I can build.

## Do first

| Idea | Why | Owner |
|---|---|---|
| Teacher line on every proof page: "Want this from your students or writers? Ask for a Huma link" → `/ask` | Every link a writer shares is opened by a teacher or client. One student brings in one teacher, and that teacher brings 30 students. | Claude |
| `/flagged` "Get Help" page for the promise in flagged-promise.md | A reason to choose Huma before being flagged, and a press hook | Claude (page); you (who answers the emails) |
| `/blog` section with `BlogPosting` and `FAQPage` markup, shared CTA boxes, `data-track="blog_cta"` | So your posts can go live and be counted | Claude |
| Original data study: 50–100 volunteers write in Huma (proven human), run the essays through GPTZero, ZeroGPT and others, publish the false-positive rate | New data gets cited by journalists, which brings links; nobody else has proven-human text to test with. Use only writing people agreed to share. | You (volunteers); Claude (page, tables) |
| Google Search Console and Bing Webmaster Tools; submit `sitemap.xml` | See which searches find us | You |

## Pages for searches

| Idea | Notes |
|---|---|
| `/vs/grammarly-authorship` | Comparison table (blog/c-huma-vs-grammarly-authorship.md), embedded YouTube video with `VideoObject` markup |
| `/vs/turnitin-clarity`, `/vs/draftback`, `/vs/gptzero` | Check each competitor's current features first |
| One page per detector: "GPTZero false positive", "ZeroGPT", "Copyleaks", "Originality", "QuillBot AI detector", "Turnitin" | Use the original-data study numbers |
| Turnitin searches: "Turnitin flagged my essay", "how accurate is Turnitin AI detection", "Turnitin Clarity alternative" | See turnitin.md |
| University policy pages: "[University]'s AI detection policy and what to do if you're flagged" | Only real ones citing the school's own page; 20 good ones, not 500 thin ones |
| "Best tools to prove you wrote it" roundup | Huma, Grammarly Authorship, Turnitin Clarity, Draftback, GPTZero history; fair to all |

## Free tools that get linked

- An appeal letter builder: a form, no AI, which produces an editable letter.
- A teacher AI-policy template: "A detector score alone isn't evidence; students may attach a Huma link."
- A "How to read a detector score" explainer.
- A **"Written in Huma ✓" badge** for blogs, Substack, LinkedIn and portfolios. It links to the proof and to huma.social, so every badge is a backlink.

## Teachers and schools (how Turnitin actually gets replaced)

- **Class inbox:** a teacher shares one link and gets every student's Huma link back. This is an upgrade to `/ask`.
- **Three teacher pilots,** written up as short case studies with quotes.
- **Email writing centres and teaching centres** (Centers for Teaching and Learning) with the teacher post and the policy template.
- **Later: Canvas and Google Classroom integration (LTI).** It's how schools buy tools like Turnitin.

## YouTube and social

**The comparison video:**
- Title: "Grammarly Authorship vs Huma: Which Proves You Wrote It?"
- Put the huma.social link in the first line of the description.
- Add chapters.
- Upload captions; don't rely on auto-generated ones.
- Pin a comment with the link.
- Embed it on the `/vs/` page.

**Other social:**
- **Short videos (TikTok, Reels, Shorts):** "My teacher said I used AI, so I showed her this." Real students only, and paid ones labelled as ads.
- **Campus ambassadors:** students paid per active writer, with disclosure.
- **Listening:** set alerts for "flagged for AI" and "turnitin said I used AI" on Reddit, X and TikTok. Reply helpfully from a clearly named Huma account.
- **Launches:** Show HN ("Huma: prove you wrote it, with proofs made on your device"), then Product Hunt with the video.
- **Timing:** publish before finals (late November, late April) and before college application deadlines (November–January).

## Press

- **Who to pitch:**
  - Plagiarism Today (Jonathan Bailey)
  - Tech & Learning
  - EdWeek
  - Inside Higher Ed
  - The Chronicle of Higher Education
- **Hooks:**
  - The original data.
  - The "we've got your back" promise.
  - "Every post on our blog proves it was written by a person."

## Before selling Plus (product, not marketing)

- Build end-to-end encryption; Plus promises it.
- A lawyer reviews the Terms and the flagged-promise wording.
- Decide about users under 18.
- Export tooling for the dataset copies.

## What to measure every week

- Search Console impressions and clicks for "grammarly authorship", "ai detector false positive", "turnitin", and "prove you didn't use ai".
- Sign-ups from blog and `/vs/` pages (`data-track` steps in PostHog).
- Proof-page visits that go on to `/ask` (the teacher loop).
- YouTube views and click-through to huma.social.
- Session replays (fixed in `bd7e866`): watch 5 a week, especially Finish and Pricing.

## Never do

- Fake reviews, fake "I got accused" stories, or sockpuppet Reddit or forum accounts.
- Unlabelled paid posts.
- Bought links or mass-made thin pages.
- Marketing as "Turnitin-proof" or "beat AI detectors". It attracts cheaters and loses teachers' trust.
- Competitors' logos, or anything that suggests a partnership.

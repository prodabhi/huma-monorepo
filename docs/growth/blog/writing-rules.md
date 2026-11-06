# Blog Writing Rules

Read this before writing any post.

## Write every post in Huma

**Write every post in Huma and put the proof link at the bottom.**
- Put this line at the end of each post: "This post was written in Huma. See how it was typed: [link]".
- A blog about proving human writing that proves its own writing is the best evidence you can offer, and nobody else can copy it.
- It also gives every reader a working example without a sign-up.

**Rules for every post:**
1. **Sources:** every number links to its source, ideally the primary one (paper, official blog).
2. **No 100% claims:** never say Huma is "100% accurate" or "impossible to fake". Say what Huma records and who can check it.
3. **Grammarly:** describe what it does, don't attack it. Let the comparison speak.
4. **Open with the answer:** the first two sentences answer the search question directly. Google often quotes them.
5. **Length:** 800–1,500 words. Each post links to 2–3 other posts and has one "Start Writing" button.

## On-page checklist

- **Title:** under 60 characters, main search near the front, e.g. "AI Detector False Positives: How Often They're Wrong".
- **Meta description:** 140–160 characters, answer plus a reason to click.
- **URL:** `/blog/ai-detector-false-positives` (short, no dates).
- **Headings:** one H1, then H2s phrased as questions people search.
- **Answer box:** the first paragraph answers in 40–60 words.
- **Table:** at least one per post (Google likes extracting them).
- **Markup:**
  - `BlogPosting` with author and date.
  - `FAQPage` for the FAQ.
  - `VideoObject` on Post C.
- **Author:** a real name with a short bio. Google rewards real authors on "your money or your life" topics like education.
- **Proof:** "Written in Huma" with the link at the bottom.
- **Links:**
  - Each post links to two other posts and one guide page.
  - The home page footer links to the blog.
  - Add each post to `sitemap.xml`.
- **Updated date:** refresh the numbers yearly and show "Updated …".

## Call to action in every post

Every post has the same CTA in two places. Keep the wording identical so it becomes recognisable.

**1. Short box after the first section** (most readers never reach the end):
> **Write it in Huma. It's free.**
> Get a link and a PDF anyone can check, showing you typed it yourself.
> [Start Writing →](/write)

**2. Full box at the end, just above "Written in Huma":**
> **Never get wrongly flagged again.**
> Huma records how you write, so you can show it instead of arguing with a score. Free on the web and on Mac.
> [Start Writing →](/write) · [See an Example →](/example)

**Rules:**
- **The button always says "Start Writing"** and goes to `/write`. No sign-up is needed to start: say "free" and "no account needed to start".
- **Matching help line:** posts about being flagged (A, D, E) add one line under the end box: "Already flagged? If you wrote it in Huma, we'll help you show it. [Get Help →](/flagged)" (once that page exists; see ../flagged-promise.md).
- **Teachers:** posts for teachers (G) swap the end box for: "Ask your students for a Huma link. It's free for them. [Ask for a Link →](/ask)".
- **Tracking:** add `data-track="blog_cta"` to both buttons so PostHog counts which posts bring writers.
- **Look:** use the same solid dark button style as the home page's Start Writing button.

## Claims to avoid

| Don't say | Say instead |
|---|---|
| "AI detectors don't work" | "AI detectors wrongly flag human writing often enough that some universities turned them off" |
| "Huma can't be faked" | "Huma shows how the text was typed, and anyone can check the link" |
| "Grammarly is lying / unreliable" | "In one test, text rewritten by Grammarly's Humanize feature was labelled as typed by a human" (with link) |
| "Turnitin is wrong 4% of the time" | "Turnitin says about 4% of highlighted sentences are actually human-written" |
| "61% of non-native essays are flagged" | "Seven detectors flagged 61% of TOEFL essays by non-native writers on average, in a 2023 Stanford study" |
| "Black students are falsely accused twice as often" | "Black teens were about twice as likely to say their work was wrongly flagged (Common Sense Media survey)" |

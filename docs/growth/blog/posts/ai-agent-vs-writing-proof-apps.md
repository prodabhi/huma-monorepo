---
title: "We Tried to Fool 4 Writing-Proof Tools. Only Huma Caught It"
description: "An AI agent and a typing script against Huma, Grammarly Authorship, ValidDraft and LyteWriter. Only Huma caught it every time. Screenshots of every result."
url: https://huma.social/blog/ai-agent-vs-writing-proof-apps
author: Swayam
date: 2026-11-05
---

<!-- Copy-ready draft. Rewrite it in your own words in Huma, then add: "This post was written in Huma. See how it was typed: [link]" -->

# We tried to fool four writing-proof tools. Only Huma caught it.

*An AI agent, a simple typing script, and four tools that say they can prove a person wrote something.*

There’s a new kind of software that says it can prove a person wrote something. Not by reading the text and guessing, the way AI detectors do, but by watching the text get written. I think this is the right idea. Guessing from finished words was always going to fail, for reasons I’ll get to [in another post](https://huma.social/blog/how-accurate-are-ai-detectors). Watching the writing happen gives you evidence instead of an opinion.

But a right idea can still be built badly. So on November 5, 2026, we tried to fool four of these tools, including our own. Huma was the only one that caught every attempt.

**Short answer:** an AI agent put AI-written text into Huma, ValidDraft and LyteWriter. Huma stopped it the moment the text appeared; ValidDraft issued a certificate ID marked “Pending review”; LyteWriter’s check failed with an error. Then a simple script typed a paragraph copied from *Pride and Prejudice*, one character at a time. Grammarly Authorship labelled 35% to 54% of it as typed by a person. Huma stopped the same script within the first sentence.

> **Write it in Huma. It’s free.**
> Get a link and a PDF anyone can check, showing you typed it yourself. No account needed to start.
> [Start Writing →](https://huma.social/write)

## The first test: let an AI agent do it

The laziest way to cheat one of these tools is to have software put the text in for you. So we gave an AI agent, Claude running in Chrome, a short AI-written bio and asked it to enter the text into each app and run the app’s check.

When we asked it to go further and type word by word with human-like pauses, it refused. It said it wouldn’t help fake a human-writing result. That’s the right call for an AI model to make, and it meant this first test only covered the crude version: text that shows up in the editor all at once.

| App | What happened | Caught it? |
|---|---|---|
| Huma | Stopped recording as soon as the text appeared; no proof possible | **Yes** |
| ValidDraft | Accepted it and issued a certificate ID, marked “Pending review” | No |
| LyteWriter | Saved it as “Unverified”; the check failed with an error | No |

Huma stopped recording and said: “Huma detected typing a person didn’t do: keys released instantly. This document can’t be proved.”

![Huma showing Automated typing detected. This document can’t be proved.](https://huma.social/blog/img/test-huma-automated-typing.webp)
*Huma stopped the recording the moment the AI agent’s text appeared.*

ValidDraft accepted the submission and created a certificate with its own ID. Its status was “Pending review”, with a note that a person would look within 24 hours. To be fair, that person may well reject it. But the automatic check didn’t notice a 515-character paragraph arriving in a single insert, and a certificate existed straight away.

![ValidDraft writing process certificate marked Pending review.](https://huma.social/blog/img/test-validdraft-pending-review.webp)
*ValidDraft issued a certificate ID and sent it for review.*

LyteWriter saved the document as “Unverified”, and when we pressed “Verify I Wrote This” it showed a server error. So we got no answer either way. It may work on another day. On the day we tested, it didn’t.

![LyteWriter document marked Unverified with a Verification error message.](https://huma.social/blog/img/test-lytewriter-verification-error.webp)
*LyteWriter couldn’t run its check.*

## The second test: a simple typing script

A determined cheater wouldn’t use an AI agent. They’d use a script that types for them. So we wrote one: it types one character at a time, pauses between words, makes the occasional typo and fixes it with backspace. Nothing clever. The kind of thing you could write in an afternoon.

And we gave it something it shouldn’t be able to pass off as human: the opening paragraph of *Pride and Prejudice*, copied word for word.[1] If a tool labels that “typed by a person”, it isn’t just missing AI. It’s certifying copying.

![The opening paragraph of Pride and Prejudice typed into a Google Doc by a script.](https://huma.social/blog/img/script-grammarly-doc-typed.webp)
*The script typed a famous novel’s opening, word for word, one character at a time.*

We ran it in a Google Doc with Grammarly Authorship, which records how a document is written,[2] then generated Grammarly’s report. We did that twice. Then we ran the same script in Huma.

| Tool | Result |
|---|---|
| Huma | **Stopped within the first sentence:** “Automated typing detected… This document can’t be proved.” |
| Grammarly Authorship, run 1 | 54% “Typed and unmodified”, 46% “Copied or generated” |
| Grammarly Authorship, run 2 | 35% “Typed and unmodified”, 65% “Copied or generated” |
![Grammarly Authorship report: 54% Started as human writing, typed and unmodified; 46% copied or generated.](https://huma.social/blog/img/script-grammarly-report-54.webp)
*Grammarly Authorship, run 1: 54% labelled “Typed and unmodified”.*
![Grammarly Authorship report: 35% typed and unmodified; 65% copied or generated.](https://huma.social/blog/img/script-grammarly-report-35.webp)
*Grammarly Authorship, run 2: 35% labelled “Typed and unmodified”.*
![Huma showing Automated typing detected for the same script.](https://huma.social/blog/img/script-huma-automated-typing.webp)
*Huma, same script: stopped within the first sentence.*

Grammarly caught part of it both times, and it’s worth saying so. But a third to a half of a 200-year-old novel, typed by a script, came out labelled as typed by a person. That isn’t the first time someone has found a gap like this: Plagiarism Today found that text rewritten by Grammarly’s own Humanize feature was labelled “Typed by a Human”.[3]

## Why the difference?

The difference is in what each tool treats as the evidence. Grammarly labels stretches of text, so a script that types slowly enough gets some of its stretches called human. Huma treats the whole writing session as one piece of evidence. It records every key press with its timing and checks that the timing could have come from human hands. A script sends key presses, but not the way fingers do: it releases keys instantly, for example. When Huma sees that, it stops, and that document can never become a proof.

When Huma does make a proof, it’s made on your own device, and anyone can check it at [huma.social/verify](https://huma.social/verify) without trusting us. That matters more than it sounds. A label that says “typed by a human” is only as good as the company printing it.

Our verdict
Huma is the only tool here that caught every attempt: the AI agent, and the typing script. The others either let the text through, labelled part of it as human, or couldn’t run their check at all. If you need a proof that holds up, use Huma.

## What this doesn’t show

- **We make Huma.** Every screenshot here comes from a continuous screen recording of the tests, and you can run the same tests yourself.
- **A few runs, on one day.** Grammarly’s results varied between runs (54% and 35%), so we show both. Apps change. If you make one of these tools and something has changed, email [team@huma.social](mailto:team@huma.social) and we’ll test again and update this post.
- **No tool is unbeatable.** Someone could build a much better typing robot than our afternoon script. Huma shows the timing of every key press in its replay, so unnatural typing is visible to a reader, but no one should claim their tool can’t be fooled. We don’t.

> **Never get wrongly flagged again.**
> Huma records how you write, so you can show it instead of arguing with a score. Free on the web and on Mac.
> [Start Writing →](https://huma.social/write) · [See an Example →](https://huma.social/example)

## Questions

### Can an AI agent fake a writing proof?

It depends on the tool. In our test on November 5, 2026, an AI agent put AI-written text into three writing-proof apps. Huma stopped it immediately, ValidDraft issued a certificate ID pending review, and LyteWriter’s check failed with an error.

### Can Grammarly Authorship be fooled by a typing script?

In our test, a simple script typed a paragraph copied from Pride and Prejudice one character at a time. Grammarly Authorship labelled 54% of it “Typed and unmodified” in one run and 35% in another. Huma stopped the same script within the first sentence.

### Which tool proves you wrote something?

Tools that record writing as it happens, such as Huma, Grammarly Authorship and Turnitin Clarity, give evidence instead of a guess. Of the four tools we tested, Huma was the only one that caught every attempt.

### Is Huma free?

Yes, on the web and on Mac.

## Notes

1. Jane Austen, Pride and Prejudice (1813), public domain, Project Gutenberg. https://www.gutenberg.org/ebooks/1342
2. Grammarly, “Grammarly Authorship”. https://www.grammarly.com/authorship
3. Plagiarism Today, “How Grammarly Launders AI-Generated Content”, November 2025. https://www.plagiarismtoday.com/2025/11/06/how-grammarly-launders-ai-generated-content/

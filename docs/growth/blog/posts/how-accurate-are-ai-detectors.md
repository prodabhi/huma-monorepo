---
title: "How Accurate Are AI Detectors? What the Studies Say"
description: "AI detectors wrongly flag human writing often enough that universities have turned them off. What the studies found, who gets flagged, and what to do instead."
url: https://huma.social/blog/how-accurate-are-ai-detectors
author: Swayam
date: 2026-11-05
---

<!-- Copy-ready draft. Rewrite it in your own words in Huma, then add: "This post was written in Huma. See how it was typed: [link]" -->

# How accurate are AI detectors?

*Not accurate enough to accuse anyone with. And the deeper problem is that they can’t be fixed.*

The short answer is: not accurate enough to accuse anyone with. But the more interesting question is why, because once you see why, you see that better detectors won’t fix it.

**Short answer:** AI detectors wrongly flag human writing often enough to matter. OpenAI shut down its own detector for being inaccurate, and a Stanford study found popular detectors flagged most essays by non-native English writers as AI. Some newer detectors test much better, but every detector gives you a guess, not evidence.

> **Write it in Huma. It’s free.**
> Get a link and a PDF anyone can check, showing you typed it yourself. No account needed to start.
> [Start Writing →](https://huma.social/write)

## What the studies found

In 2023 a group at Stanford ran 91 essays from the TOEFL, the English test for non-native speakers, through seven popular detectors.[1] Every essay was written by a person. On average, the detectors called 61% of them AI. At least one detector flagged 89 of the 91. The same detectors were near-perfect on essays by US-born eighth graders.[2]

*[Diagram: Share of 91 human-written TOEFL essays that detectors called AI]* 
*Share of 91 TOEFL essays, all written by people, that detectors called AI-generated. Source: Liang et al., 2023.*

That same year OpenAI took its own detector offline. It caught only 26% of AI-written text and wrongly flagged 9% of human text.[3] The company that makes ChatGPT couldn’t reliably tell when something was written by ChatGPT. A separate team tested 14 tools, Turnitin among them, and concluded they were “neither accurate nor reliable”.[4]

| Study | What was tested | What they found |
|---|---|---|
| Liang et al., Stanford, 2023 | 7 detectors, 91 TOEFL essays by people | 61% flagged as AI on average; 97.8% by at least one |
| OpenAI, 2023 | Its own AI text classifier | Caught 26% of AI text, flagged 9% of human text; shut down |
| Weber-Wulff et al., 2023 | 14 tools, including Turnitin | “Neither accurate nor reliable” |
| Jabarian and Imas, UChicago, 2025 | Several commercial detectors | Pangram near-zero errors on longer passages; others mixed |

## Why detectors can’t be fixed

Here’s the problem in one sentence: a detector has to decide whether a person could have written a piece of text, and a person can write almost anything.

AI models are trained to write like people, and every improvement makes their output harder to tell apart from ours. Meanwhile any AI text a detector does catch can be run through a paraphrasing tool, and researchers have shown that this defeats many detectors.[5] So detectors are squeezed from both sides. Catching more AI means flagging more humans. Flagging fewer humans means catching less AI.

Some detectors are much better than others, and it’s worth being fair about that. A 2025 University of Chicago working paper found that Pangram made almost no errors on medium and long passages.[6] That’s real progress. But notice what even a perfect detector gives you: its opinion of the words. It can’t give an honest student anything to show back.

*[Diagram: An AI detector guesses from finished text; Huma records the writing and makes a proof anyone can check]* 
*A detector gives you an opinion about the words. A recording gives you evidence about how they were made.*

## Who pays for the errors

- **Non-native English writers.** Across the seven detectors in the Stanford study, 61% of their essays were wrongly flagged, against about 5% of essays by native writers.[7]
- **Black students.** In a Common Sense Media survey, about 20% of Black teens said a teacher had wrongly flagged their work as AI, compared with 7% of white teens.[8]
- **Anyone who writes plainly.** Clear, simple writing is exactly what detectors find predictable.

And small rates become big numbers at scale. Turnitin checked 38 million submissions in its first six weeks.[9] Vanderbilt worked out that even a 1% error rate could mean about 750 wrongly flagged papers a year on its campus, and turned the detector off.[10]

## What works instead

Stop asking “does this text look human?” and ask “how was this text made?” The first question can only be answered with a guess. The second can be answered with a record, and that’s what Huma gives you. Huma records every key press as you write and gives you a link and a PDF Report showing what was typed and what was pasted, which anyone can check in a browser. See [how Huma compares with Grammarly Authorship](https://huma.social/blog/huma-vs-grammarly-authorship), or what to do if [Turnitin has already flagged you](https://huma.social/blog/turnitin-flagged-my-essay).

> **Never get wrongly flagged again.**
> Huma records how you write, so you can show it instead of arguing with a score. Free on the web and on Mac.
> [Start Writing →](https://huma.social/write) · [See an Example →](https://huma.social/example)

## Questions

### Can AI detectors be wrong?

Yes. OpenAI shut down its own detector after it flagged 9% of human text, and a Stanford study found seven popular detectors flagged 61% of essays by non-native English writers as AI on average.

### Why did OpenAI shut down its AI detector?

OpenAI took its AI text classifier offline in July 2023 because of its low accuracy. It caught only 26% of AI-written text and wrongly flagged 9% of human text.

### Are AI detectors biased against non-native English speakers?

A 2023 Stanford study found seven popular detectors flagged 61% of TOEFL essays by non-native English writers as AI on average, while being near-perfect on essays by US-born eighth graders.

## Notes

1. Liang, Yuksekgonul, Mao, Wu and Zou, “GPT detectors are biased against non-native English writers”, Patterns, 2023. https://arxiv.org/abs/2304.02819
2. Stanford HAI, “AI-Detectors Biased Against Non-Native English Writers”. https://hai.stanford.edu/news/ai-detectors-biased-against-non-native-english-writers
3. The Decoder, “OpenAI discontinues AI text detector due to lack of accuracy”, July 2023. https://the-decoder.com/openai-discontinues-ai-text-detector-due-to-lack-of-accuracy/
4. Weber-Wulff et al., “Testing of detection tools for AI-generated text”, International Journal for Educational Integrity, 2023. https://doi.org/10.1007/s40979-023-00146-z
5. Sadasivan et al., “Can AI-Generated Text be Reliably Detected?”, 2023. https://arxiv.org/abs/2303.11156
6. Jabarian and Imas, “Artificial Writing and Automated Detection”, Becker Friedman Institute, University of Chicago, 2025. https://bfi.uchicago.edu/working-papers/artificial-writing-and-automated-detection/
7. MIT Sloan Teaching & Learning Technologies, “AI Detectors Don’t Work. Here’s What to Do Instead.”. https://mitsloanedtech.mit.edu/ai/teach/ai-detectors-dont-work/
8. EdWeek, “Black Students Are More Likely to Be Falsely Accused of Using AI to Cheat”, September 2024 (Common Sense Media survey). https://www.edweek.org/technology/black-students-are-more-likely-to-be-falsely-accused-of-using-ai-to-cheat/2024/09
9. Campus Technology, “Turnitin Says Its AI Detector Analyzed 38M Submissions in Six Weeks”, May 2023. https://campustechnology.com/articles/2023/05/turnitin-says-its-ai-detector-analyzed-38m-submissions-in-six-weeks.aspx
10. Vanderbilt University, “Guidance on AI Detection and Why We’re Disabling Turnitin’s AI Detector”, August 2023. https://www.vanderbilt.edu/brightspace/2023/08/16/guidance-on-ai-detection-and-why-were-disabling-turnitins-ai-detector/

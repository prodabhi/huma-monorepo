# Why AI Detection Is a Losing Game

**Checked** = read in a primary or reliable source on 2026-11-05. **Unverified** = open the source yourself before publishing.

Use the CTA boxes from writing-rules.md in this post.

**Angle:** this isn't a bug that gets fixed. Detection gets harder as models improve.

### Facts (checked)

**Paraphrasing breaks detectors.** Sadasivan et al., "Can AI-Generated Text be Reliably Detected?", arXiv 2303.11156 (2023, revised January 2025). https://arxiv.org/abs/2303.11156
- Rewording AI text a few times with a paraphrasing model breaks detectors, and the text barely loses quality.
- It breaks watermarks too: detection of watermarked text reportedly fell from about 99% to about 10%. Check the exact figure in the PDF.
- They prove a theoretical limit: as models write more like people, even the best possible detector does worse.

**"Humanizer" tools exist to beat detectors.**
- Many apps sell "undetectable AI" rewriting. You don't need to name any.
- Plagiarism Today found text run through Grammarly's own "Humanize" feature was labelled "Typed by a Human" in Grammarly Authorship. https://www.plagiarismtoday.com/2025/11/06/how-grammarly-launders-ai-generated-content/

**The Weber-Wulff study:** obfuscation (paraphrasing, editing) significantly worsened every tool.

### Key explanation (your own words)
- A detector reads only the finished text, and the same text can come from a person or a model.
- The more models train on human writing, the more their output looks like it.
- So the only way to know is evidence of the *process*: when each word was typed, what was pasted, and how long it took.

### Outline
1. How detectors work, in plain words (predictability scores and classifiers).
2. Three ways they fail: plain writers, paraphrasing, short texts.
3. The theory: better models mean worse detection.
4. Watermarks won't save it: easy to strip, and not every model uses them.
5. What does work: a record of the writing as it happens.

### FAQ
- How do AI detectors work?
- Can AI detectors be fooled?
- Will AI detectors get better?
- What are perplexity and burstiness?

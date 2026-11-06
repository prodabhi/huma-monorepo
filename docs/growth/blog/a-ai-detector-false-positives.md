# AI Detectors Get It Wrong. Here's How Often.

**Checked** = read in a primary or reliable source on 2026-11-05. **Unverified** = open the source yourself before publishing.

Use the CTA boxes from writing-rules.md in this post.

**Angle:** detectors give a guess, not proof. Even a low error rate means many innocent people when millions of papers are checked.

### Facts (checked)

**Stanford study on non-native English writers**
- Paper: Liang, Yuksekgonul, Mao, Wu, Zou, "GPT detectors are biased against non-native English writers", *Patterns*, 2023. https://arxiv.org/abs/2304.02819
- They tested 7 popular detectors on 91 TOEFL essays written by people.
- About 61% were flagged as AI on average across the detectors.
- All 7 detectors agreed the essay was AI on 18 of 91 (19.8%).
- At least one detector flagged 89 of 91 (97.8%).
- The same detectors were near-perfect on essays by US 8th graders.
- **Why:** detectors score "perplexity", meaning how predictable the words are. Simpler vocabulary looks "AI-like". The authors say the design of many detectors discriminates against non-native writers.

**OpenAI shut down its own detector**
- Taken offline on July 20, 2023, "due to its low rate of accuracy".
- It caught only 26% of AI text and wrongly flagged human text 9% of the time.
- The company that makes ChatGPT couldn't reliably detect ChatGPT.
- Sources: https://the-decoder.com/openai-discontinues-ai-text-detector-due-to-lack-of-accuracy/ and OpenAI's original post at openai.com/blog/new-ai-classifier-for-indicating-ai-written-text (it now carries the shutdown note at the top).

**Turnitin's own numbers**
- Turnitin's Chief Product Officer, Annie Chechitelli, wrote in 2023:
  - Under 1% of whole documents wrongly flagged, for documents with 20% or more AI writing.
  - About 4% of individual highlighted sentences are actually human-written.
  - False-positive sentences cluster where human and AI text meet.
- Turnitin said these metrics may change.
- Sources: https://www.turnitin.co.uk/blog/understanding-the-false-positive-rate-for-sentences-of-our-ai-writing-detection-capability and https://www.turnitin.co.uk/blog/ai-writing-detection-update-from-turnitins-chief-product-officer
- Turnitin reported analysing 38 million submissions in its first six weeks (April–May 2023). https://campustechnology.com/articles/2023/05/turnitin-says-its-ai-detector-analyzed-38m-submissions-in-six-weeks.aspx

**Vanderbilt turned Turnitin's AI detector off**
- Effective August 16, 2023, "for the foreseeable future".
- Their maths: 75,000 papers a year × Turnitin's claimed 1% = about 750 papers that could be wrongly flagged.
- They also cited bias against non-native English writers.
- Source: https://www.vanderbilt.edu/brightspace/2023/08/16/guidance-on-ai-detection-and-why-were-disabling-turnitins-ai-detector/
- Other universities did the same. **Unverified list:** search "[university] disables Turnitin AI detection" before naming any.

**14 tools tested**
- Weber-Wulff et al., "Testing of Detection Tools for AI-Generated Text", *International Journal for Educational Integrity*, 2023. https://doi.org/10.1007/s40979-023-00146-z (arXiv 2306.15666)
- They tested 12 public tools plus Turnitin and PlagiarismCheck.
- Conclusion: the tools are "neither accurate nor reliable".
- They lean toward calling text human, and light editing or paraphrasing makes them much worse.

**Black teens are flagged more often (survey)**
- Common Sense Media, September 2024: a survey of 1,045 parents and their teens aged 13–18.
- About 20% of Black teens said a teacher wrongly flagged their work as AI, versus 7% of white and 10% of Latino teens. 10% of all teens said it happened to them.
- Coverage: https://www.edweek.org/technology/black-students-are-more-likely-to-be-falsely-accused-of-using-ai-to-cheat/2024/09
- Caveat: critics note the report measures what teens reported, not confirmed false positives. Word it as "said their work was wrongly flagged".

**Texas A&M–Commerce, May 2023**
- A professor pasted students' final papers into ChatGPT and asked if it wrote them. ChatGPT said yes for many, and he threatened to withhold grades.
- The university later said no student failed because of it.
- ChatGPT can't tell whether it wrote something, which makes this a clean example of misuse.
- Source: https://news.slashdot.org/story/23/05/17/2023212/ (originally reported by Rolling Stone; link to Rolling Stone if you can find it).

### The other side (include it; it makes the post more trustworthy)

**Some newer detectors test much better.**
- University of Chicago (Becker Friedman Institute) working paper, Jabarian & Imas, 2025, "Artificial Writing and Automated Detection".
- Pangram showed near-zero false positives and false negatives on medium and long passages.
- GPTZero and Originality were mixed, and an open-source baseline flagged 30–78% of human text.
- https://bfi.uchicago.edu/working-papers/artificial-writing-and-automated-detection/

**How to use this honestly:**
- "Some detectors have improved. But even a 1% rate means thousands of innocent people at Turnitin's scale."
- "And a detector, however good, can only tell you its guess, not show you anything."
- That's Huma's opening: show the evidence, not a score.

**Vendor benchmarks:** GPTZero claims about 99% accuracy with a false positive rate around 0.1–0.24%, from its own tests. Call these vendor-reported if you mention them.

### Outline
1. **Answer first:** "AI detectors wrongly flag human writing often enough to matter. OpenAI shut its own down for it, and a Stanford study found popular detectors flagged most essays by non-native English writers as AI."
2. **The numbers:** a table with source, what was tested, and how many people were wrongly flagged.
3. **Why it happens:** perplexity, simple vocabulary, short texts, mixed human and AI text.
4. **Why 1% is still a lot:** the Vanderbilt maths.
5. **Who gets hurt:** non-native speakers, neurodivergent writers, and anyone who writes plainly.
6. **Some detectors are better. It's still a guess.**
7. **The alternative:** show how it was written (Huma), linking to Post F.
8. **FAQ.**

### FAQ
- What is the false positive rate of AI detectors?
- Is Turnitin's AI detector accurate?
- Can AI detectors be wrong?
- Why did OpenAI shut down its AI detector?
- Are AI detectors biased against non-native speakers?

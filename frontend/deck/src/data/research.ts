/* Research data used in the deck. Every figure is copied from the cited source. */

/* Pew Research Center, "How Much of the Internet Is Written With AI?", Aug 2026.
   Share of English webpages showing significant signs of AI authorship. */
export const pewAllPages: [string, number][] = [["2021-01-27", 1.18], ["2021-03-03", 1.13], ["2021-04-20", 1.1], ["2021-05-17", 1.12], ["2021-06-23", 1.08], ["2021-08-01", 1.11], ["2021-09-19", 1.07], ["2021-10-20", 1.13], ["2021-11-30", 1.09], ["2022-01-24", 1.1], ["2022-05-25", 1.04], ["2022-07-06", 1.04], ["2022-08-16", 1.02], ["2022-09-29", 1.07], ["2022-12-08", 1.15], ["2023-02-04", 1.35], ["2023-03-20", 1.53], ["2023-06-09", 1.89], ["2023-09-21", 2.3], ["2023-12-10", 2.78], ["2024-03-01", 3.22], ["2024-04-13", 3.55], ["2024-05-18", 3.49], ["2024-06-24", 3.49], ["2024-07-24", 3.4], ["2024-08-04", 3.8], ["2024-09-20", 3.83], ["2024-10-12", 4.34], ["2024-11-02", 4.51], ["2024-12-10", 4.92], ["2025-01-22", 4.86], ["2025-02-06", 4.92], ["2025-03-23", 4.98], ["2025-04-22", 5.07], ["2025-05-12", 4.93], ["2025-06-22", 4.86], ["2025-07-14", 4.78], ["2025-08-13", 5.24], ["2025-09-12", 5.49], ["2025-10-15", 6.01], ["2025-11-15", 6.29], ["2025-12-11", 6.64], ["2026-01-25", 6.92], ["2026-02-19", 7.28], ["2026-03-15", 8.09], ["2026-04-20", 8.58], ["2026-05-19", 8.86], ["2026-06-06", 8.98], ["2026-07-18", 9.6]];
export const pewNewPages: [string, number][] = [["2022-12-08", 0.0], ["2023-02-04", 1.42], ["2023-03-20", 3.99], ["2023-06-09", 8.35], ["2023-09-21", 13.33], ["2023-12-10", 18.19], ["2024-03-01", 21.31], ["2024-04-13", 22.32], ["2024-05-18", 20.9], ["2024-06-24", 20.5], ["2024-07-24", 20.89], ["2024-08-04", 23.17], ["2024-09-20", 22.85], ["2024-10-12", 23.42], ["2024-11-02", 23.58], ["2024-12-10", 26.83], ["2025-01-22", 28.39], ["2025-02-06", 27.73], ["2025-03-23", 26.54], ["2025-04-22", 26.72], ["2025-05-12", 29.11], ["2025-06-22", 28.85], ["2025-07-14", 27.84], ["2025-08-13", 27.08], ["2025-09-12", 28.56], ["2025-10-15", 30.43], ["2025-11-15", 31.53], ["2025-12-11", 32.38], ["2026-01-25", 33.04], ["2026-02-19", 33.77], ["2026-03-15", 35.34], ["2026-04-20", 37.21], ["2026-05-19", 37.34], ["2026-06-06", 36.57], ["2026-07-18", 35.09]];

/* Originality.ai Social Media AI Tracker, July 2026 (Reddit: June 2026). Posts of 100+ words. */
export const platforms = [
  { label: 'LinkedIn', value: 75.6, detail: 'Jul 2026, 123 posts. 67.6% in Jul 2025.' },
  { label: 'Facebook', value: 64.6, detail: 'Jul 2026, 195 posts.' },
  { label: 'X', value: 63.2, detail: 'Jul 2026, 201 posts. 55.1% in 2025.' },
  { label: 'Reddit', value: 29.0, detail: 'Jun 2026, 559 posts. 21.5% in 2025.' },
];

/* Jones & Bergen, UC San Diego, 2025: share of five-minute Turing tests where the system was picked as the human. */
export const turing = [
  { model: 'ELIZA', judgedHuman: 23 },
  { model: 'GPT-4o', judgedHuman: 21 },
  { model: 'LLaMa-3.1', judgedHuman: 56 },
  { model: 'GPT-4.5', judgedHuman: 73 },
];

export const sources = [
  { n: 1, label: 'Pew Research Center, How Much of the Internet Is Written With AI?, Aug 2026', url: 'https://www.pewresearch.org/data-labs/2026/08/20/how-much-of-the-internet-is-written-with-ai/' },
  { n: 2, label: 'Originality.ai, Social Media AI Tracker Report, Jul 2026', url: 'https://originality.ai/blog/social-media-tracker-july' },
  { n: 3, label: 'Pangram, AI in your feed, 2026', url: 'https://www.pangram.com/blog/ai-in-your-feed' },
  { n: 4, label: 'Kapwing, AI Slop Report, 2025', url: 'https://www.kapwing.com/blog/ai-slop-report-the-global-rise-of-low-quality-ai-videos/' },
  { n: 5, label: 'Pew Research Center, How Americans View AI, Sep 2025', url: 'https://www.pewresearch.org/science/2025/09/17/how-americans-view-ai-and-its-impact-on-people-and-society/' },
  { n: 6, label: 'Reuters Institute, Digital News Report 2025', url: 'https://reutersinstitute.politics.ox.ac.uk/digital-news-report/2025/dnr-executive-summary' },
  { n: 7, label: 'Jones & Bergen, Large Language Models Pass the Turing Test, UC San Diego, 2025', url: 'https://arxiv.org/abs/2503.23674' },
  { n: 8, label: 'Clark et al., All That’s Human Is Not Gold, ACL 2021', url: 'https://aclanthology.org/2021.acl-long.565/' },
  { n: 9, label: 'Kobak et al., Delving into LLM-assisted writing in biomedical publications through excess vocabulary, Science Advances, 2025', url: 'https://www.science.org/doi/full/10.1126/sciadv.adt3813' },
  { n: 10, label: 'Hern, How cheap, outsourced labour in Africa is shaping AI English, The Guardian, Apr 2024', url: 'https://www.theguardian.com/technology/2024/apr/16/techscape-ai-gadgest-humane-ai-pin-chatgpt' },
  { n: 11, label: 'Juzek & Ward, Why Does ChatGPT “Delve” So Much?, COLING 2025', url: 'https://arxiv.org/abs/2412.11385' },
];

/** PubMed abstracts containing the word, per million abstracts, by year (Kobak et al., yearly-counts.csv in
 *  github.com/berenslab/llm-excess-vocab: count ÷ that year's abstracts). */
export const delves: [number, number][] = [[2010, 12], [2011, 17], [2012, 15], [2013, 5], [2014, 20], [2015, 19], [2016, 20],
  [2017, 16], [2018, 26], [2019, 38], [2020, 42], [2021, 49], [2022, 75], [2023, 745], [2024, 3572]];
export const showcasing: [number, number][] = [[2010, 12], [2015, 39], [2019, 86], [2020, 125], [2021, 142], [2022, 166],
  [2023, 519], [2024, 2291]];

import Deck from './deck/Deck';
import Slide from './deck/Slide';
import Reveal from './deck/Reveal';
import Cover from './components/Cover';
import CountUp from './components/CountUp';
import ChartSlide, { AsideStat, BigStats } from './components/ChartSlide';
import Process, { CreateFigure, SignFigure, ShareFigure, VerifyFigure } from './components/Process';
import ResearchLine from './components/ResearchLine';
import HBars from './components/HBars';
import { pewAllPages, pewNewPages, platforms, turing, sources, delves, showcasing } from './data/research';

/* Huma: why online writing needs a paper trail. Every figure is cited on its
   slide and listed on the final sources slide (see src/data/research.ts). */

const year = (date: string) => {
  const [y, m, d] = date.split('-').map(Number);
  return y + (m - 1) / 12 + (d - 1) / 365;
};
const months = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ');
const monthLabel = (v: number) => {
  const y = Math.floor(v);
  return `${months[Math.min(11, Math.round((v - y) * 12))]} ${y}`;
};
const cite = (n: number) => {
  const s = sources.find((x) => x.n === n)!;
  return (
    <a className="cite" href={s.url} target="_blank" rel="noopener" title={s.label}>
      [{n}]
    </a>
  );
};

export default function App() {
  return (
    <Deck>
      <Cover
        nav="Title"
        notes="Open like a paper: title, author, abstract. Then each slide is one figure."
        title="Writing needs a paper trail."
        subtitle={
          <>
            <span className="byline" style={{ display: 'block' }}>Huma · Research note · October 2026</span>
            <span className="abstract" style={{ display: 'block' }}>
              <b>Abstract.</b> A growing share of what people read online shows signs of AI authorship, and most
              people say they can no longer tell. We summarise the published research and describe Huma, which
              records how a page is written so anyone can check it.
            </span>
          </>
        }
      />

      <ChartSlide
        nav="The web"
        notes="Pew sampled about 490,000 English webpages. A third of pages published since ChatGPT show signs of AI writing."
        title="1. The web is filling up with AI."
        source={<><b>Figure 1.</b> English webpages showing signs of AI authorship, 2021 to 2026. Source: Pew Research Center {cite(1)}.</>}
      >
        <ResearchLine
          series={[
            { name: 'AI-generated new pages', tone: 'primary', points: pewNewPages.map(([d, v]) => [year(d), v]) },
            { name: 'AI-generated, all pages', tone: 'ink', points: pewAllPages.map(([d, v]) => [year(d), v]) },
          ]}
          x={{ min: 2021, max: 2026.6, ticks: [2021, 2022, 2023, 2024, 2025, 2026].map((y) => ({ at: y, label: String(y) })) }}
          y={{ max: 40, ticks: [0, 10, 20, 30, 40] }}
          marker={{ at: year('2022-11-30'), label: 'ChatGPT released' }}
          labelOf={monthLabel}
        />
      </ChartSlide>

      <ChartSlide
        nav="Papers"
        notes="Kobak et al. counted words in 15 million PubMed abstracts. 'Delves' was 28 times more common in 2024 than its 2021–22 trend predicted. One idea (The Guardian) is that AI picked it up from raters in Nigeria, where it's common in business English; an early corpus test (Juzek & Ward) didn't support it."
        title="2. Research papers changed their words."
        source={<><b>Figure 2.</b> PubMed abstracts using the word, per million, 2010 to 2024. Source: Kobak et al. {cite(9)}. Why “delve”? One idea {cite(10)}, not supported by an early test {cite(11)}.</>}
        aside={
          <>
            <AsideStat value="28×" label="more “delves” in 2024 than the trend predicted" />
            <AsideStat value="≥13.5%" label="of 2024 abstracts were written with AI help" />
          </>
        }
      >
        <ResearchLine
          series={[
            { name: '“delves”', tone: 'primary', points: delves },
            { name: '“showcasing”', tone: 'ink', points: showcasing },
          ]}
          x={{ min: 2010, max: 2024.4, ticks: [2010, 2012, 2014, 2016, 2018, 2020, 2022, 2024].map((y) => ({ at: y, label: String(y) })) }}
          y={{ max: 4000, ticks: [0, 1000, 2000, 3000, 4000] }}
          unit=""
          marker={{ at: year('2022-11-30'), label: 'ChatGPT released' }}
          labelOf={(v) => String(Math.round(v))}
        />
      </ChartSlide>

      <ChartSlide
        nav="Social"
        notes="Originality.ai flags long posts as likely AI when it is at least 50% confident that 15% or more was AI-written. Hover a bar for its sample size."
        title="3. Social feeds are worse."
        source={<><b>Figure 3.</b> Long posts likely written with AI, July 2026 (Reddit: June) {cite(2)}. Fully AI-generated long posts {cite(3)}. YouTube Shorts {cite(4)}.</>}
        aside={
          <>
            <AsideStat value="1 in 4" label="long posts are fully AI-generated" />
            <AsideStat value="21%" label="of Shorts shown to a new YouTube account were AI-generated" />
          </>
        }
      >
        <HBars rows={platforms} />
      </ChartSlide>

      <ChartSlide
        nav="Trust"
        notes="Pew 2025 for the first two, Reuters Institute Digital News Report 2025 for the third."
        title="4. People can’t tell anymore."
        source={<><b>Table 1.</b> Public attitudes, 2025. Sources: Pew Research Center {cite(5)}; Reuters Institute {cite(6)}.</>}
      >
        <BigStats
          items={[
            { value: <CountUp to={76} suffix="%" />, label: 'want to know if content is AI' },
            { value: <CountUp to={53} suffix="%" />, label: 'aren’t confident if they can tell' },
            { value: <CountUp to={58} suffix="%" />, label: 'worry what’s real in online news' },
          ]}
        />
      </ChartSlide>

      <ChartSlide
        nav="Turing test"
        notes="Five-minute, three-party Turing tests. LLaMa-3.1 and GPT-4.5 were prompted to act human. Spotted = 100% minus the share judged human."
        title="5. Smarter AI is harder to spot."
        source={<><b>Figure 4.</b> Five-minute Turing tests. LLaMa-3.1 and GPT-4.5 were told to act human. Source: Jones &amp; Bergen {cite(7)}.</>}
      >
        <ResearchLine
          series={[
            { name: 'AI passed as human', tone: 'primary', points: turing.map((t, i) => [i, t.judgedHuman]) },
            { name: 'People spotted the AI', tone: 'ink', points: turing.map((t, i) => [i, 100 - t.judgedHuman]) },
          ]}
          x={{ min: 0, max: 3, ticks: turing.map((t, i) => ({ at: i, label: t.model })) }}
          y={{ max: 100, ticks: [0, 25, 50, 75, 100] }}
          reference={{ at: 50, label: 'Coin flip' }}
          labelOf={(i) => turing[i].model}
        />
      </ChartSlide>

      <ChartSlide
        nav="How Huma works"
        notes="Steps 1 and 2 never leave the device. The proof is a self-contained file anyone can verify offline; Base holds a public, independently checkable record of it, with gas sponsored so users never touch crypto. Huma records text today; images, audio and video are planned."
        title="6. How Huma works."
        source={<><b>Figure 5.</b> How a Huma proof is made. Huma records text today; images, audio and video are planned.</>}
      >
        <Process
          privateLabel={<><b>Only you</b> see your drafts and edits.</>}
          sharedLabel={<><b>Anyone</b> can see the final piece and its proof.</>}
          steps={[
            { figure: CreateFigure, title: 'Create', body: 'Write, draw or record in Huma.' },
            { figure: SignFigure, title: 'Sign', body: <>Your device signs each action with a key kept in its <a href="https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web" target="_blank" rel="noopener">Secure Enclave</a>.</> },
            { figure: ShareFigure, title: 'Share the proof', body: <>Huma makes a <a href="https://en.wikipedia.org/wiki/Zero-knowledge_proof" target="_blank" rel="noopener">zero-knowledge proof</a>: a small file you can post anywhere, with a public record on <a href="https://base.org" target="_blank" rel="noopener">Base</a>.</> },
            { figure: VerifyFigure, title: 'Verify', body: 'Anyone can verify the proof in a browser.' },
          ]}
        />
      </ChartSlide>

      <Slide center nav="Conclusion" notes="Close on the call to action.">
        <Reveal>
          <h2 className="display">
            Create with Huma.
            <br />
            <span className="accent-text">Verify with Huma.</span>
          </h2>
          <p className="tagline">A verified human track record, built from everyday creation.</p>
        </Reveal>
      </Slide>

      <Slide nav="References" notes="Every number in this deck links here.">
        <Reveal>
          <div className="kicker" style={{ marginBottom: 18, textAlign: 'center' }}>References</div>
          <ol className="src-list">
            {sources.map((s) => (
              <li key={s.n}>
                <a href={s.url} target="_blank" rel="noopener">[{s.n}] {s.label}</a>
              </li>
            ))}
          </ol>
        </Reveal>
      </Slide>
    </Deck>
  );
}

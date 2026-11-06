/** Grey shapes where a card's title, words and button will be while it loads. index.html draws the same before the script runs. */
export default function Skeleton({ label = 'Loading…' }) {
  return <div className="skeleton" role="status"><span className="sr">{label}</span><i className="title" /><i /><i className="short" /><i className="pill" /></div>;
}

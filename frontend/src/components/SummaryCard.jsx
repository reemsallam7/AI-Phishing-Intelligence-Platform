export default function SummaryCard({ summary }) {
  return (
    <section className="report-card">
      <h2>Executive Summary</h2>
      <p className="summary-text">{summary}</p>
    </section>
  );
}
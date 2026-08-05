export default function ConfidenceCard({ confidence }) {
  return (
    <section className="report-card confidence-card">
      <h2>Confidence</h2>
      <p className="confidence-value">{confidence}%</p>
      <p className="muted-text">Model confidence in this assessment</p>
    </section>
  );
}
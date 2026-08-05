export default function EvidenceList({ evidence }) {
  return (
    <section className="report-card">
      <h2>Evidence</h2>

      {evidence.length > 0 ? (
        <ul className="evidence-list">
          {evidence.map((item) => (
            <li key={item}>
              <span className="check-icon" aria-hidden="true">✓</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted-text">No specific evidence was returned.</p>
      )}
    </section>
  );
}
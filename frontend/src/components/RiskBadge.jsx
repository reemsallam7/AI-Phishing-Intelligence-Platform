export default function RiskBadge({ classification }) {
  const risk = classification.toLowerCase();

  return (
    <div className={`risk-badge risk-${risk}`} aria-label={`Risk: ${classification}`}>
      <span className="risk-dot" aria-hidden="true" />
      <span>{classification}</span>
    </div>
  );
}
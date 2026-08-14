const ANALYSIS_STAGES = [
  "Parsing email",
  "Checking URLs with threat intelligence",
  "Analyzing URL and domain structure",
  "Generating AI assessment",
  "Saving scan",
];


export default function AnalysisProgress({ isAnalyzing }) {
  if (!isAnalyzing) {
    return null;
  }

  return (
    <section className="progress-card" aria-live="polite">
      <h2>Analysis in progress</h2>
      <p>
        The backend is running the security pipeline. Some stages depend on
        external services and may take a little time.
      </p>

      <ol className="progress-list">
        {ANALYSIS_STAGES.map((stage) => (
          <li key={stage}>
            <span className="progress-spinner" aria-hidden="true" />
            <span>{stage}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

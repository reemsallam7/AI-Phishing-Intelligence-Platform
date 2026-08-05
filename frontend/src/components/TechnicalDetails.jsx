export default function TechnicalDetails({
  details,
  virusTotalResults,
  domainAnalysis,
}) {
  return (
    <details className="report-card technical-details">
      <summary>Technical Details</summary>

      <dl>
        <div>
          <dt>Sender</dt>
          <dd>{details.sender}</dd>
        </div>

        <div>
          <dt>Recipient</dt>
          <dd>{details.recipient}</dd>
        </div>

        <div>
          <dt>Subject</dt>
          <dd>{details.subject}</dd>
        </div>

        <div>
          <dt>Scan time</dt>
          <dd>{details.scanTime}</dd>
        </div>

        <div>
          <dt>Number of URLs</dt>
          <dd>{details.urlCount}</dd>
        </div>

        <div>
          <dt>Analysis ID</dt>
          <dd>{details.analysisId}</dd>
        </div>
      </dl>

      <h3>Threat Intelligence Results</h3>
      <pre>{JSON.stringify(virusTotalResults, null, 2)}</pre>

      <h3>Domain Analysis</h3>
      <pre>{JSON.stringify(domainAnalysis, null, 2)}</pre>
    </details>
  );
}
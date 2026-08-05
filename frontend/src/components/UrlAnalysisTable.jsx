export default function UrlAnalysisTable({
  urls,
  virusTotalResults,
  domainAnalysis,
}) {
  return (
    <section className="report-card">
      <h2>URL Analysis</h2>

      {urls.length > 0 ? (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>URL</th>
                <th>VirusTotal</th>
                <th>Domain</th>
                <th>Risk Level</th>
              </tr>
            </thead>
            <tbody>
              {urls.map((url) => {
                const vt = findByUrl(virusTotalResults, url);
                const domain = findByUrl(domainAnalysis, url);
                const risk = calculateUrlRisk(vt, domain);

                return (
                  <tr key={url}>
                    <td className="url-cell">{url}</td>
                    <td>{formatVirusTotal(vt)}</td>
                    <td>{domain?.domain ?? "Unknown"}</td>
                    <td>
                      <span className={`risk-pill risk-${risk.toLowerCase()}`}>
                        {risk}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted-text">No URLs were found in this email.</p>
      )}
    </section>
  );
}

function findByUrl(items, url) {
  return items.find((item) => item.url === url);
}

function formatVirusTotal(result) {
  if (!result) {
    return "No result";
  }

  if (result.status && result.status !== "success") {
    return result.status;
  }

  return `${result.malicious ?? 0} malicious, ${result.suspicious ?? 0} suspicious`;
}

function calculateUrlRisk(vt, domain) {
  if ((vt?.malicious ?? 0) > 0 || domain?.features?.uses_ip_address) {
    return "High";
  }

  if ((vt?.suspicious ?? 0) > 0 || domain?.risk_indicators?.length > 0) {
    return "Medium";
  }

  return "Low";
}
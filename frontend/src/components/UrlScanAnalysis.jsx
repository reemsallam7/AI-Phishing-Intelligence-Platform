export default function UrlScanAnalysis({ results }) {
  return (
    <section className="report-card">
      <h2>URLScan Analysis</h2>

      {results.length > 0 ? (
        <div className="urlscan-grid">
          {results.map((result) => (
            <article className="urlscan-card" key={result.url}>
              {result.screenshot_url && result.status === "completed" ? (
                <img
                  src={result.screenshot_url}
                  alt={`URLScan screenshot for ${result.url}`}
                />
              ) : (
                <div className="screenshot-placeholder">
                  URLScan unavailable.
                </div>
              )}

              <dl>
                <div>
                  <dt>Final URL</dt>
                  <dd>{result.final_url ?? "Unavailable"}</dd>
                </div>

                <div>
                  <dt>Hosting Country</dt>
                  <dd>{result.country ?? "Unavailable"}</dd>
                </div>

                <div>
                  <dt>Server</dt>
                  <dd>{result.server ?? "Unavailable"}</dd>
                </div>

                <div>
                  <dt>IP</dt>
                  <dd>{result.ip ?? "Unavailable"}</dd>
                </div>

                <div>
                  <dt>Verdict</dt>
                  <dd>{result.verdict ?? "Unavailable"}</dd>
                </div>

                <div>
                  <dt>Page Title</dt>
                  <dd>{result.page_title ?? "Unavailable"}</dd>
                </div>
              </dl>

              {result.message && <p className="muted-text">{result.message}</p>}
            </article>
          ))}
        </div>
      ) : (
        <p className="muted-text">No URLScan results available.</p>
      )}
    </section>
  );
}
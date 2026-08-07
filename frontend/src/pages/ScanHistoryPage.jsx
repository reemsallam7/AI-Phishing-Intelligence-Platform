import { useEffect, useState } from "react";
import { fetchScan, fetchScans } from "../services/api";
import { normalizeAnalysisResponse } from "../utils/analysisMapper";

export default function ScanHistoryPage({ onOpenReport }) {
  const [scans, setScans] = useState([]);
  const [search, setSearch] = useState("");
  const [classification, setClassification] = useState("All");
  const [sort, setSort] = useState("newest");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    loadScans();
  }, [classification, sort]);

  async function loadScans() {
    try {
      setIsLoading(true);
      setError("");

      const data = await fetchScans({
        search,
        classification,
        sort,
      });

      setScans(data.scans);
    } catch (error) {
      setError(error.message || "Failed to load scans.");
    } finally {
      setIsLoading(false);
    }
  }

  async function openScan(scanId) {
    try {
      setError("");

      const data = await fetchScan(scanId);
      const report = normalizeAnalysisResponse(data);

      onOpenReport(report);
    } catch (error) {
      setError(error.message || "Failed to open scan.");
    }
  }

  return (
    <section className="page-section">
      <h1>Scan History</h1>

      <div className="history-controls">
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search sender, subject, or URL"
          aria-label="Search scan history"
        />

        <select
          value={classification}
          onChange={(event) => setClassification(event.target.value)}
          aria-label="Filter by classification"
        >
          <option>All</option>
          <option>Safe</option>
          <option>Suspicious</option>
          <option>Phishing</option>
        </select>

        <select
          value={sort}
          onChange={(event) => setSort(event.target.value)}
          aria-label="Sort scans"
        >
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
          <option value="highest-confidence">Highest confidence</option>
          <option value="lowest-confidence">Lowest confidence</option>
        </select>

        <button type="button" onClick={loadScans}>
          Search
        </button>
      </div>

      {isLoading && <p className="status-message">Loading scans...</p>}
      {error && <p className="error-message">{error}</p>}

      {!isLoading && scans.length === 0 && (
        <p className="muted-text">No scans found.</p>
      )}

      {scans.length > 0 && (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Subject</th>
                <th>Sender</th>
                <th>Risk</th>
                <th>Confidence</th>
                <th>Date</th>
                <th>URLs</th>
              </tr>
            </thead>

            <tbody>
              {scans.map((scan) => (
                <tr
                  key={scan.id}
                  className="clickable-row"
                  onClick={() => openScan(scan.id)}
                >
                  <td>{scan.subject ?? "Missing"}</td>
                  <td>{scan.sender ?? "Missing"}</td>
                  <td>{scan.classification}</td>
                  <td>{scan.confidence}%</td>
                  <td>{formatDate(scan.created_at)}</td>
                  <td>{scan.url_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  return new Date(value).toLocaleString();
}
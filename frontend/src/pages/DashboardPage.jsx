import { useEffect, useState } from "react";
import { fetchDashboardStats } from "../services/api";

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  async function loadStats() {
    try {
      setIsLoading(true);
      setError("");

      const data = await fetchDashboardStats();
      setStats(data);
    } catch (error) {
      setError(error.message || "Failed to load dashboard.");
    } finally {
      setIsLoading(false);
    }
  }

  if (isLoading) {
    return <p className="status-message">Loading dashboard...</p>;
  }

  if (error) {
    return <p className="error-message">{error}</p>;
  }

  if (!stats) {
    return null;
  }

  return (
    <section className="page-section">
      <h1>Dashboard</h1>

      <div className="stats-grid">
        <StatCard title="Total Scans" value={stats.total_scans} />
        <StatCard
          title="Phishing"
          value={stats.phishing}
          detail={`${stats.phishing_percentage}%`}
        />
        <StatCard
          title="Suspicious"
          value={stats.suspicious}
          detail={`${stats.suspicious_percentage}%`}
        />
        <StatCard
          title="Safe"
          value={stats.safe}
          detail={`${stats.safe_percentage}%`}
        />
      </div>

      <section className="report-card">
        <h2>Classification Distribution</h2>

        {stats.total_scans === 0 ? (
          <p className="muted-text">No scans have been created yet.</p>
        ) : (
          <div className="bar-chart">
            {stats.classification_distribution.map((item) => (
              <div className="bar-row" key={item.label}>
                <span>{item.label}</span>

                <div className="bar-track">
                  <div
                    className={`bar-fill bar-${item.label.toLowerCase()}`}
                    style={{
                      width: `${(item.count / stats.total_scans) * 100}%`,
                    }}
                  />
                </div>

                <strong>{item.count}</strong>
              </div>
            ))}
          </div>
        )}
      </section>
    </section>
  );
}

function StatCard({ title, value, detail }) {
  return (
    <section className="stat-card">
      <h2>{title}</h2>
      <p>{value}</p>
      {detail && <span>{detail}</span>}
    </section>
  );
}
import { useState } from "react";
import "./App.css";

import AnalysisProgress from "./components/AnalysisProgress";
import ConfidenceCard from "./components/ConfidenceCard";
import DashboardPage from "./pages/DashboardPage";
import EvidenceList from "./components/EvidenceList";
import Navigation from "./components/Navigation";
import RecommendationList from "./components/RecommendationList";
import RiskBadge from "./components/RiskBadge";
import ScanHistoryPage from "./pages/ScanHistoryPage";
import SummaryCard from "./components/SummaryCard";
import TechnicalDetails from "./components/TechnicalDetails";
import UrlAnalysisTable from "./components/UrlAnalysisTable";
import URLScanAnalysis from "./components/UrlScanAnalysis";
import { normalizeAnalysisResponse } from "./utils/analysisMapper";

const ANALYSIS_TIMEOUT_MS = 180000;

function App() {
  const [emailText, setEmailText] = useState("");
  const [report, setReport] = useState(null);
  const [statusMessage, setStatusMessage] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentPage, setCurrentPage] = useState("analyze");

  async function handleAnalyzeClick() {
    setIsAnalyzing(true);
    setStatusMessage("");
    setReport(null);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), ANALYSIS_TIMEOUT_MS);

    try {
      const response = await fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: emailText,
        }),
        signal: controller.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        setStatusMessage(data.error ?? "Analysis failed.");
        return;
      }

      setStatusMessage(data.message ?? "Analysis complete.");
      setReport(normalizeAnalysisResponse(data));
    } catch (error) {
      if (error.name === "AbortError") {
        setStatusMessage("Analysis timed out. Try again with fewer URLs or retry later.");
      } else {
        setStatusMessage(error.message || "Could not connect to the backend.");
      }
    } finally {
      clearTimeout(timeoutId);
      setIsAnalyzing(false);
    }
  }

  function handleClearClick() {
    setEmailText("");
    setReport(null);
    setStatusMessage("");
  }

  function handleOpenHistoryReport(historyReport) {
    setReport(historyReport);
    setStatusMessage("Loaded a previous scan from history.");
    setCurrentPage("analyze");
  }

  return (
    <main className="app-shell">
      <Navigation currentPage={currentPage} onNavigate={setCurrentPage} />

      {currentPage === "analyze" && (
        <>
          <section className="input-panel" aria-labelledby="page-title">
            <div>
              <p className="eyebrow">AI Phishing Intelligence Platform</p>
              <h1 id="page-title">Email Threat Analysis</h1>
              <p className="page-description">
                Paste a suspicious email to generate a readable phishing risk report.
              </p>
            </div>

            <label htmlFor="email-input">Email content</label>

            <textarea
              id="email-input"
              value={emailText}
              onChange={(event) => setEmailText(event.target.value)}
              placeholder="Paste the full email here..."
            />

            <div className="actions">
              <p>{emailText.length} characters</p>

              <div className="button-group">
                <button
                  type="button"
                  onClick={handleAnalyzeClick}
                  disabled={isAnalyzing}
                >
                  {isAnalyzing ? "Analyzing..." : "Analyze Email"}
                </button>

                <button
                  type="button"
                  className="secondary-button"
                  onClick={handleClearClick}
                >
                  Clear
                </button>
              </div>
            </div>

            {statusMessage && <p className="status-message">{statusMessage}</p>}
          </section>

          <AnalysisProgress isAnalyzing={isAnalyzing} />

          {report && (
            <section className="report" aria-labelledby="report-title">
              <div className="report-header">
                <div>
                  <p className="eyebrow">Analysis Report</p>
                  <h2 id="report-title">Overall Risk Assessment</h2>
                </div>

                <RiskBadge classification={report.classification} />
              </div>

              <div className="report-grid">
                <ConfidenceCard confidence={report.confidence} />
                <SummaryCard summary={report.summary} />
              </div>

              <EvidenceList evidence={report.explanation} />

              <RecommendationList recommendations={report.recommendations} />

              <UrlAnalysisTable
                urls={report.urls}
                virusTotalResults={report.virusTotalResults}
                domainAnalysis={report.domainAnalysis}
              />

              <URLScanAnalysis results={report.urlScanResults} />

              <TechnicalDetails
                details={report.technicalDetails}
                virusTotalResults={report.virusTotalResults}
                domainAnalysis={report.domainAnalysis}
              />
            </section>
          )}
        </>
      )}

      {currentPage === "dashboard" && <DashboardPage />}

      {currentPage === "history" && (
        <ScanHistoryPage onOpenReport={handleOpenHistoryReport} />
      )}
    </main>
  );
}

export default App;

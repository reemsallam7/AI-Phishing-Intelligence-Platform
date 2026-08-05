import { useState } from "react";
import "./App.css";

import ConfidenceCard from "./components/ConfidenceCard";
import EvidenceList from "./components/EvidenceList";
import RecommendationList from "./components/RecommendationList";
import RiskBadge from "./components/RiskBadge";
import SummaryCard from "./components/SummaryCard";
import TechnicalDetails from "./components/TechnicalDetails";
import UrlAnalysisTable from "./components/UrlAnalysisTable";
import { normalizeAnalysisResponse } from "./utils/analysisMapper";

function App() {
  const [emailText, setEmailText] = useState("");
  const [report, setReport] = useState(null);
  const [statusMessage, setStatusMessage] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  async function handleAnalyzeClick() {
    setIsAnalyzing(true);
    setStatusMessage("");
    setReport(null);

    try {
      const response = await fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: emailText,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setStatusMessage(data.error ?? "Analysis failed.");
        return;
      }

      setStatusMessage(data.message ?? "Analysis complete.");
      setReport(normalizeAnalysisResponse(data));
    } catch {
      setStatusMessage("Could not connect to the backend.");
    } finally {
      setIsAnalyzing(false);
    }
  }

  function handleClearClick() {
    setEmailText("");
    setReport(null);
    setStatusMessage("");
  }

  return (
    <main className="app-shell">
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

            <button type="button" className="secondary-button" onClick={handleClearClick}>
              Clear
            </button>
          </div>
        </div>

        {statusMessage && <p className="status-message">{statusMessage}</p>}
      </section>

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

          <TechnicalDetails
            details={report.technicalDetails}
            virusTotalResults={report.virusTotalResults}
            domainAnalysis={report.domainAnalysis}
          />
        </section>
      )}
    </main>
  );
}

export default App;
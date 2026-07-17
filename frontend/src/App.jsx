import { useState } from "react";
import "./App.css";

function App() {
  const [emailText, setEmailText] = useState("");
  const [backendMessage, setBackendMessage] = useState("");
  const [parsedEmail, setParsedEmail] = useState(null);

  function handleEmailChange(event) {
    setEmailText(event.target.value);
  }

  function handleClearClick() {
  setEmailText("");
  setBackendMessage("");
  setParsedEmail(null);
}

  async function handleAnalyzeClick() {
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

    if (response.ok) {
      setBackendMessage(data.message);
      setParsedEmail(data.parsed_email);
    } else {
      setBackendMessage(data.error);
      setParsedEmail(null);
    }
  }

  return (
    <main className="page">
      <section className="email-panel">
        <h1>AI Phishing Intelligence Platform</h1>

        <p className="intro">
          Paste a suspicious email below. This sprint only parses the email
          into basic fields.
        </p>

        <label htmlFor="email-input">Email content</label>

        <textarea
          id="email-input"
          value={emailText}
          onChange={handleEmailChange}
          placeholder="Paste the email content here..."
        />

        <div className="actions">
          <p>{emailText.length} characters</p>

          <button type="button" onClick={handleAnalyzeClick}>
            Analyze Email
          </button>
          <button type="button" onClick={handleClearClick}>
            Clear
          </button>
        </div>

        {backendMessage && <p className="result-message">{backendMessage}</p>}

        {parsedEmail && (
  <section className="parsed-email">
    <h2>Parsed Email</h2>

    <p><strong>From:</strong> {parsedEmail.from ?? "Missing"}</p>
    <p><strong>To:</strong> {parsedEmail.to ?? "Missing"}</p>
    <p><strong>Subject:</strong> {parsedEmail.subject ?? "Missing"}</p>

    <p><strong>Body:</strong></p>
    <pre>{parsedEmail.body ?? "Missing"}</pre>

    <h3>Extracted URLs</h3>

    {parsedEmail.urls.length > 0 ? (
      <ul>
        {parsedEmail.urls.map((url) => (
          <li key={url}>{url}</li>
        ))}
      </ul>
    ) : (
      <p>No URLs found.</p>
    )}

    <h3>VirusTotal Reputation</h3>

{parsedEmail.url_reputation.length > 0 ? (
  <ul>
    {parsedEmail.url_reputation.map((result) => (
      <li key={result.url}>
        <strong>{result.url}</strong>
        <br />
        Status: {result.status}
        <br />
        Malicious: {result.malicious ?? "N/A"}
        <br />
        Suspicious: {result.suspicious ?? "N/A"}
        <br />
        Harmless: {result.harmless ?? "N/A"}
        <br />
        Undetected: {result.undetected ?? "N/A"}
        {result.message && (
          <>
            <br />
            Message: {result.message}
          </>
        )}
      </li>
    ))}
  </ul>
) : (
  <p>No URL reputation results.</p>
)}

  <h3>URL Analysis</h3>

{parsedEmail.url_analysis.length > 0 ? (
  <ul>
    {parsedEmail.url_analysis.map((analysis) => (
      <li key={analysis.url}>
        <strong>{analysis.url}</strong>
        <br />
        Scheme: {analysis.scheme || "Missing"}
        <br />
        Domain: {analysis.domain || "Missing"}
        <br />
        Path: {analysis.path || "Missing"}
        <br />
        TLD: {analysis.tld || "Missing"}
        <br />
        URL length: {analysis.features.url_length}
        <br />
        Dots: {analysis.features.dot_count}
        <br />
        Hyphens: {analysis.features.hyphen_count}
        <br />
        Digits: {analysis.features.digit_count}
        <br />
        Uses HTTPS: {analysis.features.uses_https ? "Yes" : "No"}
        <br />
        Uses IP address: {analysis.features.uses_ip_address ? "Yes" : "No"}

        <br />
        Risk indicators:
        {analysis.risk_indicators.length > 0 ? (
          <ul>
            {analysis.risk_indicators.map((indicator) => (
              <li key={indicator}>{indicator}</li>
            ))}
          </ul>
        ) : (
          <p>No simple risk indicators found.</p>
        )}
      </li>
    ))}
  </ul>
) : (
  <p>No URL analysis available.</p>
)}

  </section>

)}
      </section>
    </main>
  );
}

export default App;
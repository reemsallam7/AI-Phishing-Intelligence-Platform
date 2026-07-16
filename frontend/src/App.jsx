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
          </section>
        )}
      </section>
    </main>
  );
}

export default App;
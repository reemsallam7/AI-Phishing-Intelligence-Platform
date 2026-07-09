import { useState } from "react";
import "./App.css";

function App() {
  const [emailText, setEmailText] = useState("");
  const [backendMessage, setBackendMessage] = useState("");

  function handleEmailChange(event) {
    setEmailText(event.target.value);
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
  } else {
    setBackendMessage(data.error);
  }
  }

  return (
    <main className="page">
      <section className="email-panel">
        <h1>AI Phishing Intelligence Platform</h1>

        <p className="intro">
          Paste a suspicious email below. In a later sprint, this tool will help
          analyze it for phishing signals.
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
        </div>

        {backendMessage && <p className="result-message">{backendMessage}</p>}
      </section>
    </main>
  );
}

export default App;
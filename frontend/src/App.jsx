import { useState } from "react";
import "./App.css";

function App() {
  const [emailText, setEmailText] = useState("");

  function handleEmailChange(event) {
    setEmailText(event.target.value);
  }

  function handleAnalyzeClick() {
    alert("Email analysis will be added in a later sprint.");
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
      </section>
    </main>
  );
}

export default App;
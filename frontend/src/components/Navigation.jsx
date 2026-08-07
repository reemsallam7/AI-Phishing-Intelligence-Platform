export default function Navigation({ currentPage, onNavigate }) {
  return (
    <nav className="navigation" aria-label="Main navigation">
      <button
        type="button"
        className={currentPage === "analyze" ? "nav-active" : ""}
        onClick={() => onNavigate("analyze")}
      >
        Analyze Email
      </button>

      <button
        type="button"
        className={currentPage === "dashboard" ? "nav-active" : ""}
        onClick={() => onNavigate("dashboard")}
      >
        Dashboard
      </button>

      <button
        type="button"
        className={currentPage === "history" ? "nav-active" : ""}
        onClick={() => onNavigate("history")}
      >
        Scan History
      </button>
    </nav>
  );
}
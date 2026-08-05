export default function RecommendationList({ recommendations }) {
  return (
    <section className="report-card">
      <h2>Recommendations</h2>

      {recommendations.length > 0 ? (
        <ul className="recommendation-list">
          {recommendations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted-text">No recommendations were returned.</p>
      )}
    </section>
  );
}
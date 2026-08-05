export function normalizeAnalysisResponse(data) {
  const ai = data.ai_analysis ?? data;

  return {
    classification: ai.classification ?? "Suspicious",
    confidence: ai.confidence ?? 50,
    summary: ai.summary ?? buildFallbackSummary(ai),
    explanation: ai.explanation ?? [],
    recommendations: ai.recommendations ?? [],
    urls: data.urls ?? data.parsed_email?.urls ?? [],
    virusTotalResults:
      data.virusTotalResults ?? data.parsed_email?.url_reputation ?? [],
    domainAnalysis:
      data.domainAnalysis ?? data.parsed_email?.url_analysis ?? [],
    technicalDetails: {
      sender: data.parsed_email?.from ?? data.sender ?? "Missing",
      recipient: data.parsed_email?.to ?? data.recipient ?? "Missing",
      subject: data.parsed_email?.subject ?? data.subject ?? "Missing",
      scanTime: data.created_at ?? new Date().toLocaleString(),
      urlCount: data.parsed_email?.urls?.length ?? data.urls?.length ?? 0,
      analysisId: data.analysis_id ?? "Not saved",
    },
  };
}

function buildFallbackSummary(ai) {
  return `The analysis classified this email as ${
    ai.classification ?? "Suspicious"
  } with ${ai.confidence ?? 50}% confidence.`;
}
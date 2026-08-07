export function normalizeAnalysisResponse(data) {
  const ai = data.ai_analysis ?? data;

  return {
    classification: ai.classification ?? "Suspicious",
    confidence: ai.confidence ?? ai.confidence_score ?? 50,
    summary: ai.summary ?? buildFallbackSummary(ai),
    explanation: Array.isArray(ai.explanation) ? ai.explanation : [],
    recommendations: Array.isArray(ai.recommendations)
      ? ai.recommendations
      : [],

    urls: data.parsed_email?.urls ?? data.urls ?? [],
    virusTotalResults:
      data.parsed_email?.url_reputation ?? data.virusTotalResults ?? [],
    domainAnalysis:
      data.parsed_email?.url_analysis ?? data.domainAnalysis ?? [],
    urlScanResults:
      data.parsed_email?.urlscan_results ?? data.urlScanResults ?? [],
    technicalDetails: {
      sender: data.parsed_email?.from ?? "Missing",
      recipient: data.parsed_email?.to ?? "Missing",
      subject: data.parsed_email?.subject ?? "Missing",
      scanTime: data.created_at ?? new Date().toLocaleString(),
      urlCount: data.parsed_email?.urls?.length ?? 0,
      analysisId: data.analysis_id ?? "Not saved",
    },
  };
}

function buildFallbackSummary(ai) {
  return `The analysis classified this email as ${
    ai.classification ?? "Suspicious"
  } with ${ai.confidence ?? ai.confidence_score ?? 50}% confidence.`;
}
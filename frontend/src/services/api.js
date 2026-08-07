const API_BASE_URL = "http://127.0.0.1:5000";

export async function fetchScans({ search, classification, sort }) {
  const params = new URLSearchParams();

  if (search) params.set("search", search);
  if (classification) params.set("classification", classification);
  if (sort) params.set("sort", sort);

  const response = await fetch(`${API_BASE_URL}/api/scans?${params.toString()}`);

  if (!response.ok) {
    throw new Error("Failed to load scans.");
  }

  return response.json();
}

export async function fetchScan(scanId) {
  const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}`);

  if (response.status === 404) {
    throw new Error("Scan not found.");
  }

  if (!response.ok) {
    throw new Error("Failed to load scan.");
  }

  return response.json();
}

export async function fetchDashboardStats() {
  const response = await fetch(`${API_BASE_URL}/api/dashboard/stats`);

  if (!response.ok) {
    throw new Error("Failed to load dashboard statistics.");
  }

  return response.json();
}
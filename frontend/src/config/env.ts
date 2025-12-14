export const API_BASE =
    process.env.REACT_APP_API_URL || "http://localhost:8000";

export const GITHUB_OAUTH_URL =
    process.env.REACT_APP_GITHUB_OAUTH_URL || `${API_BASE}/auth/github`;


import { API_BASE } from "../config/env";

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

export async function request<T>(
    path: string,
    options: {
        method?: HttpMethod;
        body?: unknown;
        headers?: Record<string, string>;
    } = {}
): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
        method: options.method ?? "GET",
        headers: {
            "Content-Type": "application/json",
            ...(options.headers ?? {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
        credentials: "include",
    });

    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(text || `HTTP ${res.status}`);
    }

    return (await res.json()) as T;
}

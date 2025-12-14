import { request } from "./http";
import type { LoginRequest, LoginResponse } from "../types/auth";

export async function login(payload: LoginRequest): Promise<LoginResponse> {
    return request<LoginResponse>("/auth/login", {
        method: "POST",
        body: payload,
    });
}

import { apiRequest } from "./queryClient";

export interface AuthResponse {
  isAuthenticated: boolean;
  userId?: number;
  username?: string;
  role?: string;
}

export const authApi = {
  login: async (username: string, password: string) => {
    const response = await apiRequest("POST", "/api/auth/login", {
      username,
      password,
    });
    return response.json();
  },

  logout: async () => {
    const response = await apiRequest("POST", "/api/auth/logout");
    return response.json();
  },

  getMe: async (): Promise<AuthResponse> => {
    const response = await fetch("/api/auth/me", {
      credentials: "include",
    });
    return response.json();
  },
};

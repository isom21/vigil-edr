import { api } from "./client";
import type { User } from "@/types/api";

export const usersApi = {
  list: () => api<User[]>("/api/users"),
  get: (id: string) => api<User>(`/api/users/${id}`),
};

import { api } from "./client";
import type { User, UserRole } from "@/types/api";

export interface UserCreateBody {
  email: string;
  password: string;
  role: UserRole;
}

export interface UserUpdateBody {
  email?: string;
  password?: string;
  role?: UserRole;
  disabled?: boolean;
}

export interface UserGroupAssignment {
  host_group_ids: string[];
}

export const usersApi = {
  list: () => api<User[]>("/api/users"),
  get: (id: string) => api<User>(`/api/users/${id}`),
  create: (body: UserCreateBody) => api<User>("/api/users", { method: "POST", body }),
  update: (id: string, body: UserUpdateBody) =>
    api<User>(`/api/users/${id}`, { method: "PATCH", body }),
  remove: (id: string) => api<void>(`/api/users/${id}`, { method: "DELETE" }),
  getGroups: (id: string) => api<UserGroupAssignment>(`/api/users/${id}/groups`),
  replaceGroups: (id: string, body: UserGroupAssignment) =>
    api<UserGroupAssignment>(`/api/users/${id}/groups`, { method: "POST", body }),
  // Admin account-recovery for users who've lost both their
  // authenticator and recovery codes. Always audited as
  // `user.2fa.admin_disabled`; never silent.
  disable2FA: (id: string) => api<void>(`/api/users/${id}/2fa/disable`, { method: "POST" }),
};

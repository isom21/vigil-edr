import { FormEvent, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { login, login2fa } from "@/api/auth";
import { ApiError } from "@/api/client";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type Stage = { kind: "password" } | { kind: "mfa"; mfaToken: string };

export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, refresh } = useAuth();
  const [stage, setStage] = useState<Stage>({ kind: "password" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (isAuthenticated) {
    const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname;
    return <Navigate to={from ?? "/dashboard"} replace />;
  }

  const onSubmitPassword = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await login(email, password);
      if (result.kind === "mfa") {
        setStage({ kind: "mfa", mfaToken: result.mfaToken });
        setCode("");
      } else {
        refresh();
        navigate("/dashboard", { replace: true });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "login failed");
    } finally {
      setSubmitting(false);
    }
  };

  const onSubmit2FA = async (e: FormEvent) => {
    e.preventDefault();
    if (stage.kind !== "mfa") return;
    setError(null);
    setSubmitting(true);
    try {
      await login2fa(stage.mfaToken, code);
      refresh();
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "verification failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="mb-2 flex items-center gap-2">
            <Shield className="h-5 w-5" />
            <CardTitle className="text-xl">Vigil</CardTitle>
          </div>
          <CardDescription>
            {stage.kind === "password"
              ? "Sign in to the Vigil manager."
              : "Enter the 6-digit code from your authenticator app, or a recovery code."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {stage.kind === "password" ? (
            <form onSubmit={onSubmitPassword} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              {error && (
                <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {error}
                </div>
              )}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Signing in..." : "Sign in"}
              </Button>
            </form>
          ) : (
            <form onSubmit={onSubmit2FA} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="code">Verification code</Label>
                <Input
                  id="code"
                  type="text"
                  inputMode="text"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="123456 or recovery code"
                />
                <p className="text-xs text-muted-foreground">
                  Lost your authenticator? A recovery code works here too — they&apos;re one-shot,
                  so one will be consumed.
                </p>
              </div>
              {error && (
                <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {error}
                </div>
              )}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Verifying..." : "Verify"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="w-full"
                onClick={() => {
                  setStage({ kind: "password" });
                  setCode("");
                  setError(null);
                }}
              >
                ← Back to sign in
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

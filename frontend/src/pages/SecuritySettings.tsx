/**
 * Self-service account security: TOTP 2FA enroll / disable +
 * recovery-code download.
 *
 * Three states drive the panel:
 *   1. disabled — show the "Enable two-factor" button.
 *   2. enrolling — we have a fresh secret; show QR + manual entry +
 *      a 6-digit confirm input.
 *   3. enabled — confirm screen + recovery codes (only on the
 *      transition from enrolling→enabled), then a "Disable" path.
 *
 * Recovery codes leave the server exactly once, at the moment
 * verify-setup succeeds. We keep them in component state so the
 * user can download / copy them, and warn aggressively before
 * navigating away.
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { Copy, KeyRound, ShieldCheck, ShieldOff } from "lucide-react";
import { totpApi } from "@/api/auth";
import { ApiError } from "@/api/client";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import type { TotpSetupResponse } from "@/types/api";

export function SecuritySettings() {
  return (
    <>
      <PageHeader
        title="Account security"
        description="Two-factor authentication for your account. Opt-in; not enforced."
      />
      <div className="space-y-4 px-8 py-6">
        <TwoFactorCard />
      </div>
    </>
  );
}

function TwoFactorCard() {
  const { refresh: refreshAuth } = useAuth();
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["2fa-status"],
    queryFn: () => totpApi.status(),
  });

  // Local UI state for the in-progress enrollment.
  const [setup, setSetup] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disableCode, setDisableCode] = useState("");

  // Reset transient state when status changes underneath us (e.g.
  // admin force-disabled).
  useEffect(() => {
    if (status.data?.enabled) {
      setSetup(null);
      setCode("");
    }
    if (!status.data?.enabled && !status.data?.pending) {
      setSetup(null);
      setCode("");
      setRecoveryCodes(null);
    }
  }, [status.data?.enabled, status.data?.pending]);

  const startSetup = useMutation({
    mutationFn: () => totpApi.setup(),
    onSuccess: (data) => {
      setSetup(data);
      setError(null);
      qc.invalidateQueries({ queryKey: ["2fa-status"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const verifySetup = useMutation({
    mutationFn: () => totpApi.verifySetup(code),
    onSuccess: (data) => {
      setRecoveryCodes(data.recovery_codes);
      setSetup(null);
      setCode("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["2fa-status"] });
      qc.invalidateQueries({ queryKey: ["users"] });
      refreshAuth();
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  const disable = useMutation({
    mutationFn: () => totpApi.disable(disableCode),
    onSuccess: () => {
      setDisableCode("");
      setError(null);
      setRecoveryCodes(null);
      qc.invalidateQueries({ queryKey: ["2fa-status"] });
      qc.invalidateQueries({ queryKey: ["users"] });
      refreshAuth();
    },
    onError: (err) => setError(err instanceof ApiError ? err.detail : String(err)),
  });

  if (status.isLoading) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Two-factor authentication</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">Loading…</p>
        </CardContent>
      </Card>
    );
  }

  // After a successful verify-setup we render the recovery codes once,
  // immediately after the panel flips to "enabled".
  if (recoveryCodes) {
    return (
      <RecoveryCodesPanel codes={recoveryCodes} onAcknowledge={() => setRecoveryCodes(null)} />
    );
  }

  if (status.data?.enabled) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
            Two-factor authentication is on
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            You&apos;ll be asked for a 6-digit code (or a recovery code) every time you sign in.
          </p>
          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              disable.mutate();
            }}
          >
            <Label htmlFor="disable-code">Disable two-factor</Label>
            <p className="text-xs text-muted-foreground">
              Enter a current 6-digit code or a recovery code to confirm. Required so a stolen
              session can&apos;t silently turn 2FA off.
            </p>
            <div className="flex gap-2">
              <Input
                id="disable-code"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
                placeholder="123456 or recovery code"
                required
              />
              <Button
                type="submit"
                variant="destructive"
                size="sm"
                disabled={disable.isPending || !disableCode}
              >
                <ShieldOff className="h-3.5 w-3.5" aria-hidden="true" />
                {disable.isPending ? "Disabling…" : "Disable"}
              </Button>
            </div>
            {error && (
              <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}
          </form>
        </CardContent>
      </Card>
    );
  }

  if (setup) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Scan with your authenticator</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <div className="flex flex-col items-start gap-4 sm:flex-row">
            <div className="rounded-md border bg-white p-3">
              <QRCodeSVG value={setup.provisioning_uri} size={192} level="M" />
            </div>
            <div className="flex-1 space-y-2">
              <p className="text-muted-foreground">
                Open Google Authenticator, 1Password, Authy, or any TOTP app and scan this code. If
                you can&apos;t scan, enter the secret manually:
              </p>
              <div className="flex items-center gap-2 rounded-md border bg-muted/30 px-3 py-2 font-mono text-xs">
                <span className="flex-1 break-all">{setup.secret_base32}</span>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Copy secret"
                  onClick={() => navigator.clipboard.writeText(setup.secret_base32)}
                  className="h-6 w-6"
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </div>
          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              verifySetup.mutate();
            }}
          >
            <Label htmlFor="verify-code">Enter the 6-digit code to confirm</Label>
            <div className="flex gap-2">
              <Input
                id="verify-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                pattern="\d{6}"
                maxLength={6}
                placeholder="123456"
                autoFocus
                required
              />
              <Button type="submit" size="sm" disabled={verifySetup.isPending || code.length !== 6}>
                {verifySetup.isPending ? "Verifying…" : "Confirm"}
              </Button>
            </div>
            {error && (
              <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setSetup(null);
                setCode("");
                setError(null);
              }}
            >
              Cancel
            </Button>
          </form>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRound className="h-4 w-4" />
          Two-factor authentication
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Add a time-based one-time passcode (TOTP) to your account. After enabling, you&apos;ll
          enter a 6-digit code from your authenticator app every time you sign in. You&apos;ll get
          ten one-shot recovery codes you can save somewhere safe in case you lose access to your
          authenticator.
        </p>
        {error && (
          <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
        <Button
          size="sm"
          onClick={() => {
            setError(null);
            startSetup.mutate();
          }}
          disabled={startSetup.isPending}
        >
          {startSetup.isPending ? "Generating…" : "Enable two-factor"}
        </Button>
      </CardContent>
    </Card>
  );
}

function RecoveryCodesPanel({
  codes,
  onAcknowledge,
}: {
  codes: string[];
  onAcknowledge: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);

  const text = useMemo(() => codes.join("\n"), [codes]);

  const download = () => {
    const blob = new Blob(
      [
        "Vigil EDR — recovery codes\n" +
          "Generated " +
          new Date().toISOString() +
          "\n" +
          "Each code works exactly once. Treat them like passwords.\n\n" +
          text +
          "\n",
      ],
      { type: "text/plain" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigil-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card className="border-amber-500/40">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-4 w-4 text-emerald-500" />
          Two-factor enabled — save your recovery codes
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          These codes are shown <span className="font-semibold">once</span>. Each one works exactly
          once. If you lose access to your authenticator, you can sign in with a recovery code
          instead of a TOTP. Save them to a password manager or print them.
        </p>
        <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/30 p-3 font-mono text-sm">
          {codes.map((c) => (
            <div key={c} className="select-all">
              {c}
            </div>
          ))}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => navigator.clipboard.writeText(text)}>
            <Copy className="h-3.5 w-3.5" aria-hidden="true" />
            Copy all
          </Button>
          <Button size="sm" variant="outline" onClick={download}>
            Download .txt
          </Button>
        </div>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I&apos;ve saved these codes somewhere safe.
        </label>
        <Button size="sm" disabled={!acknowledged} onClick={onAcknowledge}>
          Done
        </Button>
      </CardContent>
    </Card>
  );
}

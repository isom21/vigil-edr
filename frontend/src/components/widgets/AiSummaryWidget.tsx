/**
 * AI summary card (Phase 4 #4.1).
 *
 * Reads `GET /api/alerts/:id/summary`. A 404 is the expected initial
 * state — the summariser worker hasn't produced a row yet — and
 * renders a small "AI analysis pending" spinner rather than an error
 * card so the analyst's first impression isn't a red box.
 *
 * The summary itself comes back as plain text. The model is
 * prompted to keep paragraphs short; we render it inside a `prose`-
 * style block but deliberately avoid pulling in a Markdown
 * dependency for this one surface — the model rarely emits
 * meaningful Markdown, and the cost of `react-markdown` + its
 * `remark` stack on the alert-detail bundle is not worth the gain.
 * Line breaks survive via CSS (`whitespace-pre-line`); links and
 * emphasis show as plain text.
 *
 * The suggested-response chips render only entries whose `kind` is
 * one of the recognised values. Unknown kinds are dropped so a
 * model prompt change can't crash the card; the operator can tune
 * the prompt without coordinating a frontend release.
 */
import { useQuery } from "@tanstack/react-query";
import { Loader2, Sparkles } from "lucide-react";

import { aiApi } from "@/api/ai";
import { ApiError } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AiSuggestedResponse } from "@/types/api";

interface Props {
  alertId: string;
}

const KNOWN_KINDS = new Set(["isolate", "kill", "quarantine", "ask_analyst", "monitor"]);

const KIND_STYLE: Record<string, string> = {
  isolate: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  kill: "border-destructive/40 bg-destructive/10 text-destructive",
  quarantine: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  ask_analyst: "border-muted-foreground/30 bg-muted text-muted-foreground",
  monitor: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
};

function SuggestionChip({ suggestion }: { suggestion: AiSuggestedResponse }) {
  const style = KIND_STYLE[suggestion.kind] ?? "border-border bg-muted text-foreground";
  return (
    <span
      title={suggestion.rationale ?? undefined}
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${style}`}
    >
      <span className="font-mono uppercase tracking-wide text-[10px] mr-1.5">
        {suggestion.kind}
      </span>
      {suggestion.label}
    </span>
  );
}

export function AiSummaryWidget({ alertId }: Props) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["alert-summary", alertId],
    queryFn: () => aiApi.getAlertSummary(alertId),
    retry: (failureCount, err) => {
      // 404 means the summariser hasn't produced a row yet. Don't
      // retry tight — let the surrounding UI poll if it cares.
      if (err instanceof ApiError && err.status === 404) return false;
      return failureCount < 2;
    },
  });

  // 404 → pending state. Any other error renders as an inline notice
  // so analysts can spot a configuration miss without leaving the
  // page (e.g. the manager forgot to set VIGIL_ANTHROPIC_API_KEY).
  const isPending = isError && error instanceof ApiError && error.status === 404;
  const otherError =
    isError && !(error instanceof ApiError && error.status === 404)
      ? error instanceof ApiError
        ? error.detail
        : String(error)
      : null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Sparkles className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          AI analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
            Loading…
          </div>
        )}
        {isPending && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
            AI analysis pending
          </div>
        )}
        {otherError && (
          <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {otherError}
          </p>
        )}
        {data && (
          <>
            <p className="whitespace-pre-line text-sm text-foreground">{data.summary}</p>
            {data.suggested_response_json && data.suggested_response_json.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {data.suggested_response_json
                  .filter((s) => KNOWN_KINDS.has(s.kind))
                  .map((s, idx) => (
                    <SuggestionChip key={`${s.kind}-${idx}`} suggestion={s} />
                  ))}
              </div>
            )}
            <div className="pt-1 text-[10px] uppercase tracking-wider text-muted-foreground">
              Model: {data.model_id}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

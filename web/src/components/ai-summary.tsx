"use client";

import { useMutation, useQuery } from "@tanstack/react-query";

import { Button, Card, Notice } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";

/** What changed, the likely cause and next steps, written by Claude from the
 * incident and similar recent ones. Shown only where it's set up. */
export function AISummary({ incidentId }: { incidentId: string }) {
  const status = useQuery({
    queryKey: ["ai-status"],
    queryFn: async () => unwrap(await api.GET("/v1/ai/status")),
    staleTime: 10 * 60_000,
  });
  const run = useMutation({
    mutationFn: async (refresh: boolean) =>
      unwrap(
        await api.POST("/v1/incidents/{incident_id}/ai-summary", {
          params: { path: { incident_id: incidentId }, query: { refresh } },
        }),
      ),
  });
  if (!status.data?.enabled) return null;
  const s = run.data;
  return (
    <Card title="AI summary">
      {!s ? (
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-ink-3 text-sm">
            What changed, the likely cause and what to check, from this incident and similar recent
            ones.
          </p>
          <Button loading={run.isPending} onClick={() => run.mutate(false)}>
            Summarise
          </Button>
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          <p>
            <b>What changed.</b> {s.what_changed}
          </p>
          <p>
            <b>Likely cause.</b> {s.likely_cause}
          </p>
          {s.next_steps.length > 0 && (
            <div>
              <b>Next steps</b>
              <ol className="mt-1 list-decimal space-y-1 pl-5">
                {s.next_steps.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ol>
            </div>
          )}
          <div className="text-ink-3 flex flex-wrap items-center gap-3 text-xs">
            <span>
              Written by AI at {dateTime(s.generated_at)}. Check it against the facts before acting.
            </span>
            <Button loading={run.isPending} onClick={() => run.mutate(true)}>
              Again
            </Button>
          </div>
        </div>
      )}
      {run.error && (
        <div className="mt-3">
          <Notice tone="bad">{errorText(run.error)}</Notice>
        </div>
      )}
    </Card>
  );
}

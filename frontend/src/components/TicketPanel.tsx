/**
 * TicketPanel — file a finding into TOPdesk, or show the incident already tracking it.
 *
 * Distinguishes "opened a new incident" from "this was already tracked": adopting
 * an existing ticket is the expected outcome on a re-scan, and reporting it as a
 * new one would have people looking for a ticket that was never created.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Ticket } from "lucide-react";
import { useState } from "react";

import { type TicketLink, integrationsApi } from "@/api/integrations";
import { safeUrl } from "@/utils/safeUrl";

export default function TicketPanel({ findingId }: { findingId: string }) {
  const qc = useQueryClient();
  const [note, setNote] = useState<string | null>(null);

  const { data: config } = useQuery({
    queryKey: ["topdesk-status"],
    queryFn: integrationsApi.topdeskStatus,
    // Non-admins get 403 here; treat that as "not available to you" rather than
    // an error banner on an unrelated panel.
    retry: false,
  });

  const { data: ticket } = useQuery<TicketLink | null>({
    queryKey: ["topdesk-ticket", findingId],
    queryFn: () => integrationsApi.getTicket(findingId).catch(() => null),
    retry: false,
  });

  const mut = useMutation({
    mutationFn: () => integrationsApi.createTicket(findingId),
    onSuccess: (link) => {
      setNote(
        link.created
          ? null
          : "This finding was already tracked — linked to the existing incident.",
      );
      qc.setQueryData(["topdesk-ticket", findingId], link);
    },
    onError: (e) => setNote(e instanceof Error ? e.message : String(e)),
  });

  // Nothing useful to show if the integration was never set up.
  if (config && !config.configured && !ticket) return null;

  if (ticket) {
    const href = safeUrl(ticket.url);
    return (
      <div style={{ fontSize: 11.5, display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
        <Ticket size={12} style={{ color: "var(--accent)" }} />
        {href ? (
          <a href={href} target="_blank" rel="noopener noreferrer"
             style={{ color: "var(--accent)", display: "inline-flex", alignItems: "center", gap: 4 }}>
            {ticket.external_key ?? ticket.external_id}
            <ExternalLink size={10} />
          </a>
        ) : (
          <span>{ticket.external_key ?? ticket.external_id}</span>
        )}
        {ticket.external_status && (
          <span style={{ color: "var(--text-3)" }}>· {ticket.external_status}</span>
        )}
        {note && <span style={{ color: "var(--text-3)" }}>{note}</span>}
      </div>
    );
  }

  return (
    <div>
      <button className="btn btn-ghost btn-sm" disabled={mut.isPending}
              onClick={() => mut.mutate()}
              title="Create a TOPdesk incident for this finding">
        <Ticket size={11} /> {mut.isPending ? "Filing…" : "Create TOPdesk ticket"}
      </button>
      {note && (
        <div style={{ fontSize: 11, color: "var(--sev-high)", marginTop: 5 }}>{note}</div>
      )}
    </div>
  );
}

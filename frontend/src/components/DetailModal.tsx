import { doLabel, opcodeLabel, protoLabel, queryTypeShort, rcodeLabel } from "../labels";
import type { Analysis } from "../types";

const FEATURE_FIELDS: (keyof Analysis)[] = [
  "dns_domain_name_length",
  "dns_subdomain_name_length",
  "numerical_percentage",
  "character_entropy",
  "max_continuous_numeric_len",
  "max_continuous_alphabet_len",
  "max_continuous_consonants_len",
  "max_continuous_same_alphabet_len",
  "vowels_consonant_ratio",
  "conv_freq_vowels_consonants",
];

export function DetailModal({ record, onClose }: { record: Analysis; onClose: () => void }) {
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Analysis #{record.id}</h2>
        <div className="kv">
          <div className="k">When</div><div>{record.created_at}</div>
          <div className="k">Client</div><div>{record.client_ip}:{record.client_port}</div>
          <div className="k">Protocol</div><div>{protoLabel(record.proto)}</div>
          <div className="k">Query</div>
          <div>{queryTypeShort(record.query_type)} — {record.query_name}</div>
          <div className="k">Parent domain / depth</div>
          <div>{record.parent_domain} / {record.subdomain_depth}</div>
          <div className="k">Response</div>
          <div>{rcodeLabel(record.rcode)} ({record.rcode}) · {record.response_size} B · {record.duration_ms.toFixed(2)} ms</div>
          <div className="k">DNS metadata</div>
          <div>
            id {record.dns_id || "?"} · {opcodeLabel(record.opcode)} · EDNS buffer {record.bufsize || "?"} · {doLabel(record.do_flag)}
          </div>
          <div className="k">Score</div>
          <div>
            <strong>{record.score.toFixed(4)}</strong> (threshold {record.threshold.toFixed(2)}){" "}
            <span className={`pill ${record.alerted ? "alert" : "safe"}`}>
              {record.alerted ? "Alert" : "Safe"}
            </span>
          </div>
        </div>

        <h3 style={{ marginTop: 18, fontSize: 14 }}>ML features</h3>
        <div className="kv">
          {FEATURE_FIELDS.map((f) => (
            <div key={f} style={{ display: "contents" }}>
              <div className="k">{f}</div>
              <div>{Number(record[f]).toFixed(4)}</div>
            </div>
          ))}
        </div>

        <h3 style={{ marginTop: 18, fontSize: 14 }}>Raw CoreDNS log</h3>
        <pre>{JSON.stringify(record.raw_log, null, 2)}</pre>

        <div style={{ marginTop: 16, textAlign: "right" }}>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

const QUERY_TYPE_LABELS: Record<string, string> = {
  A: "IPv4 address",
  AAAA: "IPv6 address",
  TXT: "Text record",
  NULL: "Null (tunneling)",
  MX: "Mail server",
  CNAME: "Alias",
  NS: "Name server",
  SOA: "Authority",
  PTR: "Reverse lookup",
  SRV: "Service",
  HTTPS: "HTTPS hint",
  SVCB: "Service binding",
  CAA: "Certificate authority",
  ANY: "All records",
  DS: "Delegation signer",
  DNSKEY: "DNS public key",
  RRSIG: "DNSSEC signature",
};

const RCODE_LABELS: Record<string, string> = {
  NOERROR: "Success",
  NXDOMAIN: "Not found",
  SERVFAIL: "Server error",
  REFUSED: "Refused",
  FORMERR: "Format error",
  NOTIMP: "Not implemented",
  YXDOMAIN: "Name exists",
  NOTAUTH: "Not authoritative",
};

const OPCODE_LABELS: Record<string, string> = {
  "0": "Query",
  "1": "Inverse query",
  "2": "Status",
  "4": "Notify",
  "5": "Update",
};

const DO_LABELS: Record<string, string> = {
  "true": "DNSSEC OK",
  "false": "no DNSSEC",
};

export function queryTypeLabel(t: string): string {
  return QUERY_TYPE_LABELS[t.toUpperCase()] ?? t;
}

export function queryTypeShort(t: string): string {
  const long = QUERY_TYPE_LABELS[t.toUpperCase()];
  return long ? `${t} — ${long}` : t;
}

export function rcodeLabel(r: string): string {
  return RCODE_LABELS[r.toUpperCase()] ?? r;
}

export function protoLabel(p: string): string {
  return p ? p.toUpperCase() : "";
}

export function opcodeLabel(c: string): string {
  return OPCODE_LABELS[c] ?? c;
}

export function doLabel(d: string): string {
  return DO_LABELS[d.toLowerCase()] ?? d;
}

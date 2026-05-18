import type {
  Analysis,
  AnalysesFilters,
  AnalysesResponse,
  ClientDist,
  HourlyBucket,
  ParentDist,
  QueryTypeCount,
  Stats,
  TopSuspicious,
} from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

export const api = {
  stats: () => get<Stats>("/stats"),
  topSuspicious: (limit = 10) => get<TopSuspicious[]>(`/stats/top?limit=${limit}`),
  hourly: (hours = 24) => get<HourlyBucket[]>(`/stats/hourly?hours=${hours}`),
  clients: (limit = 10) => get<ClientDist[]>(`/stats/clients?limit=${limit}`),
  parents: (limit = 10) => get<ParentDist[]>(`/stats/parents?limit=${limit}`),
  types: () => get<QueryTypeCount[]>("/stats/types"),
  analyses: (f: AnalysesFilters = {}) => {
    const p = new URLSearchParams();
    if (f.limit !== undefined) p.set("limit", String(f.limit));
    if (f.offset !== undefined) p.set("offset", String(f.offset));
    if (f.query_type) p.set("query_type", f.query_type);
    if (f.alerted !== undefined) p.set("alerted", String(f.alerted));
    if (f.q) p.set("q", f.q);
    return get<AnalysesResponse>(`/analyses?${p.toString()}`);
  },
  analysisDetail: (id: number) => get<Analysis>(`/analyses/${id}`),
};

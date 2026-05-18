export interface Analysis {
  id: number;
  created_at: string;
  client_ip: string;
  client_port: number;
  proto: string;
  query_type: string;
  query_name: string;
  query_class: string;
  parent_domain: string;
  subdomain_depth: number;
  rcode: string;
  response_size: number;
  duration_ms: number;
  dns_id: string;
  opcode: string;
  bufsize: string;
  do_flag: string;
  raw_log: Record<string, unknown>;
  score: number;
  threshold: number;
  alerted: boolean;
  dns_domain_name_length: number;
  dns_subdomain_name_length: number;
  numerical_percentage: number;
  character_entropy: number;
  max_continuous_numeric_len: number;
  max_continuous_alphabet_len: number;
  max_continuous_consonants_len: number;
  max_continuous_same_alphabet_len: number;
  vowels_consonant_ratio: number;
  conv_freq_vowels_consonants: number;
}

export interface AnalysesResponse {
  total: number;
  items: Analysis[];
}

export interface Stats {
  total: number;
  alerts: number;
  safe: number;
  average_score: number;
  max_score: number;
  threshold: number;
}

export interface TopSuspicious {
  query_name: string;
  count: number;
  max_score: number;
}

export interface HourlyBucket {
  hour: string;
  total: number;
  alerts: number;
}

export interface ClientDist {
  client_ip: string;
  count: number;
}

export interface ParentDist {
  parent_domain: string;
  count: number;
}

export interface QueryTypeCount {
  query_type: string;
  count: number;
}

export interface AnalysesFilters {
  limit?: number;
  offset?: number;
  query_type?: string;
  alerted?: boolean;
  q?: string;
}

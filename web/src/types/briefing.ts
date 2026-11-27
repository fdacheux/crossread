export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export type Category =
  | 'Web/AppSec'
  | 'CVEs'
  | 'Regulations'
  | 'Forensics'
  | 'Threats'
  | 'Trends/Research';

export const ALL_CATEGORIES: Category[] = [
  'Web/AppSec',
  'CVEs',
  'Regulations',
  'Forensics',
  'Threats',
  'Trends/Research',
];

export const ALL_SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

export interface ArticleFactSheet {
  cve_ids: string[];
  affected_versions: string[];
  affected_tech: string[];
  key_claims: string[];
  remediations: string[];
  source_url: string;
  source_name: string;
}

export interface ArticleSource {
  id: string;
  url: string;
  title: string;
  source_name: string;
  language: 'en' | 'fr';
  published_at: string;
  fact_sheet: ArticleFactSheet;
}

export interface ClusterBriefing {
  id: string;
  created_at: string;
  updated_at: string;
  source_count: number;
  headline: string;
  tldr: string;
  severity: Severity;
  categories: Category[];
  cve_ids: string[];
  affected_tech: string[];
  entities: string[];
  technical_details: string;
  remediations: string;
  source_diffs: string;
  articles: ArticleSource[];
}

import { Search, X } from 'lucide-react';
import {
  ALL_CATEGORIES,
  ALL_SEVERITIES,
  type Category,
  type Severity,
} from '../types/briefing';

export type SortMode = 'recent' | 'severity' | 'sources';

interface FilterBarProps {
  selectedCategory: Category | 'All';
  onSelectCategory: (category: Category | 'All') => void;
  selectedSeverity: Severity | 'All';
  onSelectSeverity: (severity: Severity | 'All') => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  sortMode: SortMode;
  onSortChange: (mode: SortMode) => void;
  totalCount: number;
  filteredCount: number;
  onResetFilters: () => void;
}

export function FilterBar({
  selectedCategory,
  onSelectCategory,
  selectedSeverity,
  onSelectSeverity,
  searchQuery,
  onSearchChange,
  sortMode,
  onSortChange,
  totalCount,
  filteredCount,
  onResetFilters,
}: FilterBarProps) {
  const hasActiveFilters =
    selectedCategory !== 'All' ||
    selectedSeverity !== 'All' ||
    searchQuery.trim().length > 0;

  return (
    <section
      aria-label="Filter briefings"
      className="bg-white border border-slate-200 rounded-lg p-5 space-y-4"
    >
      <div className="flex flex-col lg:flex-row lg:items-center gap-4 justify-between">
        {/* Search input */}
        <div className="relative flex-1 max-w-xl">
          <Search
            className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
            aria-hidden="true"
          />
          {/* Hide browser-native WebKit clear cross so only our custom clear button below appears */}
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search by CVE, vendor, regulation, or keyword..."
            aria-label="Search briefings"
            className="w-full pl-10 pr-9 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-md text-slate-900 placeholder:text-slate-400 focus:outline-none focus:bg-white focus:border-slate-900 transition-colors [&::-webkit-search-cancel-button]:appearance-none [&::-webkit-search-decoration]:appearance-none"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => onSearchChange('')}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-700"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity segmented control + Sort */}
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2.5">
            <span className="text-xs font-medium text-slate-500 whitespace-nowrap shrink-0">
              Severity
            </span>
            <div
              role="group"
              aria-label="Filter by severity"
              className="inline-flex items-center p-1 bg-slate-100 rounded-md gap-0.5 shrink-0"
            >
              {(['All', ...ALL_SEVERITIES] as const).map((sev) => {
                const active = selectedSeverity === sev;
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => onSelectSeverity(sev)}
                    aria-pressed={active}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      active
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {sev}
                  </button>
                );
              })}
            </div>
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-500 whitespace-nowrap shrink-0">
            <span className="font-medium">Sort</span>
            <select
              value={sortMode}
              onChange={(e) => onSortChange(e.target.value as SortMode)}
              className="bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-xs font-medium text-slate-800 focus:outline-none focus:border-slate-900 cursor-pointer"
            >
              <option value="recent">Most recent</option>
              <option value="severity">Highest severity</option>
              <option value="sources">Most sources</option>
            </select>
          </label>
        </div>
      </div>

      {/* Category filter bar */}
      <div className="pt-3 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div
          role="group"
          aria-label="Filter by category"
          className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0"
        >
          {(['All', ...ALL_CATEGORIES] as const).map((category) => {
            const active = selectedCategory === category;
            return (
              <button
                key={category}
                type="button"
                onClick={() => onSelectCategory(category)}
                aria-pressed={active}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'bg-slate-900 text-white'
                    : 'bg-slate-100 text-slate-700 hover:bg-slate-200 hover:text-slate-900'
                }`}
              >
                {category}
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-3 text-xs text-slate-500 tabular-nums whitespace-nowrap shrink-0">
          <span>
            Showing {filteredCount} of {totalCount} briefings
          </span>
          {hasActiveFilters && (
            <>
              <span aria-hidden="true">·</span>
              <button
                type="button"
                onClick={onResetFilters}
                className="font-medium text-slate-900 underline underline-offset-2 hover:text-slate-700 cursor-pointer"
              >
                Reset
              </button>
            </>
          )}
        </div>
      </div>
    </section>
  );
}

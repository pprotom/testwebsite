import React, { useState } from 'react';
import { Layers, Search, FileText, Globe, Server, PackageCheck, FileCode, CheckCircle2, XCircle, HelpCircle, ShieldAlert } from 'lucide-react';
import { ChecklistItem } from '../types';

interface ModulesExplorerProps {
  items: ChecklistItem[];
  onOpenEvidence: (path: string) => void;
}

type ModuleKey = 'recon' | 'files' | 'weblayer' | 'infra' | 'supply';

interface ModuleDef {
  key: ModuleKey;
  label: string;
  tag: string;
  description: string;
  icon: React.ReactNode;
}

const MODULES: ModuleDef[] = [
  {
    key: 'recon',
    label: 'D1: Reconnaissance',
    tag: 'Recon & Surface',
    description: 'DNS scope validation, Top 1000 ports, Subdomain mapping, Tech stack fingerprinting, and WAF inspection.',
    icon: <Search className="w-4 h-4" />,
  },
  {
    key: 'files',
    label: 'D2: Sensitive Files',
    tag: 'Files & Dirs',
    description: 'Verification of /.git/HEAD, /.env, backup dumps (*.sql, *.zip), and directory indexing exposures.',
    icon: <FileText className="w-4 h-4" />,
  },
  {
    key: 'weblayer',
    label: 'D3: Web Layer',
    tag: 'Web Application',
    description: '5 Security Headers (CSP, HSTS, etc.), HTTPS enforcement, TLS 1.0/1.1 deprecation, Cookie flags, and SQLi pilots.',
    icon: <Globe className="w-4 h-4" />,
  },
  {
    key: 'infra',
    label: 'D4: Infrastructure',
    tag: 'Host & Perimeter',
    description: 'Direct IP Database ports (3306, 5432, 6379, 27017), TruffleHog git secrets scan, and robots/sitemap exposures.',
    icon: <Server className="w-4 h-4" />,
  },
  {
    key: 'supply',
    label: 'D5: Supply Chain',
    tag: 'Dependencies & CVE',
    description: 'Software component versions, CVSS >= 7.0 and >= 9.0 CVE mappings, and CMS vulnerability audits.',
    icon: <PackageCheck className="w-4 h-4" />,
  },
];

export const ModulesExplorer: React.FC<ModulesExplorerProps> = ({ items, onOpenEvidence }) => {
  const [activeModule, setActiveModule] = useState<ModuleKey>('recon');

  const filteredItems = items.filter((item) => item.module === activeModule);
  const activeDef = MODULES.find((m) => m.key === activeModule)!;

  const getModuleStats = (key: ModuleKey) => {
    const mItems = items.filter((i) => i.module === key);
    const pass = mItems.filter((i) => i.status === 'PASS').length;
    const fail = mItems.filter((i) => i.status === 'FAIL').length;
    const total = mItems.length;
    return { pass, fail, total };
  };

  return (
    <section className="mb-8 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 shadow-xs">
      <div className="flex items-center justify-between gap-4 mb-4 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-indigo-600" />
            5 Defensive Modules Audit Breakdown
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Detailed inspection of all individual empirical security tests and checklists.
          </p>
        </div>
      </div>

      {/* Module Navigation Tabs */}
      <div className="flex flex-wrap gap-2 mb-6 border-b border-slate-100 pb-3">
        {MODULES.map((mod) => {
          const stats = getModuleStats(mod.key);
          const isActive = activeModule === mod.key;
          return (
            <button
              key={mod.key}
              type="button"
              onClick={() => setActiveModule(mod.key)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold transition-all ${
                isActive
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'bg-slate-50 text-slate-700 hover:bg-slate-100 hover:text-slate-900 border border-slate-200/60'
              }`}
            >
              {mod.icon}
              <span>{mod.label}</span>
              {stats.fail > 0 ? (
                <span className="px-1.5 py-0.2 rounded-full text-2xs font-mono font-bold bg-rose-500 text-white">
                  {stats.fail} FAIL
                </span>
              ) : (
                <span
                  className={`px-1.5 py-0.2 rounded-full text-2xs font-mono font-bold ${
                    isActive ? 'bg-slate-700 text-emerald-400' : 'bg-slate-200 text-slate-700'
                  }`}
                >
                  {stats.pass}/{stats.total}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Active Module Header */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 mb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <span className="text-2xs font-bold uppercase tracking-wider text-indigo-600">
            {activeDef.tag}
          </span>
          <h4 className="text-sm font-bold text-slate-900 mt-0.5">{activeDef.label}</h4>
          <p className="text-xs text-slate-600 mt-0.5">{activeDef.description}</p>
        </div>
        <div className="text-xs font-medium text-slate-500 shrink-0">
          Showing {filteredItems.length} empirical checks
        </div>
      </div>

      {/* Checklist Items Table / Cards */}
      <div className="space-y-3">
        {filteredItems.length === 0 ? (
          <div className="text-center py-8 text-xs text-slate-400">
            No checklist items recorded for this module in this run.
          </div>
        ) : (
          filteredItems.map((item) => {
            const isPass = item.status === 'PASS';
            const isFail = item.status === 'FAIL';

            return (
              <div
                key={item.id}
                className={`rounded-xl border p-4 transition-all ${
                  isFail
                    ? 'border-rose-200 bg-rose-50/40'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                  <div className="space-y-1.5 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        Check {item.id}
                      </span>

                      {/* Status Badge */}
                      {isPass && (
                        <span className="inline-flex items-center gap-1 text-2xs font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3" />
                          PASS
                        </span>
                      )}
                      {isFail && (
                        <span className="inline-flex items-center gap-1 text-2xs font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-200">
                          <XCircle className="w-3 h-3" />
                          FAIL
                        </span>
                      )}
                      {!isPass && !isFail && (
                        <span className="inline-flex items-center gap-1 text-2xs font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200">
                          <HelpCircle className="w-3 h-3" />
                          UNKNOWN
                        </span>
                      )}

                      {/* Score Badge */}
                      <span className="text-2xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                        Score: {item.score}/2
                      </span>

                      {/* P0 Gate association */}
                      {item.p0_gate_id && (
                        <span className="inline-flex items-center gap-1 text-2xs font-bold px-2 py-0.5 rounded bg-rose-600 text-white shadow-2xs">
                          <ShieldAlert className="w-3 h-3" />
                          P0 Gate #{item.p0_gate_id}
                        </span>
                      )}
                    </div>

                    <h5 className="text-sm font-bold text-slate-900 leading-snug">
                      {item.check}
                    </h5>

                    <p className="text-xs text-slate-600 font-medium">
                      {item.note}
                    </p>
                  </div>

                  {/* Evidence File Button */}
                  {item.evidence && item.evidence.length > 0 && (
                    <div className="shrink-0 flex flex-col items-end gap-1">
                      {item.evidence.map((evPath) => (
                        <button
                          key={evPath}
                          type="button"
                          onClick={() => onOpenEvidence(evPath)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-indigo-50 hover:border-indigo-200 text-xs font-semibold text-slate-700 hover:text-indigo-700 transition-colors"
                          title="Open verified raw evidence file with SHA-256 hash"
                        >
                          <FileCode className="w-3.5 h-3.5 text-indigo-600" />
                          <span className="truncate max-w-[160px] font-mono text-2xs">
                            {evPath.split('/').pop()}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
};

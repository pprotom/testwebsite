import React, { useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, HelpCircle, ChevronDown, ChevronUp, ExternalLink, CheckCircle2, AlertTriangle, Layers, Info } from 'lucide-react';
import { OWASPRiskCategory } from '../types';

interface OWASPMatrixProps {
  categories: OWASPRiskCategory[];
  onOpenEvidence?: (path: string) => void;
}

export const OWASPMatrix: React.FC<OWASPMatrixProps> = ({ categories, onOpenEvidence }) => {
  const [expandedCode, setExpandedCode] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'FAIL' | 'PASS'>('all');

  const passCount = categories.filter((c) => c.status === 'PASS').length;
  const failCount = categories.filter((c) => c.status === 'FAIL').length;
  const unknownCount = categories.filter((c) => c.status === 'UNKNOWN').length;
  const complianceRate = categories.length > 0 ? Math.round((passCount / categories.length) * 100) : 0;

  const filteredCategories = categories.filter((c) => {
    if (filter === 'all') return true;
    return c.status === filter;
  });

  const toggleExpand = (code: string) => {
    setExpandedCode((prev) => (prev === code ? null : code));
  };

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xs mb-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="p-1.5 rounded-lg bg-indigo-100 text-indigo-700">
              <Layers className="w-5 h-5" />
            </div>
            <h2 className="text-lg font-bold text-slate-900 tracking-tight flex items-center gap-2">
              OWASP Top 10 Compliance Matrix (2021)
            </h2>
            <span className="text-2xs font-semibold px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200">
              Global Standard
            </span>
          </div>
          <p className="text-xs text-slate-500 font-medium">
            การประเมินความสอดคล้องตามมาตรฐาน 10 ความเสี่ยงความปลอดภัยเว็บยอดนิยมของโลก &bull; ตรวจจับด้วยหลักฐานเชิงประจักษ์
          </p>
        </div>

        {/* Quick Stats & Filter Chips */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-50 border border-slate-200 text-xs">
            <span className="text-slate-500 font-medium">ความสอดคล้อง:</span>
            <span className={`font-mono font-bold ${complianceRate >= 80 ? 'text-emerald-700' : 'text-amber-700'}`}>
              {complianceRate}%
            </span>
            <span className="text-slate-400">({passCount}/10 ผ่าน)</span>
          </div>

          <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-100/70 text-xs font-semibold">
            <button
              type="button"
              onClick={() => setFilter('all')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                filter === 'all' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              ทั้งหมด (10)
            </button>
            <button
              type="button"
              onClick={() => setFilter('FAIL')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1 ${
                filter === 'FAIL' ? 'bg-rose-600 text-white shadow-2xs' : 'text-rose-700 hover:bg-rose-50'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              พบความเสี่ยง ({failCount})
            </button>
            <button
              type="button"
              onClick={() => setFilter('PASS')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1 ${
                filter === 'PASS' ? 'bg-emerald-600 text-white shadow-2xs' : 'text-emerald-700 hover:bg-emerald-50'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              ผ่านเกณฑ์ ({passCount})
            </button>
          </div>
        </div>
      </div>

      {/* Grid of 10 OWASP Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 mt-5">
        {filteredCategories.map((cat) => {
          const isExpanded = expandedCode === cat.code;
          const isPass = cat.status === 'PASS';
          const isFail = cat.status === 'FAIL';

          return (
            <div
              key={cat.code}
              className={`rounded-xl border transition-all text-xs ${
                isFail
                  ? 'border-rose-200 bg-rose-50/40 hover:border-rose-300'
                  : isPass
                  ? 'border-slate-200 bg-slate-50/50 hover:border-slate-300'
                  : 'border-amber-200 bg-amber-50/40'
              }`}
            >
              {/* Header Bar */}
              <div
                onClick={() => toggleExpand(cat.code)}
                className="p-3.5 flex items-start justify-between gap-2.5 cursor-pointer select-none"
              >
                <div className="flex items-start gap-2.5 min-w-0">
                  <div
                    className={`p-1.5 rounded-lg shrink-0 mt-0.5 ${
                      isFail
                        ? 'bg-rose-100 text-rose-700'
                        : isPass
                        ? 'bg-emerald-100 text-emerald-700'
                        : 'bg-amber-100 text-amber-700'
                    }`}
                  >
                    {isFail ? (
                      <ShieldAlert className="w-4 h-4" />
                    ) : isPass ? (
                      <ShieldCheck className="w-4 h-4" />
                    ) : (
                      <HelpCircle className="w-4 h-4" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-0.5">
                      <span className="font-mono font-bold text-2xs px-1.5 py-0.5 rounded bg-slate-200/80 text-slate-800">
                        {cat.code}
                      </span>
                      <h4 className="font-bold text-slate-900 truncate">{cat.title}</h4>
                    </div>
                    <p className="text-2xs text-slate-600 font-medium truncate">{cat.thaiTitle}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span
                    className={`font-bold font-mono text-2xs px-2 py-0.5 rounded-full border ${
                      isFail
                        ? 'bg-rose-100 text-rose-800 border-rose-200'
                        : isPass
                        ? 'bg-emerald-100 text-emerald-800 border-emerald-200'
                        : 'bg-amber-100 text-amber-800 border-amber-200'
                    }`}
                  >
                    {cat.status}
                  </span>
                  <button
                    type="button"
                    className="text-slate-400 hover:text-slate-600 p-0.5"
                    aria-label="Toggle details"
                  >
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Description Preview (When collapsed) */}
              {!isExpanded && (
                <div className="px-3.5 pb-3 text-2xs text-slate-500 line-clamp-2">
                  {cat.description}
                </div>
              )}

              {/* Expanded Detail Panel */}
              {isExpanded && (
                <div className="px-3.5 pb-3.5 pt-1 border-t border-current/10 space-y-2.5 text-2xs leading-relaxed animate-in fade-in duration-150">
                  <div>
                    <span className="font-bold text-slate-800 block mb-0.5">คำอธิบายและขอบเขตความเสี่ยง:</span>
                    <p className="text-slate-600">{cat.description}</p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-white/80 border border-current/10">
                    <span className="font-bold text-rose-900 block mb-0.5 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-rose-600" />
                      ผลกระทบต่อหน่วยงาน (Impact):
                    </span>
                    <p className="text-slate-700">{cat.impact}</p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-emerald-50/80 border border-emerald-200/60">
                    <span className="font-bold text-emerald-950 block mb-0.5 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                      แนวทางป้องกันและแก้ไขตาม OWASP (Remediation):
                    </span>
                    <p className="text-emerald-900">{cat.remediationSummary}</p>
                  </div>

                  {/* Mapped Checklist Items & Gates */}
                  <div className="pt-1 flex flex-wrap items-center gap-1.5 text-2xs text-slate-500">
                    <span className="font-medium">ด่านตรวจที่เกี่ยวข้อง:</span>
                    {cat.relatedChecks.map((chk) => (
                      <span key={chk} className="font-mono bg-white px-1.5 py-0.5 rounded border border-slate-200 text-slate-700">
                        Check {chk}
                      </span>
                    ))}
                    {cat.p0GateIds && cat.p0GateIds.map((gid) => (
                      <span key={gid} className="font-mono bg-rose-50 text-rose-700 px-1.5 py-0.5 rounded border border-rose-200">
                        Gate P0-{gid}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

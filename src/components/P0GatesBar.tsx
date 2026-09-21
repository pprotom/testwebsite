import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, HelpCircle, ChevronRight, AlertTriangle, FileCode } from 'lucide-react';
import { P0Gate } from '../types';

interface P0GatesBarProps {
  gates: P0Gate[];
  onOpenEvidence: (path: string) => void;
}

export const P0GatesBar: React.FC<P0GatesBarProps> = ({ gates, onOpenEvidence }) => {
  const [selectedGate, setSelectedGate] = useState<P0Gate | null>(null);

  const passedCount = gates.filter((g) => g.passed).length;
  const failedCount = gates.length - passedCount;

  return (
    <section className="mb-8 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 pb-4 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-600" />
              10 Hardcoded P0 Security Gates
            </h3>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">
              {passedCount}/10 Passed
            </span>
            {failedCount > 0 && (
              <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 animate-pulse">
                {failedCount} Critical Failure{failedCount > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Zero-Tolerance Defensive Gates. Any single failure triggers an immediate and irreversible <strong>NOT PASS</strong> verdict.
          </p>
        </div>

        <div className="text-xs text-slate-400 font-mono">
          Criteria Source: auditor/scoring.py (P0_GATES)
        </div>
      </div>

      {/* 10 Gates Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {gates.map((gate) => {
          const isFailed = !gate.passed;
          return (
            <div
              key={gate.id}
              onClick={() => setSelectedGate(gate)}
              className={`cursor-pointer rounded-xl border p-3.5 transition-all text-left flex flex-col justify-between group hover:shadow-sm ${
                isFailed
                  ? 'border-rose-200 bg-rose-50/50 hover:bg-rose-50 hover:border-rose-300'
                  : 'border-slate-200 bg-slate-50/40 hover:bg-white hover:border-emerald-200'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span
                    className={`text-xs font-mono font-black px-2 py-0.5 rounded-md ${
                      isFailed
                        ? 'bg-rose-600 text-white shadow-2xs'
                        : 'bg-slate-200 text-slate-800'
                    }`}
                  >
                    Gate {gate.id}
                  </span>
                  <div className="shrink-0">
                    {isFailed ? (
                      <span className="inline-flex items-center gap-1 text-2xs font-bold uppercase px-1.5 py-0.5 rounded bg-rose-100 text-rose-700 border border-rose-200">
                        <AlertTriangle className="w-3 h-3" />
                        FAIL
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-2xs font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700 border border-emerald-200">
                        <ShieldCheck className="w-3 h-3" />
                        PASS
                      </span>
                    )}
                  </div>
                </div>

                <h4 className="text-xs font-bold text-slate-900 leading-snug line-clamp-2">
                  {gate.name}
                </h4>
                <p className="text-2xs text-slate-500 mt-1 line-clamp-1 italic">
                  {gate.thaiName}
                </p>
              </div>

              <div className="mt-3 pt-2.5 border-t border-slate-200/60 flex items-center justify-between text-2xs">
                {isFailed ? (
                  <span className="text-rose-700 font-semibold truncate pr-1">
                    {gate.failedItem || 'Critical breach detected'}
                  </span>
                ) : (
                  <span className="text-emerald-700 font-medium">Clean & Verified</span>
                )}
                <ChevronRight className="w-3.5 h-3.5 text-slate-400 group-hover:translate-x-0.5 transition-transform shrink-0" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Gate Detail Popover / Expanded Modal if selected */}
      {selectedGate && (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4 animate-in fade-in duration-200">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-900 text-white">
                  P0 Gate {selectedGate.id}
                </span>
                <h4 className="text-sm font-bold text-slate-900">
                  {selectedGate.name}
                </h4>
                <span className="text-xs text-slate-500">({selectedGate.thaiName})</span>
              </div>
              <p className="text-xs text-slate-600 mt-1.5 max-w-3xl">
                {selectedGate.description}
              </p>
              {selectedGate.failedItem && (
                <div className="mt-2 text-xs font-semibold text-rose-700 bg-rose-100/80 px-2.5 py-1.5 rounded-lg border border-rose-200 inline-block">
                  🚨 Detection Reason: {selectedGate.failedItem}
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {selectedGate.evidencePath && (
                <button
                  type="button"
                  onClick={() => onOpenEvidence(selectedGate.evidencePath!)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors"
                >
                  <FileCode className="w-3.5 h-3.5 text-indigo-600" />
                  View Raw Evidence
                </button>
              )}
              <button
                type="button"
                onClick={() => setSelectedGate(null)}
                className="text-xs font-semibold text-slate-500 hover:text-slate-800 px-2.5 py-1.5 rounded-lg hover:bg-slate-200 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

import React from 'react';
import { X, RefreshCw, TrendingUp, TrendingDown, Minus, CheckCircle, AlertCircle, ArrowRight } from 'lucide-react';
import { DeltaComparison } from '../types';

interface DeltaReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  delta: DeltaComparison;
}

export const DeltaReportModal: React.FC<DeltaReportModalProps> = ({ isOpen, onClose, delta }) => {
  if (!isOpen) return null;

  const isImproved = delta.status === 'IMPROVED';
  const isRegressed = delta.status === 'REGRESSED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="w-full max-w-2xl rounded-2xl bg-white shadow-2xl border border-slate-200 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-100 text-indigo-700">
              <RefreshCw className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Comparative Delta Security Report
              </h3>
              <p className="text-xs text-slate-500">
                Baseline: {delta.baseline_date} &rarr; Current: {delta.current_date}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Delta Status Banner */}
        <div
          className={`p-6 border-b flex items-center justify-between gap-4 ${
            isImproved
              ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
              : isRegressed
              ? 'bg-rose-50 border-rose-200 text-rose-950'
              : 'bg-slate-50 border-slate-200 text-slate-900'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`p-3 rounded-xl text-white ${
                isImproved ? 'bg-emerald-600' : isRegressed ? 'bg-rose-600' : 'bg-slate-600'
              }`}
            >
              {isImproved && <TrendingUp className="w-6 h-6" />}
              {isRegressed && <TrendingDown className="w-6 h-6" />}
              {!isImproved && !isRegressed && <Minus className="w-6 h-6" />}
            </div>
            <div>
              <span className="text-2xs font-bold uppercase tracking-wider block opacity-75">
                Audit Trajectory
              </span>
              <h4 className="text-xl font-black">{delta.status}</h4>
              <p className="text-xs mt-0.5 opacity-90">
                {isImproved
                  ? 'Security posture significantly strengthened since baseline.'
                  : isRegressed
                  ? 'New critical security risks introduced compared to previous baseline.'
                  : 'No significant changes in defensive gates or findings.'}
              </p>
            </div>
          </div>

          <div className="text-right shrink-0">
            <span className="text-2xs font-semibold text-slate-500 block">Coverage Shift</span>
            <span
              className={`text-2xl font-black font-mono ${
                delta.coverage_diff > 0
                  ? 'text-emerald-700'
                  : delta.coverage_diff < 0
                  ? 'text-rose-700'
                  : 'text-slate-700'
              }`}
            >
              {delta.coverage_diff > 0 ? `+${delta.coverage_diff.toFixed(1)}%` : `${delta.coverage_diff.toFixed(1)}%`}
            </span>
          </div>
        </div>

        {/* Changes Breakdown */}
        <div className="flex-1 p-6 overflow-y-auto space-y-4 text-xs">
          {/* Fixed Issues */}
          <div>
            <h5 className="text-xs font-bold text-emerald-800 uppercase tracking-wider flex items-center gap-1.5 mb-2">
              <CheckCircle className="w-4 h-4 text-emerald-600" />
              Resolved & Fixed Vulnerabilities ({delta.fixed_issues.length})
            </h5>
            {delta.fixed_issues.length === 0 ? (
              <p className="text-slate-400 italic bg-slate-50 p-3 rounded-lg">
                No issues resolved since baseline.
              </p>
            ) : (
              <ul className="space-y-1.5">
                {delta.fixed_issues.map((fix, idx) => (
                  <li
                    key={idx}
                    className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-100 text-emerald-900 font-medium flex items-center gap-2"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                    {fix}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* New Failures */}
          <div>
            <h5 className="text-xs font-bold text-rose-800 uppercase tracking-wider flex items-center gap-1.5 mb-2">
              <AlertCircle className="w-4 h-4 text-rose-600" />
              New Failures & Regressions ({delta.new_failures.length})
            </h5>
            {delta.new_failures.length === 0 ? (
              <p className="text-slate-400 italic bg-slate-50 p-3 rounded-lg">
                Zero new regressions detected.
              </p>
            ) : (
              <ul className="space-y-1.5">
                {delta.new_failures.map((fail, idx) => (
                  <li
                    key={idx}
                    className="p-2.5 rounded-lg bg-rose-50 border border-rose-100 text-rose-900 font-medium flex items-center gap-2"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0" />
                    {fail}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 text-white font-semibold hover:bg-slate-800 transition-colors text-xs"
          >
            Close Delta View
          </button>
        </div>
      </div>
    </div>
  );
};

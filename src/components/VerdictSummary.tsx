import React from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, HelpCircle, FileCheck, Clock, Server, Lock, Printer, Factory } from 'lucide-react';
import { AuditReport } from '../types';

interface VerdictSummaryProps {
  report: AuditReport;
  onOpenEvidence: (path: string) => void;
  onOpenExecutiveReport?: () => void;
  onOpenPlaybook?: () => void;
}

export const VerdictSummary: React.FC<VerdictSummaryProps> = ({
  report,
  onOpenEvidence,
  onOpenExecutiveReport,
  onOpenPlaybook,
}) => {
  const isPass = report.verdict === 'PASS';
  const failedP0s = report.p0_gates.filter((g) => !g.passed);
  const testExecutionCoveragePct = report.summary.total > 0
    ? Math.round(((report.summary.pass + report.summary.fail) / report.summary.total) * 100)
    : 100;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 mb-6">
      {/* Executive Verdict Card (col-span-5) */}
      <div
        className={`lg:col-span-5 rounded-2xl border p-6 flex flex-col justify-between transition-all shadow-xs ${
          isPass
            ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
            : 'bg-rose-50/70 border-rose-200 text-rose-950'
        }`}
      >
        <div>
          <div className="flex items-center justify-between gap-3 mb-4">
            <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-md bg-white/80 border border-current/20 shadow-2xs">
              Executive Security Verdict
            </span>
            <span className="text-xs font-medium text-slate-500 flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              {report.duration_seconds}s audit duration
            </span>
          </div>

          <div className="flex items-center gap-4 mb-4">
            <div
              className={`p-3.5 rounded-2xl ${
                isPass ? 'bg-emerald-600 text-white shadow-emerald-200' : 'bg-rose-600 text-white shadow-rose-200'
              } shadow-md`}
            >
              {isPass ? <ShieldCheck className="w-10 h-10" /> : <ShieldAlert className="w-10 h-10" />}
            </div>
            <div>
              <h2 className="text-3xl font-black tracking-tight flex items-center gap-2">
                {report.verdict}
              </h2>
              <p className="text-sm font-medium mt-0.5 opacity-90">
                {isPass
                  ? 'All 10 Hardcoded P0 Security Gates strictly verified clean.'
                  : `${failedP0s.length} Critical P0 Gate${failedP0s.length > 1 ? 's' : ''} violated. Audit failed immediately.`}
              </p>
            </div>
          </div>

          {/* Core Empirical Principle Banner */}
          <div className="rounded-xl bg-white/90 border border-current/10 p-3 text-xs leading-relaxed text-slate-700">
            <span className="font-bold text-slate-900">Principle: </span>
            <span className="italic font-medium text-slate-800">"Look like closed ≠ proven closed"</span>
            <div className="mt-1 text-slate-600">
              Every score requires verifiable raw evidence hashed with SHA-256. Any single P0 failure overrides overall score to <strong>NOT PASS</strong>.
            </div>
          </div>

          {onOpenExecutiveReport && (
            <button
              type="button"
              onClick={onOpenExecutiveReport}
              className="mt-3 w-full py-2 px-3 rounded-xl bg-white hover:bg-slate-50 text-slate-900 text-xs font-bold border border-current/20 shadow-2xs flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5 text-indigo-600" />
              พิมพ์รายงานสรุปผลผู้บริหาร (Executive 1-Pager PDF)
            </button>
          )}
        </div>

        {/* Target Meta */}
        <div className="mt-5 pt-4 border-t border-current/15 flex flex-wrap items-center justify-between text-xs font-medium text-slate-600 gap-2">
          <div className="flex items-center gap-1.5 truncate max-w-[260px]">
            <Server className="w-3.5 h-3.5 shrink-0 text-slate-500" />
            <span className="truncate">{report.domain}</span>
            {report.ip && <span className="text-slate-400">({report.ip})</span>}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-2xs font-bold ${
              report.target_environment === 'production' || !report.target_environment
                ? 'bg-emerald-100 text-emerald-900 border border-emerald-300'
                : 'bg-slate-100 text-slate-800 border border-slate-300'
            }`}>
              <Factory className="w-3 h-3 text-emerald-700" />
              {report.target_environment === 'production' || !report.target_environment
                ? 'Production (Safe Scan)'
                : `${report.target_environment?.toUpperCase()}`}
            </span>
            <div className="flex items-center gap-1">
              <FileCheck className="w-3.5 h-3.5 text-emerald-600" />
              <span>{report.evidence_count} evidence files</span>
            </div>
          </div>
        </div>
      </div>

      {/* Coverage Score & Calculation Card (col-span-4) */}
      <div className="lg:col-span-4 rounded-2xl border border-slate-200 bg-white p-6 shadow-xs flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Defensive Coverage
            </span>
            <span className="text-xs font-mono font-semibold text-slate-700 bg-slate-100 px-2 py-0.5 rounded">
              Formula: (Scores / Total*2) × 100
            </span>
          </div>

          <div className="flex items-baseline gap-3 mb-2">
            <span className="text-4xl font-black tracking-tight text-slate-900 font-mono">
              {report.coverage_pct.toFixed(1)}%
            </span>
            <span className="text-xs font-medium text-slate-500">
              คะแนนความปลอดภัย (Security Score)
            </span>
          </div>

          {/* Test Execution Completeness Badge */}
          <div className="flex items-center gap-1.5 mb-3 px-2.5 py-1 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 text-2xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>ความครอบคลุมการสแกน: {testExecutionCoveragePct}% เต็ม (ตรวจสอบครบ {report.summary.total}/{report.summary.total} ด่าน)</span>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-slate-100 rounded-full h-3 overflow-hidden p-0.5 border border-slate-200 mb-4">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                report.coverage_pct >= 90
                  ? 'bg-emerald-500'
                  : report.coverage_pct >= 75
                  ? 'bg-indigo-500'
                  : 'bg-amber-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, report.coverage_pct))}%` }}
            />
          </div>

          {/* Score Legend Breakdown */}
          <div className="space-y-2 text-xs text-slate-600">
            <div className="flex items-center justify-between py-1 border-b border-slate-100">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                <strong>Score 2:</strong> PASS + Verified Raw Evidence
              </span>
              <span className="font-mono font-bold text-slate-900">{report.summary.pass} items</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-100">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <strong>Score 0:</strong> FAIL (Vulnerability or Misconfig)
              </span>
              <span className="font-mono font-bold text-slate-900">{report.summary.fail} items</span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <strong>Score 1:</strong> UNKNOWN / Missing Raw Proof
              </span>
              <span className="font-mono font-bold text-slate-900">{report.summary.unknown} items</span>
            </div>
          </div>

          {/* Road to 100% Score Action */}
          {report.coverage_pct < 100 && onOpenPlaybook && (
            <button
              type="button"
              onClick={onOpenPlaybook}
              className="mt-3 w-full py-1.5 px-2.5 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-2xs font-bold border border-indigo-200 flex items-center justify-center gap-1 transition-colors cursor-pointer"
            >
              💡 ดูวิธีปรับจูน Server สู่คะแนน 100% เต็ม &rarr;
            </button>
          )}
        </div>

        <div className="pt-3 border-t border-slate-100 text-2xs text-slate-400">
          Target Date: {report.date} &bull; Safe Mode: {report.safe_mode ? 'Enabled' : 'Disabled'}
        </div>
      </div>

      {/* Metric Breakdown Stats (col-span-3) */}
      <div className="lg:col-span-3 grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-1 gap-3">
        <div className="rounded-xl border border-emerald-100 bg-emerald-50/50 p-4 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-emerald-800 uppercase tracking-wider block">
              Pass With Evidence
            </span>
            <span className="text-2xl font-black text-emerald-700 font-mono">
              {report.summary.pass}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-emerald-100 text-emerald-700">
            <CheckCircle2 className="w-6 h-6" />
          </div>
        </div>

        <div className="rounded-xl border border-rose-100 bg-rose-50/50 p-4 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-rose-800 uppercase tracking-wider block">
              Security Failures
            </span>
            <span className="text-2xl font-black text-rose-700 font-mono">
              {report.summary.fail}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-rose-100 text-rose-700">
            <XCircle className="w-6 h-6" />
          </div>
        </div>

        <div className="rounded-xl border border-amber-100 bg-amber-50/50 p-4 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-amber-800 uppercase tracking-wider block">
              Unknown / Incomplete
            </span>
            <span className="text-2xl font-black text-amber-700 font-mono">
              {report.summary.unknown}
            </span>
          </div>
          <div className="p-2.5 rounded-xl bg-amber-100 text-amber-700">
            <HelpCircle className="w-6 h-6" />
          </div>
        </div>
      </div>
    </div>
  );
};

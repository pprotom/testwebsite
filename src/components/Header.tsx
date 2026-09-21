import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Download, RefreshCw, Terminal, Printer, BookOpen } from 'lucide-react';
import { AuditVerdict } from '../types';

interface HeaderProps {
  verdict: AuditVerdict;
  safeMode: boolean;
  activeTarget: string;
  isScanning: boolean;
  onOpenDelta: () => void;
  onOpenTerminal: () => void;
  onExportJson: () => void;
  onExportMarkdown: () => void;
  onOpenExecutiveReport: () => void;
  onOpenPlaybook: () => void;
  selectedPreset: string;
  onSelectPreset: (preset: 'vulnerable' | 'hardened') => void;
}

export const Header: React.FC<HeaderProps> = ({
  verdict,
  safeMode,
  activeTarget,
  isScanning,
  onOpenDelta,
  onOpenTerminal,
  onExportJson,
  onExportMarkdown,
  onOpenExecutiveReport,
  onOpenPlaybook,
  selectedPreset,
  onSelectPreset,
}) => {
  return (
    <header className="border-b border-slate-200 bg-white/95 backdrop-blur sticky top-0 z-30 shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        {/* Brand & Subtitle */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-slate-900 text-white shadow-sm flex items-center justify-center">
            <Shield className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-slate-900">
                Website Security Auditor
              </h1>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                v1.0.0
              </span>
              {safeMode ? (
                <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Safe Mode (Non-Destructive)
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Aggressive Mode
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 font-medium">
              ระบบตรวจสอบความปลอดภัยเว็บสำหรับองค์กร &bull; 10 ด่านวิกฤต P0 &bull; ปลอดภัย ไม่ทำให้เว็บล่ม
            </p>
          </div>
        </div>

        {/* Preset switch & Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Executive PDF Report */}
          <button
            id="executive-report-btn"
            type="button"
            onClick={onOpenExecutiveReport}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold shadow-xs transition-colors"
            title="สร้างรายงานสรุป 1 หน้าสำหรับเสนอผู้บริหาร หรือพิมพ์เป็น PDF"
          >
            <Printer className="w-3.5 h-3.5" />
            Executive PDF Report
          </button>

          {/* Self-Audit Playbook */}
          <button
            id="playbook-btn"
            type="button"
            onClick={onOpenPlaybook}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-200 bg-emerald-50 text-xs font-bold text-emerald-800 hover:bg-emerald-100 transition-colors"
            title="คู่มือสำหรับหน่วยงานงบประหยัด และวิธีตั้งเวลาสแกนอัตโนมัติฟรีด้วย Cron"
          >
            <BookOpen className="w-3.5 h-3.5 text-emerald-600" />
            คู่มือหน่วยงาน (Playbook)
          </button>

          {/* Compare Delta */}
          <button
            id="compare-delta-btn"
            type="button"
            onClick={onOpenDelta}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors"
            title="เปรียบเทียบผลลัพธ์รอบก่อนหน้าเพื่อดูว่าช่องโหว่ถูกแก้ไขหรือยัง"
          >
            <RefreshCw className="w-3.5 h-3.5 text-indigo-600" />
            Delta Report
          </button>

          {/* Terminal Logs & CLI */}
          <button
            id="open-terminal-btn"
            type="button"
            onClick={onOpenTerminal}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-semibold text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors"
            title="ดูคำสั่ง Linux CLI และ Log ดิบ"
          >
            <Terminal className="w-3.5 h-3.5 text-slate-600" />
            CLI / Logs
          </button>

          {/* Export Dropdown */}
          <div className="inline-flex rounded-lg border border-slate-200 bg-white shadow-xs overflow-hidden">
            <button
              id="export-md-btn"
              type="button"
              onClick={onExportMarkdown}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 border-r border-slate-200"
              title="Download full Markdown report"
            >
              <Download className="w-3.5 h-3.5 text-slate-500" />
              MD
            </button>
            <button
              id="export-json-btn"
              type="button"
              onClick={onExportJson}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
              title="Download JSON report"
            >
              JSON
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

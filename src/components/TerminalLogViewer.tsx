import React, { useState } from 'react';
import { X, Terminal, Copy, Check, ShieldCheck, Play } from 'lucide-react';
import { AuditReport } from '../types';

interface TerminalLogViewerProps {
  isOpen: boolean;
  onClose: () => void;
  report: AuditReport;
}

export const TerminalLogViewer: React.FC<TerminalLogViewerProps> = ({ isOpen, onClose, report }) => {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyCmd = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const cliSnippet = `python3 website-security-auditor/main.py --config config.yaml${
    report.safe_mode ? '' : ' --allow-risky sqlmap'
  }`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="w-full max-w-3xl rounded-2xl bg-slate-950 text-slate-200 shadow-2xl border border-slate-800 overflow-hidden flex flex-col max-h-[85vh]">
        {/* Terminal Header */}
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-900">
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 mr-2">
              <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
            </div>
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-mono font-bold text-slate-300">
              auditor-terminal &bull; Execution Logs & CLI Mirror
            </span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Linux CLI Command to Reproduce */}
        <div className="p-4 bg-slate-900/80 border-b border-slate-800 text-xs">
          <div className="flex items-center justify-between mb-1.5">
            <span className="font-semibold text-slate-400 uppercase tracking-wider text-2xs">
              Execute Directly via Linux Shell
            </span>
            <button
              type="button"
              onClick={() => copyCmd(cliSnippet)}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-2xs font-semibold text-slate-300"
            >
              {copiedCmd === cliSnippet ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3 text-slate-400" />
                  Copy Command
                </>
              )}
            </button>
          </div>
          <pre className="font-mono text-xs text-emerald-400 bg-slate-950 p-2.5 rounded-lg border border-slate-800 overflow-x-auto">
            <code>{cliSnippet}</code>
          </pre>
        </div>

        {/* Console Log Output */}
        <div className="flex-1 p-5 overflow-y-auto font-mono text-xs space-y-3 leading-relaxed">
          <div className="text-cyan-400 font-bold">
            ╔═══════════════════════════════════════════════════════════════════════╗<br />
            ║                  WEBSITE SECURITY AUDITOR v1.0.0                      ║<br />
            ║     Automated 5-Module Defensive Security Auditing Engine (Linux)    ║<br />
            ║        Strict Empirical Verification &amp; Non-Destructive Scanning       ║<br />
            ╚═══════════════════════════════════════════════════════════════════════╝
          </div>

          <div className="text-slate-400">
            [+] Target: <span className="text-white">{report.target_url}</span> ({report.domain})<br />
            [+] Safe Mode: <span className="text-emerald-400">{report.safe_mode ? 'ENABLED (Concurrence: 3, Timeout: <=60s)' : 'DISABLED'}</span><br />
            [+] Subprocess Engine: python3 subprocess.run with timeout &amp; transient retry<br />
            [+] Evidence Directory: ./evidence/{report.domain}/
          </div>

          <div className="border-t border-slate-800 pt-2 text-slate-300">
            <span className="text-amber-400 font-bold">[*] Commands Executed in this Audit Run:</span>
            <div className="mt-2 space-y-1.5 pl-2 border-l-2 border-slate-800">
              {report.commands_run.map((cmd, i) => (
                <div key={i} className="flex items-start justify-between gap-3 group">
                  <span className="text-slate-300">
                    <span className="text-slate-500 select-none mr-2">{i + 1}.</span>
                    <span className="text-emerald-300">$ {cmd}</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => copyCmd(cmd)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity p-1 text-slate-400 hover:text-white"
                    title="Copy command"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="border-t border-slate-800 pt-2 text-slate-400 text-2xs space-y-1">
            <div className="text-emerald-400 font-bold">
              [✔] All execution outputs captured with verified SHA-256 manifest.json
            </div>
            <div>
              Verdict calculated: <span className={report.verdict === 'PASS' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>{report.verdict}</span> (Coverage: {report.coverage_pct.toFixed(1)}%)
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-2xs text-slate-500">
          <span>Linux Bash &bull; Python 3.10+ &bull; Subprocess Wrapper</span>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

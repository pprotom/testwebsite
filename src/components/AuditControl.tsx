import React, { useState } from 'react';
import { Play, Square, Globe, Shield, ShieldAlert, Sliders, Filter, Sparkles, AlertCircle } from 'lucide-react';
import { AuditConfigInput } from '../types';

interface AuditControlProps {
  config: AuditConfigInput;
  onChangeConfig: (newConfig: AuditConfigInput) => void;
  onRunAudit: () => void;
  isScanning: boolean;
  scanProgress: {
    phase: string;
    step: number;
    total: number;
    message: string;
  };
}

export const AuditControl: React.FC<AuditControlProps> = ({
  config,
  onChangeConfig,
  onRunAudit,
  isScanning,
  scanProgress,
}) => {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [domainInput, setDomainInput] = useState('');

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    let extractedDomain = '';
    try {
      if (val.includes('://')) {
        extractedDomain = new URL(val).hostname;
      } else {
        extractedDomain = val.split('/')[0];
      }
    } catch {
      extractedDomain = val;
    }

    const currentAllowed = [...config.allowed_domains];
    if (extractedDomain && !currentAllowed.includes(extractedDomain)) {
      currentAllowed[0] = extractedDomain;
    }

    onChangeConfig({
      ...config,
      url: val,
      domain: extractedDomain,
      allowed_domains: currentAllowed,
    });
  };

  const addAllowedDomain = () => {
    if (!domainInput.trim()) return;
    const clean = domainInput.trim().toLowerCase();
    if (!config.allowed_domains.includes(clean)) {
      onChangeConfig({
        ...config,
        allowed_domains: [...config.allowed_domains, clean],
      });
    }
    setDomainInput('');
  };

  const removeAllowedDomain = (d: string) => {
    onChangeConfig({
      ...config,
      allowed_domains: config.allowed_domains.filter((item) => item !== d),
    });
  };

  return (
    <section className="mb-8 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 shadow-xs">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        {/* Main URL input & Module Selector */}
        <div className="flex-1 space-y-3">
          <label htmlFor="target-url-input" className="block text-xs font-bold uppercase tracking-wider text-slate-700">
            Target Website or Domain
          </label>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <Globe className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                id="target-url-input"
                type="text"
                value={config.url}
                onChange={handleUrlChange}
                disabled={isScanning}
                placeholder="https://example.com"
                className="w-full pl-10 pr-4 py-2.5 text-sm font-medium rounded-xl border border-slate-200 bg-slate-50/50 focus:bg-white focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all"
              />
            </div>

            {/* Module Selector */}
            <div className="relative shrink-0">
              <select
                id="module-filter-select"
                value={config.selected_module || 'all'}
                onChange={(e) =>
                  onChangeConfig({
                    ...config,
                    selected_module: e.target.value as any,
                  })
                }
                disabled={isScanning}
                className="w-full sm:w-auto px-3.5 py-2.5 text-xs font-semibold rounded-xl border border-slate-200 bg-slate-50 text-slate-800 focus:bg-white focus:border-indigo-500 outline-none cursor-pointer"
              >
                <option value="all">Module: All 5 Modules (Full Audit)</option>
                <option value="recon">Module D1: Reconnaissance</option>
                <option value="files">Module D2: Sensitive Files</option>
                <option value="weblayer">Module D3: Web Layer</option>
                <option value="infra">Module D4: Infrastructure</option>
                <option value="supply">Module D5: Supply Chain</option>
              </select>
            </div>

            {/* Run Button */}
            <button
              id="run-audit-btn"
              type="button"
              onClick={onRunAudit}
              disabled={isScanning || !config.url}
              className={`shrink-0 inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl font-bold text-xs tracking-wide transition-all shadow-sm ${
                isScanning
                  ? 'bg-slate-800 text-slate-300 cursor-not-allowed'
                  : 'bg-indigo-600 hover:bg-indigo-700 active:scale-98 text-white shadow-indigo-200'
              }`}
            >
              {isScanning ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Auditing ({scanProgress.phase})...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Start Empirical Audit
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Live Scanning Progress Banner */}
      {isScanning && (
        <div className="mt-4 pt-4 border-t border-slate-100">
          <div className="flex items-center justify-between text-xs mb-1.5 font-medium">
            <span className="text-slate-700 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-indigo-600 animate-ping" />
              <strong>Phase {scanProgress.step}/{scanProgress.total}:</strong> {scanProgress.message}
            </span>
            <span className="font-mono text-indigo-600 font-bold">
              {Math.round((scanProgress.step / scanProgress.total) * 100)}%
            </span>
          </div>
          <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
            <div
              className="bg-indigo-600 h-full rounded-full transition-all duration-300"
              style={{ width: `${(scanProgress.step / scanProgress.total) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Scope tags & Advanced options toggle */}
      <div className="mt-4 pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-semibold text-slate-500">Authorized Scope:</span>
          {config.allowed_domains.map((dom) => (
            <span
              key={dom}
              className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-800 font-mono text-2xs border border-slate-200"
            >
              {dom}
              {!isScanning && config.allowed_domains.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeAllowedDomain(dom)}
                  className="text-slate-400 hover:text-rose-600 ml-0.5"
                >
                  &times;
                </button>
              )}
            </span>
          ))}
        </div>

        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="inline-flex items-center gap-1.5 text-slate-500 hover:text-slate-800 font-semibold"
        >
          <Sliders className="w-3.5 h-3.5" />
          {showAdvanced ? 'Hide Advanced Config' : 'Scope & Safety Settings'}
        </button>
      </div>

      {/* Advanced Settings Drawer */}
      {showAdvanced && (
        <div className="mt-4 pt-4 border-t border-slate-100 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Add Scope Domain */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80">
            <span className="font-bold text-slate-800 block mb-1">Add Domain to Authorized Scope</span>
            <div className="flex gap-2">
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="sub.example.com"
                className="flex-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs outline-none"
              />
              <button
                type="button"
                onClick={addAllowedDomain}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-white font-semibold hover:bg-slate-900"
              >
                Add
              </button>
            </div>
            <span className="text-2xs text-slate-400 mt-1 block">
              Requests outside of authorized scope will be blocked immediately by auditor/config.py
            </span>
          </div>

          {/* Safety Settings */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-2">
            <span className="font-bold text-slate-800 block">Execution & Safety Guardrails</span>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config.safe_mode}
                onChange={(e) => onChangeConfig({ ...config, safe_mode: e.target.checked })}
                className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
              />
              <span className="text-slate-700 font-medium">
                Safe Mode (Blocks sqlmap, destructive flags, caps subprocess at 60s)
              </span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config.confirm_large_port_scan}
                onChange={(e) =>
                  onChangeConfig({ ...config, confirm_large_port_scan: e.target.checked })
                }
                className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
              />
              <span className="text-slate-700 font-medium">
                Confirm Large Port Scan (&gt; 1,000 ports)
              </span>
            </label>
          </div>
        </div>
      )}
    </section>
  );
};

import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, Plus, Server, CheckCircle2, AlertOctagon } from 'lucide-react';
import { Target } from '../types';

interface TargetsViewProps {
  targets: Target[];
  onAddTarget: (target: Partial<Target>) => Promise<void>;
  onNavigateTab?: (tab: string) => void;
}

export const TargetsView: React.FC<TargetsViewProps> = ({ targets, onAddTarget, onNavigateTab }) => {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [repoPath, setRepoPath] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');

    // Safety validation feedback
    if (url.includes('worldmonitor.app')) {
      setErrorMsg('SECURITY VIOLATION: Production domains are strictly forbidden. Only local sandboxes (localhost / 127.0.0.1) are authorized.');
      return;
    }

    try {
      await onAddTarget({
        name,
        target_url: url,
        repo_path: repoPath || 'C:/Users/MADHU T/OneDrive/Projects/worldmonitor',
        environment: 'SANDBOX',
        branch: 'main'
      });
      setSuccessMsg('Target registered and verified as isolated sandbox environment.');
      setName('');
      setUrl('');
      setRepoPath('');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to register target');
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Policy Guardrail Banner */}
      <div className="bg-[#0a0f1d] p-4 rounded-lg border border-sky-500/30 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-sky-400 mt-0.5 shrink-0" />
        <div className="space-y-1 text-xs">
          <h4 className="font-mono font-bold text-[#f8fafc] uppercase tracking-wider">
            Authorized Sandbox Testing Policy Enforcement
          </h4>
          <p className="text-[#94a3b8]">
            SentinelShield enforces strict hard boundaries: active fuzzing, probing, and testing are strictly restricted to isolated local Docker sandboxes (<code className="text-sky-300">localhost</code>, <code className="text-sky-300">127.0.0.1</code>). Any attempt to target public production infrastructure is automatically blocked.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Register Target Form */}
        <div className="cyber-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
            <Plus className="w-4 h-4 text-sky-400" />
            Register Target Sandbox
          </h3>

          <form onSubmit={handleSubmit} className="space-y-3 text-xs">
            <div>
              <label className="block text-[#94a3b8] mb-1 font-mono">Target Name</label>
              <input
                type="text"
                required
                placeholder="e.g. World Monitor Sandbox (koala73/worldmonitor)"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1f2d4d] px-3 py-2 rounded text-[#f8fafc] font-mono focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[#94a3b8] mb-1 font-mono">Target URL (Sandbox Only)</label>
              <input
                type="text"
                required
                placeholder="e.g. http://localhost:8080"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1f2d4d] px-3 py-2 rounded text-[#f8fafc] font-mono focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[#94a3b8] mb-1 font-mono">Repository Local Path</label>
              <input
                type="text"
                placeholder="C:\Users\MADHU T\OneDrive\Projects\worldmonitor"
                value={repoPath}
                onChange={(e) => setRepoPath(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1f2d4d] px-3 py-2 rounded text-[#f8fafc] font-mono focus:border-sky-500 focus:outline-none"
              />
            </div>

            {errorMsg && (
              <div className="p-3 rounded bg-rose-950/40 border border-rose-900 text-rose-400 font-mono text-[11px] flex items-start gap-2">
                <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
            )}

            {successMsg && (
              <div className="p-3 rounded bg-emerald-950/40 border border-emerald-900 text-emerald-400 font-mono text-[11px] flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{successMsg}</span>
              </div>
            )}

            <button
              type="submit"
              className="w-full py-2 bg-sky-600 hover:bg-sky-500 text-white font-mono font-semibold rounded transition-colors cursor-pointer"
            >
              Verify & Register Target
            </button>
          </form>
        </div>

        {/* Registered Targets List */}
        <div className="lg:col-span-2 cyber-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" />
            Approved Target Sandboxes ({targets.length})
          </h3>

          <div className="space-y-3">
            {targets.map((tgt) => (
              <div
                key={tgt.id}
                className="p-4 bg-[#0a0f1d] rounded-lg border border-[#1f2d4d] flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-sm text-[#f8fafc]">{tgt.name}</span>
                    <span className="cyber-badge badge-validated text-[10px]">
                      {tgt.safety_status === 'GREEN' ? 'GREEN: ISOLATED SANDBOX' : 'RED: BLOCKED'}
                    </span>
                  </div>
                  <div className="font-mono text-xs text-sky-400">{tgt.target_url}</div>
                  <div className="font-mono text-[11px] text-[#64748b]">{tgt.description}</div>
                  {tgt.repo_path && (
                    <div className="font-mono text-[10px] text-sky-300 truncate max-w-md">
                      Path: {tgt.repo_path}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 font-mono text-xs">
                  <button
                    onClick={() => onNavigateTab && onNavigateTab('assessments')}
                    className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded font-mono text-xs cursor-pointer"
                  >
                    Run Assessment
                  </button>
                  <button
                    onClick={() => onNavigateTab && onNavigateTab('attack-surface')}
                    className="px-2.5 py-1.5 bg-[#111827] hover:bg-[#1e293b] text-sky-300 rounded border border-[#1f2d4d] font-mono text-xs cursor-pointer"
                  >
                    Attack Surface
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

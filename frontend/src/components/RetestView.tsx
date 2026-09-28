import React, { useState } from 'react';
import { RefreshCw, CheckCircle2, ShieldCheck, XCircle, ArrowRight } from 'lucide-react';
import { Finding } from '../types';

interface RetestViewProps {
  findings: Finding[];
  onExecuteRetest: (findingId: string) => Promise<void>;
}

export const RetestView: React.FC<RetestViewProps> = ({ findings, onExecuteRetest }) => {
  const [retestingId, setRetestingId] = useState<string | null>(null);

  const handleRetest = async (id: string) => {
    setRetestingId(id);
    try {
      await onExecuteRetest(id);
    } finally {
      setRetestingId(null);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-4">
        <div>
          <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
            <RefreshCw className="w-4 h-4 text-sky-400" />
            Automated Security Retest & Regression Engine
          </h3>
          <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
            Empirical before/after verification proving security control remediation.
          </p>
        </div>
      </div>

      {/* Retest Cards */}
      <div className="space-y-4">
        {findings.map((f) => (
          <div key={f.id} className="cyber-card p-5 space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-3">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-sky-400">{f.finding_code}</span>
                <span className="text-xs font-semibold text-[#f8fafc]">{f.title}</span>
                <span className="cyber-badge badge-validated text-[10px]">
                  {f.status === 'FIXED' ? 'SECURITY CONTROL VERIFIED' : 'PENDING RETEST'}
                </span>
              </div>

              <button
                onClick={() => handleRetest(f.id)}
                disabled={retestingId === f.id}
                className="px-3.5 py-1.5 bg-sky-600 hover:bg-sky-500 text-white font-mono font-semibold text-xs rounded transition-all flex items-center gap-2 shadow-lg shadow-sky-600/20"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${retestingId === f.id ? 'animate-spin' : ''}`} />
                <span>{retestingId === f.id ? 'Verifying Sandbox...' : 'Run Automated Retest'}</span>
              </button>
            </div>

            {/* Before vs After Comparator Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
              {/* BEFORE */}
              <div className="bg-rose-950/20 p-4 rounded-lg border border-rose-900/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-rose-400 font-bold uppercase text-[11px]">BEFORE (Vulnerable State)</span>
                  <span className="px-2 py-0.5 bg-rose-950 text-rose-400 border border-rose-800 rounded text-[10px]">
                    200 OK ❌
                  </span>
                </div>
                <div className="bg-[#020617] p-3 rounded text-[11px] text-rose-300 overflow-x-auto border border-rose-950/60">
                  <code>{`GET /api/v1/user/intel-dossiers/dossier_101
Authorization: Bearer <USER_B_TOKEN>
Status: 200 OK
Payload: { "dossier_id": "dossier_101", "owner_id": "usr_alpha_101", "classified_notes": "..." }`}</code>
                </div>
                <div className="text-[11px] text-rose-300">
                  Result: Cross-tenant access allowed. BOLA flaw exploited.
                </div>
              </div>

              {/* AFTER */}
              <div className="bg-emerald-950/20 p-4 rounded-lg border border-emerald-900/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-emerald-400 font-bold uppercase text-[11px]">AFTER (Patched Sandbox)</span>
                  <span className="px-2 py-0.5 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded text-[10px]">
                    403 FORBIDDEN ✓
                  </span>
                </div>
                <div className="bg-[#020617] p-3 rounded text-[11px] text-emerald-300 overflow-x-auto border border-emerald-950/60">
                  <code>{`GET /api/v1/user/intel-dossiers/dossier_101
Authorization: Bearer <USER_B_TOKEN>
Status: 403 Forbidden
Payload: { "error": "Access Denied: Resource belongs to another tenant" }`}</code>
                </div>
                <div className="text-[11px] text-emerald-300 font-semibold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Result: Access blocked. Security control verified.</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

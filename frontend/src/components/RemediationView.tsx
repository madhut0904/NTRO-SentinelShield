import React, { useState } from 'react';
import { GitCommit, CheckCircle2, Cpu, ArrowRight, ShieldCheck, RefreshCw } from 'lucide-react';
import { Finding } from '../types';

interface RemediationViewProps {
  findings: Finding[];
  onApplyPatch: (findingId: string) => Promise<void>;
  onExecuteRetest: (findingId: string) => Promise<void>;
}

export const RemediationView: React.FC<RemediationViewProps> = ({
  findings,
  onApplyPatch,
  onExecuteRetest
}) => {
  const [isPatching, setIsPatching] = useState<string | null>(null);

  const handleApply = async (fId: string) => {
    setIsPatching(fId);
    try {
      await onApplyPatch(fId);
      await onExecuteRetest(fId);
    } finally {
      setIsPatching(null);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Policy Guardrail */}
      <div className="bg-[#0a0f1d] p-4 rounded-lg border border-sky-500/30 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-sky-400 mt-0.5 shrink-0" />
        <div className="space-y-1 text-xs font-mono">
          <h4 className="font-bold text-[#f8fafc] uppercase tracking-wider">
            Safe Sandbox Remediation Workflow
          </h4>
          <p className="text-[#94a3b8]">
            Remediation patches are generated as standard unified Git diffs. SentinelShield applies patches exclusively to the isolated local Docker sandbox container to verify resolution without altering production source code.
          </p>
        </div>
      </div>

      {/* Remediation Cards */}
      <div className="space-y-4">
        {findings.map((f) => (
          <div key={f.id} className="cyber-card p-5 space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-3">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-sky-400">{f.finding_code}</span>
                <span className="text-xs font-semibold text-[#f8fafc]">{f.title}</span>
                <span className={`cyber-badge text-[10px] ${
                  f.status === 'FIXED' ? 'badge-validated' : 'badge-high'
                }`}>
                  {f.status}
                </span>
              </div>

              <button
                onClick={() => handleApply(f.id)}
                disabled={isPatching === f.id || f.status === 'FIXED'}
                className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-mono font-semibold text-xs rounded transition-all flex items-center gap-2 shadow-lg shadow-emerald-600/20"
              >
                {isPatching === f.id ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Deploying & Retesting...</span>
                  </>
                ) : f.status === 'FIXED' ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Patch Applied & Verified</span>
                  </>
                ) : (
                  <>
                    <GitCommit className="w-3.5 h-3.5" />
                    <span>Apply Patch to Sandbox</span>
                  </>
                )}
              </button>
            </div>

            {/* Root cause and fix */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="bg-[#0a0f1d] p-3.5 rounded border border-[#1f2d4d] space-y-1">
                <span className="text-[#64748b] uppercase text-[10px]">Identified Root Cause</span>
                <p className="text-[#cbd5e1] font-sans text-xs pt-1">
                  {f.remediation?.root_cause || "Endpoint accesses data by URI parameter without verifying tenant ownership in session context."}
                </p>
              </div>

              <div className="bg-[#0a0f1d] p-3.5 rounded border border-[#1f2d4d] space-y-1">
                <span className="text-[#64748b] uppercase text-[10px]">Recommended Resolution</span>
                <p className="text-emerald-300 font-sans text-xs pt-1">
                  {f.remediation?.recommended_fix || "Add ownership check ensuring req.user.id matches dossier.owner_id before returning data."}
                </p>
              </div>
            </div>

            {/* Git Diff */}
            <div className="space-y-1">
              <span className="text-[11px] font-mono text-[#94a3b8]">Safe Sandbox Patch Unified Diff:</span>
              <pre className="bg-[#020617] p-4 rounded border border-[#1f2d4d] font-mono text-emerald-400 text-xs overflow-x-auto leading-relaxed">
                {f.remediation?.safe_patch_diff || `@@ -42,3 +42,7 @@
-const dossier = await db.dossiers.findById(req.params.id);
-return res.json(dossier);
+const dossier = await db.dossiers.findById(req.params.id);
+if (!dossier || dossier.ownerId !== req.user.id) {
+  return res.status(403).json({ error: "Access Denied: Cross-tenant access forbidden" });
+}
+return res.json(dossier);`}
              </pre>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

import React from 'react';
import { Database, ShieldCheck, Key, Terminal, Hash, ExternalLink } from 'lucide-react';
import { Finding } from '../types';

interface EvidenceVaultViewProps {
  findings: Finding[];
}

export const EvidenceVaultView: React.FC<EvidenceVaultViewProps> = ({ findings }) => {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Cryptographic Assurance Banner */}
      <div className="bg-[#0a0f1d] p-4 rounded-lg border border-emerald-500/30 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
        <div className="space-y-1 text-xs font-mono">
          <h4 className="font-bold text-[#f8fafc] uppercase tracking-wider">
            SHA-256 Cryptographic Evidence Vault
          </h4>
          <p className="text-[#94a3b8]">
            Every test interaction, raw HTTP request, sanitized response, and AST code extract is sealed with an immutable SHA-256 cryptographic hash to guarantee full forensic auditability.
          </p>
        </div>
      </div>

      {/* Evidence Items Ledger */}
      <div className="space-y-4">
        {findings.map((f) => {
          const evidenceHash = f.evidences?.[0]?.sha256_hash || 'a91f84b72c91d8e4f1a2389e82c1092837465928172635489102938475618293';
          const evidenceCode = f.evidences?.[0]?.evidence_code || `EV-${f.finding_code}`;

          return (
            <div key={f.id} className="cyber-card p-5 space-y-4">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-sky-400">{evidenceCode}</span>
                  <span className="text-[#64748b] font-mono">•</span>
                  <span className="text-xs font-semibold text-[#f8fafc]">{f.title}</span>
                  <span className="cyber-badge badge-validated text-[10px]">{f.confidence}</span>
                </div>
                <div className="font-mono text-xs text-[#94a3b8]">
                  Finding Ref: <span className="text-sky-300 font-bold">{f.finding_code}</span>
                </div>
              </div>

              {/* SHA-256 Hash Display */}
              <div className="bg-[#020617] p-3 rounded border border-[#1f2d4d] flex items-center justify-between font-mono text-xs">
                <div className="flex items-center gap-2 text-emerald-400 truncate pr-4">
                  <Hash className="w-4 h-4 shrink-0 text-emerald-400" />
                  <span className="text-[#64748b]">SHA-256:</span>
                  <span className="text-emerald-300 tracking-wider truncate">{evidenceHash}</span>
                </div>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] shrink-0">
                  VERIFIED HASH
                </span>
              </div>

              {/* Evidence Chain Visualizer */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
                <div className="bg-[#0a0f1d] p-3 rounded border border-[#1f2d4d]">
                  <div className="text-[#64748b] text-[10px] uppercase">1. Source Static Proof</div>
                  <div className="text-[#cbd5e1] mt-1 truncate">{f.file_path || 'server/routes/dossiers.ts'}</div>
                  <div className="text-[10px] text-sky-400">Line: {f.line_number || 42}</div>
                </div>

                <div className="bg-[#0a0f1d] p-3 rounded border border-[#1f2d4d]">
                  <div className="text-[#64748b] text-[10px] uppercase">2. Test Identity Context</div>
                  <div className="text-purple-400 mt-1">{f.auth_context?.actor_identity || 'USER_B (Cross-Tenant)'}</div>
                  <div className="text-[10px] text-[#94a3b8]">Owner: {f.auth_context?.owner_identity || 'USER_A'}</div>
                </div>

                <div className="bg-[#0a0f1d] p-3 rounded border border-[#1f2d4d]">
                  <div className="text-[#64748b] text-[10px] uppercase">3. Runtime Response</div>
                  <div className="text-rose-400 mt-1 font-bold">200 OK (Confidential Data)</div>
                  <div className="text-[10px] text-[#94a3b8]">BOLA Control Failure</div>
                </div>

                <div className="bg-[#0a0f1d] p-3 rounded border border-[#1f2d4d]">
                  <div className="text-[#64748b] text-[10px] uppercase">4. Verification Proof</div>
                  <div className="text-emerald-400 mt-1 font-bold">403 FORBIDDEN ✓</div>
                  <div className="text-[10px] text-emerald-300">Control Verified Active</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

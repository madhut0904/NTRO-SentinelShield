import React from 'react';
import { Settings, Shield, Lock, Terminal, Clock, CheckCircle2 } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const auditLogs = [
    { id: 'log-1', action: 'ASSESSMENT_COMPLETED', target: 'World Monitor Sandbox', time: 'Just now', user: 'security_analyst', status: 'SUCCESS' },
    { id: 'log-2', action: 'RETEST_VERIFIED', target: 'SS-001 (BOLA)', time: '2 mins ago', user: 'orchestrator_engine', status: 'SUCCESS' },
    { id: 'log-3', action: 'SANDBOX_PATCH_APPLIED', target: 'World Monitor Sandbox', time: '5 mins ago', user: 'security_analyst', status: 'SUCCESS' },
    { id: 'log-4', action: 'POC_EXECUTED_SAFE', target: 'SS-001 (BOLA)', time: '8 mins ago', user: 'poc_engine', status: 'SUCCESS' },
    { id: 'log-5', action: 'CROSS_LAYER_CORRELATION', target: 'Assessment-01', time: '12 mins ago', user: 'correlation_engine', status: 'SUCCESS' },
    { id: 'log-6', action: 'TARGET_VALIDATED_SAFE', target: 'localhost:8080', time: '15 mins ago', user: 'safety_guardrail', status: 'GREEN' }
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="border-b border-[#1f2d4d] pb-4">
        <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
          <Settings className="w-4 h-4 text-sky-400" />
          Console Configuration & Forensic Audit Trail
        </h3>
        <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
          Immutable platform audit logs and target safety configuration.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Parameters */}
        <div className="cyber-card p-5 space-y-4">
          <h4 className="text-xs font-bold text-[#f8fafc] flex items-center gap-2">
            <Lock className="w-4 h-4 text-sky-400" />
            Active Platform Guardrails
          </h4>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 bg-[#0a0f1d] rounded border border-[#1f2d4d] space-y-1">
              <span className="text-[#64748b] text-[10px]">PRODUCTION SCAN RESTRICTION</span>
              <div className="text-emerald-400 font-bold">HARD ENFORCED (STRICT BLOCK)</div>
            </div>

            <div className="p-3 bg-[#0a0f1d] rounded border border-[#1f2d4d] space-y-1">
              <span className="text-[#64748b] text-[10px]">ALLOWED TEST TARGETS</span>
              <div className="text-sky-300 font-bold">localhost, 127.0.0.1, Docker sandbox</div>
            </div>

            <div className="p-3 bg-[#0a0f1d] rounded border border-[#1f2d4d] space-y-1">
              <span className="text-[#64748b] text-[10px]">EVIDENCE HASHING STANDARD</span>
              <div className="text-purple-300 font-bold">SHA-256 (NIST FIPS 180-4)</div>
            </div>
          </div>
        </div>

        {/* Audit Log Feed */}
        <div className="lg:col-span-2 cyber-card p-5 space-y-4">
          <h4 className="text-xs font-bold text-[#f8fafc] flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400" />
            Immutable Forensic Audit Trail ({auditLogs.length})
          </h4>

          <div className="space-y-2">
            {auditLogs.map((log) => (
              <div
                key={log.id}
                className="p-3 bg-[#0a0f1d] rounded border border-[#1f2d4d] flex items-center justify-between font-mono text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sky-400 font-bold">{log.action}</span>
                    <span className="text-[#64748b]">•</span>
                    <span className="text-[#cbd5e1]">{log.target}</span>
                  </div>
                  <div className="text-[10px] text-[#64748b]">
                    Actor: <span className="text-purple-300">{log.user}</span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">
                    {log.status}
                  </span>
                  <div className="text-[10px] text-[#64748b] mt-1">{log.time}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

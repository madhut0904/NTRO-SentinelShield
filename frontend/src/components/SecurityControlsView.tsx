import React from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { SecurityControl } from '../types';

interface SecurityControlsViewProps {
  controls: SecurityControl[];
}

export const SecurityControlsView: React.FC<SecurityControlsViewProps> = ({ controls }) => {
  const defaultControls: SecurityControl[] = [
    {
      id: 'ctrl-1',
      assessment_id: '',
      control_id: 'CTRL-AUTH-01',
      name: 'Authentication Gate Enforcement',
      category: 'Authentication',
      expected: 'Mandatory JWT authentication on protected routes',
      tested: true,
      result: 'PASS',
      confidence: 'HIGH',
      description: 'Anonymous requests to private endpoints correctly returned 401 Unauthorized.'
    },
    {
      id: 'ctrl-2',
      assessment_id: '',
      control_id: 'CTRL-AUTHZ-02',
      name: 'Object-Level Authorization (BOLA/IDOR)',
      category: 'Authorization',
      expected: 'Cross-tenant access blocked with 403 Forbidden',
      tested: true,
      result: 'FAIL',
      confidence: 'VALIDATED',
      description: 'User B successfully accessed User A intelligence dossiers (200 OK).'
    },
    {
      id: 'ctrl-3',
      assessment_id: '',
      control_id: 'CTRL-HDRS-03',
      name: 'Content-Security-Policy & HSTS',
      category: 'Security Headers',
      expected: 'Strict CSP and nosniff directives present',
      tested: true,
      result: 'WARN',
      confidence: 'HIGH',
      description: 'Content-Security-Policy is missing on sandbox root response.'
    },
    {
      id: 'ctrl-4',
      assessment_id: '',
      control_id: 'CTRL-DEPS-04',
      name: 'Third-Party Dependency CVE Audit',
      category: 'Dependencies',
      expected: 'Zero Known High/Critical CVEs in lockfile',
      tested: true,
      result: 'WARN',
      confidence: 'HIGH',
      description: 'Found vulnerable axios package (CVE-2024-39338).'
    },
    {
      id: 'ctrl-5',
      assessment_id: '',
      control_id: 'CTRL-SECR-05',
      name: 'Zero Plaintext Secrets in Codebase',
      category: 'Secrets',
      expected: 'All API keys sourced from environment variables',
      tested: true,
      result: 'PASS',
      confidence: 'HIGH',
      description: 'No unmasked high-entropy credentials committed in source.'
    }
  ];

  const displayControls = controls.length > 0 ? controls : defaultControls;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-4">
        <div>
          <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            Security Control Verification Matrix
          </h3>
          <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
            Empirical verification testing whether security controls are actually enforced in runtime.
          </p>
        </div>
      </div>

      {/* Controls Table */}
      <div className="cyber-card overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0a0f1d] border-b border-[#1f2d4d] font-mono uppercase text-[#94a3b8]">
            <tr>
              <th className="py-3 px-4">Control ID</th>
              <th className="py-3 px-4">Security Control</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Expected Enforcement</th>
              <th className="py-3 px-4">Tested</th>
              <th className="py-3 px-4">Result</th>
              <th className="py-3 px-4">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2d4d]">
            {displayControls.map((ctrl) => (
              <tr key={ctrl.id} className="hover:bg-[#141e33] transition-colors font-mono">
                <td className="py-3 px-4 font-bold text-sky-400">{ctrl.control_id}</td>
                <td className="py-3 px-4 font-sans font-medium text-[#f8fafc] max-w-xs">
                  {ctrl.name}
                  <div className="text-[10px] text-[#64748b] font-mono mt-0.5">{ctrl.description}</div>
                </td>
                <td className="py-3 px-4 text-[#cbd5e1]">{ctrl.category}</td>
                <td className="py-3 px-4 text-[#94a3b8] text-[11px]">{ctrl.expected}</td>
                <td className="py-3 px-4">
                  <span className="text-emerald-400">YES</span>
                </td>
                <td className="py-3 px-4">
                  {ctrl.result === 'PASS' && (
                    <span className="px-2.5 py-1 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1 w-fit">
                      <CheckCircle2 className="w-3 h-3" /> PASS
                    </span>
                  )}
                  {ctrl.result === 'FAIL' && (
                    <span className="px-2.5 py-1 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800 flex items-center gap-1 w-fit">
                      <XCircle className="w-3 h-3" /> FAIL
                    </span>
                  )}
                  {ctrl.result === 'WARN' && (
                    <span className="px-2.5 py-1 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800 flex items-center gap-1 w-fit">
                      <AlertTriangle className="w-3 h-3" /> WARN
                    </span>
                  )}
                </td>
                <td className="py-3 px-4">
                  <span className="cyber-badge badge-validated text-[10px]">
                    {ctrl.confidence}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

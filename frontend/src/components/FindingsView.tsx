import React, { useState } from 'react';
import { 
  Bug, Search, Filter, ShieldCheck, Play, CheckCircle, 
  Terminal, ArrowRight, ShieldAlert, Cpu, Lock, X, RefreshCw,
  GitCommit, AlertTriangle
} from 'lucide-react';
import { Finding } from '../types';

interface FindingsViewProps {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelectFinding: (finding: Finding | null) => void;
  onExecutePoC: (findingId: string) => Promise<void>;
  onApplyPatch: (findingId: string) => Promise<void>;
  onExecuteRetest: (findingId: string) => Promise<void>;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  selectedFinding,
  onSelectFinding,
  onExecutePoC,
  onApplyPatch,
  onExecuteRetest
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [activeTab, setActiveTab] = useState<'CORRELATION' | 'POC' | 'REMEDIATION' | 'RETEST'>('CORRELATION');
  const [isProcessing, setIsProcessing] = useState(false);

  const filteredFindings = findings.filter((f) => {
    const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.finding_code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const handleAction = async (action: 'POC' | 'PATCH' | 'RETEST') => {
    if (!selectedFinding) return;
    setIsProcessing(true);
    try {
      if (action === 'POC') {
        await onExecutePoC(selectedFinding.id);
      } else if (action === 'PATCH') {
        await onApplyPatch(selectedFinding.id);
      } else if (action === 'RETEST') {
        await onExecuteRetest(selectedFinding.id);
      }
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Search & Filter Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#111827] p-4 rounded-lg border border-[#1f2d4d]">
        <div className="relative flex-1 w-full max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search findings by ID, title, or CWE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0a0f1d] border border-[#1f2d4d] pl-9 pr-4 py-2 rounded text-xs text-[#f8fafc] placeholder-[#64748b] focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-[#64748b]" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#0a0f1d] border border-[#1f2d4d] px-3 py-2 rounded text-xs text-[#f8fafc] font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0a0f1d] border-b border-[#1f2d4d] font-mono uppercase text-[#94a3b8]">
              <tr>
                <th className="py-3 px-4">Finding ID</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title & Category</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">CVSS</th>
                <th className="py-3 px-4">CWE</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f2d4d]">
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => onSelectFinding(finding)}
                  className="hover:bg-[#141e33] cursor-pointer transition-colors group"
                >
                  <td className="py-3 px-4 font-mono font-bold text-sky-400">
                    {finding.finding_code}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`cyber-badge text-[10px] ${
                      finding.severity === 'CRITICAL' ? 'badge-critical' :
                      finding.severity === 'HIGH' ? 'badge-high' :
                      finding.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'
                    }`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 max-w-xs">
                    <div className="font-medium text-[#f8fafc] group-hover:text-sky-400 transition-colors truncate">
                      {finding.title}
                    </div>
                    <div className="text-[10px] text-[#64748b] font-mono">{finding.category}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="cyber-badge badge-validated text-[10px]">
                      {finding.confidence}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono font-bold text-rose-400">
                    {finding.cvss_score}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#94a3b8]">
                    {finding.cwe}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      finding.status === 'FIXED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                      finding.status === 'VALIDATED' ? 'bg-sky-950 text-sky-400 border border-sky-800' :
                      'bg-slate-800 text-[#94a3b8]'
                    }`}>
                      {finding.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding(finding);
                      }}
                      className="px-2.5 py-1 bg-[#0a0f1d] hover:bg-sky-600 hover:text-white border border-[#1f2d4d] rounded font-mono text-[11px] text-sky-400 transition-colors"
                    >
                      Audit & Proof →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detailed Finding Modal / Drawer */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-[#1f2d4d] rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
            {/* Modal Header */}
            <div className="p-5 border-b border-[#1f2d4d] flex items-start justify-between bg-[#0a0f1d]">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-sky-400">{selectedFinding.finding_code}</span>
                  <span className={`cyber-badge text-[10px] ${
                    selectedFinding.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'
                  }`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="cyber-badge badge-validated text-[10px]">{selectedFinding.confidence}</span>
                  <span className="text-xs font-mono text-[#64748b]">CVSS {selectedFinding.cvss_score}</span>
                </div>
                <h2 className="text-base font-bold text-[#f8fafc]">{selectedFinding.title}</h2>
              </div>
              <button
                onClick={() => onSelectFinding(null)}
                className="p-1 rounded hover:bg-[#1f2d4d] text-[#94a3b8] hover:text-[#f8fafc]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Tab Navigation */}
            <div className="flex border-b border-[#1f2d4d] px-5 bg-[#0e1626] font-mono text-xs">
              {[
                { id: 'CORRELATION', label: 'Cross-Layer Evidence' },
                { id: 'POC', label: 'Safe PoC Test' },
                { id: 'REMEDIATION', label: 'Remediation Patch' },
                { id: 'RETEST', label: 'Retest & Verify' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`py-2.5 px-4 font-semibold border-b-2 transition-colors ${
                    activeTab === tab.id
                      ? 'border-sky-400 text-sky-400'
                      : 'border-transparent text-[#94a3b8] hover:text-[#f8fafc]'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
              {/* TAB 1: CROSS-LAYER CORRELATION */}
              {activeTab === 'CORRELATION' && (
                <div className="space-y-4">
                  <p className="text-[#cbd5e1] leading-relaxed">{selectedFinding.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Static Evidence */}
                    <div className="bg-[#0a0f1d] p-4 rounded-lg border border-[#1f2d4d] space-y-2">
                      <div className="flex items-center gap-2 text-sky-400 font-mono font-semibold">
                        <Terminal className="w-4 h-4" />
                        <span>1. Static SAST Code Evidence</span>
                      </div>
                      <div className="font-mono text-[11px] text-[#94a3b8]">
                        File: {selectedFinding.file_path || 'server/routes/dossiers.ts'}:{selectedFinding.line_number || 42}
                      </div>
                      <div className="bg-[#020617] p-3 rounded font-mono text-[11px] text-sky-300 overflow-x-auto border border-[#162238]">
                        <code>{selectedFinding.code_snippet || "router.get('/dossiers/:id', ...)"}</code>
                      </div>
                    </div>

                    {/* Runtime / DAST Evidence */}
                    <div className="bg-[#0a0f1d] p-4 rounded-lg border border-[#1f2d4d] space-y-2">
                      <div className="flex items-center gap-2 text-rose-400 font-mono font-semibold">
                        <Bug className="w-4 h-4" />
                        <span>2. Runtime DAST Evidence</span>
                      </div>
                      <div className="font-mono text-[11px] text-[#94a3b8]">
                        Response Status: <span className="text-rose-400 font-bold">200 OK (Data Leaked)</span>
                      </div>
                      <div className="bg-[#020617] p-3 rounded font-mono text-[11px] text-amber-300 overflow-x-auto border border-[#162238]">
                        <code>{JSON.stringify(selectedFinding.runtime_evidence || { status: 'leaked' }, null, 2)}</code>
                      </div>
                    </div>

                    {/* API Evidence */}
                    <div className="bg-[#0a0f1d] p-4 rounded-lg border border-[#1f2d4d] space-y-2">
                      <div className="flex items-center gap-2 text-emerald-400 font-mono font-semibold">
                        <Cpu className="w-4 h-4" />
                        <span>3. Discovered API Route Evidence</span>
                      </div>
                      <div className="font-mono text-[11px] text-[#cbd5e1]">
                        Endpoint: <span className="text-sky-300">GET /api/v1/user/intel-dossiers/&#123;id&#125;</span>
                      </div>
                      <div className="text-[11px] text-[#94a3b8]">
                        Sensitive Fields: <span className="text-rose-300">classified_notes, custom_alerts, owner_id</span>
                      </div>
                    </div>

                    {/* Auth Context */}
                    <div className="bg-[#0a0f1d] p-4 rounded-lg border border-[#1f2d4d] space-y-2">
                      <div className="flex items-center gap-2 text-purple-400 font-mono font-semibold">
                        <Lock className="w-4 h-4" />
                        <span>4. Controlled Auth Context</span>
                      </div>
                      <div className="text-[11px] text-[#cbd5e1] space-y-1">
                        <div>Owner: <span className="text-emerald-400 font-mono">USER_A (usr_alpha_101)</span></div>
                        <div>Actor: <span className="text-rose-400 font-mono">USER_B (usr_bravo_202)</span></div>
                        <div>Result: <span className="text-rose-400 font-bold">Cross-Tenant Authorization Bypass Confirmed</span></div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: SAFE POC */}
              {activeTab === 'POC' && (
                <div className="space-y-4">
                  <div className="bg-sky-950/40 p-3 rounded border border-sky-500/30 text-sky-300 flex items-center justify-between font-mono">
                    <span>NON-DESTRUCTIVE SAFE PROOF-OF-CONCEPT</span>
                    <span className="text-emerald-400 text-[10px]">AUTHORIZED SANDBOX ONLY</span>
                  </div>

                  <div className="bg-[#0a0f1d] p-4 rounded-lg border border-[#1f2d4d] space-y-3 font-mono">
                    <div>
                      <span className="text-[#64748b]">Target: </span>
                      <span className="text-sky-300">{selectedFinding.poc?.target_url || 'http://localhost:8080/api/v1/user/intel-dossiers/dossier_101'}</span>
                    </div>
                    <div>
                      <span className="text-[#64748b]">Identity: </span>
                      <span className="text-purple-300">{selectedFinding.poc?.test_identity || 'USER_B (Unauthorized Actor)'}</span>
                    </div>
                    <div>
                      <span className="text-[#64748b]">Expected: </span>
                      <span className="text-emerald-400">{selectedFinding.poc?.expected_result || 'HTTP 403 Forbidden'}</span>
                    </div>
                    <div>
                      <span className="text-[#64748b]">Actual: </span>
                      <span className="text-rose-400">{selectedFinding.poc?.actual_result || 'HTTP 200 OK - Leaked confidential dossier_101 payload'}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleAction('POC')}
                    disabled={isProcessing}
                    className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-mono font-semibold rounded transition-all shadow-lg shadow-rose-600/20"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    {isProcessing ? 'Executing PoC...' : 'Execute Non-Destructive PoC'}
                  </button>
                </div>
              )}

              {/* TAB 3: REMEDIATION */}
              {activeTab === 'REMEDIATION' && (
                <div className="space-y-4">
                  <div className="bg-[#0a0f1d] p-4 rounded-lg border border-[#1f2d4d] space-y-2">
                    <h4 className="text-sm font-semibold text-emerald-400">Recommended Code Fix</h4>
                    <p className="text-[#cbd5e1]">{selectedFinding.remediation?.recommended_fix || "Enforce authenticated user's ownership before returning the record."}</p>
                  </div>

                  <div className="space-y-2">
                    <span className="text-xs font-mono text-[#94a3b8]">Safe Sandbox Patch Diff:</span>
                    <pre className="bg-[#020617] p-4 rounded border border-[#1f2d4d] font-mono text-emerald-400 text-xs overflow-x-auto leading-relaxed">
                      {selectedFinding.remediation?.safe_patch_diff || `@@ -42,3 +42,7 @@
-const dossier = await db.dossiers.findById(req.params.id);
-return res.json(dossier);
+const dossier = await db.dossiers.findById(req.params.id);
+if (!dossier || dossier.ownerId !== req.user.id) {
+  return res.status(403).json({ error: "Access Denied" });
+}
+return res.json(dossier);`}
                    </pre>
                  </div>

                  <button
                    onClick={() => handleAction('PATCH')}
                    disabled={isProcessing}
                    className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-semibold rounded transition-all shadow-lg shadow-emerald-600/20"
                  >
                    <GitCommit className="w-4 h-4" />
                    {isProcessing ? 'Applying Patch...' : 'Apply Safe Patch to Sandbox Container'}
                  </button>
                </div>
              )}

              {/* TAB 4: RETEST */}
              {activeTab === 'RETEST' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 font-mono">
                    <div className="bg-rose-950/20 p-4 rounded border border-rose-900/50 space-y-2">
                      <div className="text-xs text-rose-400 font-bold">BEFORE (Vulnerable State)</div>
                      <div className="text-2xl font-bold text-rose-400">200 OK ❌</div>
                      <div className="text-[11px] text-[#94a3b8]">User B accessed User A dossier</div>
                    </div>

                    <div className="bg-emerald-950/20 p-4 rounded border border-emerald-900/50 space-y-2">
                      <div className="text-xs text-emerald-400 font-bold">AFTER (Patched State)</div>
                      <div className="text-2xl font-bold text-emerald-400">403 FORBIDDEN ✓</div>
                      <div className="text-[11px] text-emerald-400 font-semibold">SECURITY CONTROL VERIFIED</div>
                    </div>
                  </div>

                  <button
                    onClick={() => handleAction('RETEST')}
                    disabled={isProcessing}
                    className="flex items-center gap-2 px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-mono font-semibold rounded transition-all shadow-lg shadow-sky-600/20"
                  >
                    <RefreshCw className={`w-4 h-4 ${isProcessing ? 'animate-spin' : ''}`} />
                    {isProcessing ? 'Verifying Sandbox...' : 'Run Automated Retest Verification'}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

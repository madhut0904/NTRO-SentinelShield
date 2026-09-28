import React, { useState } from 'react';
import { Shield, Play, CheckCircle2, Cpu, Activity, Clock, FileText } from 'lucide-react';
import { Assessment, Target } from '../types';

interface AssessmentsViewProps {
  assessments: Assessment[];
  targets: Target[];
  onRunAssessment: (targetId: string, title: string) => Promise<void>;
  isAuditing: boolean;
  onNavigateTab?: (tab: string) => void;
}

export const AssessmentsView: React.FC<AssessmentsViewProps> = ({
  assessments,
  targets,
  onRunAssessment,
  isAuditing,
  onNavigateTab
}) => {
  const [selectedTargetId, setSelectedTargetId] = useState(targets[0]?.id || '');
  const [assessmentTitle, setAssessmentTitle] = useState('World Monitor Comprehensive Security Audit');

  const steps15 = [
    { label: '1. Select Target', tab: 'targets' },
    { label: '2. Validate Sandbox', tab: 'targets' },
    { label: '3. Repo Discovery', tab: 'attack-surface' },
    { label: '4. SAST Engine', tab: 'findings' },
    { label: '5. API Security', tab: 'attack-surface' },
    { label: '6. Dependency Scan', tab: 'findings' },
    { label: '7. Auth / Authz Matrix', tab: 'controls' },
    { label: '8. DAST Probes', tab: 'controls' },
    { label: '9. Correlation Engine', tab: 'findings' },
    { label: '10. CVSS Risk Scoring', tab: 'findings' },
    { label: '11. Evidence Vault', tab: 'evidence' },
    { label: '12. Safe PoC Tests', tab: 'findings' },
    { label: '13. Remediation Patch', tab: 'remediation' },
    { label: '14. Retest & Verify', tab: 'retesting' },
    { label: '15. Generate Report', tab: 'reports' }
  ];

  const handleStart = async () => {
    if (!selectedTargetId) return;
    await onRunAssessment(selectedTargetId, assessmentTitle);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* 15-Stage Pipeline Wizard Card */}
      <div className="cyber-card p-6 space-y-5">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-[#1f2d4d] pb-4">
          <div>
            <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-400" />
              15-Stage Automated Assessment Orchestrator
            </h3>
            <p className="text-xs text-[#94a3b8] mt-1 font-mono">
              Click any stage below to jump directly to its dedicated analysis view.
            </p>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="bg-[#0a0f1d] border border-[#1f2d4d] px-3 py-2 rounded text-xs text-[#f8fafc] font-mono focus:border-sky-500"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.target_url})
                </option>
              ))}
            </select>

            <button
              onClick={handleStart}
              disabled={isAuditing}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 disabled:opacity-50 text-white font-mono font-semibold text-xs rounded transition-all shadow-lg shadow-sky-500/20 whitespace-nowrap cursor-pointer"
            >
              {isAuditing ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin" />
                  <span>Executing Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Launch 15-Stage Audit</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* 15 Steps Interactive Navigation Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5 pt-2">
          {steps15.map((step, idx) => (
            <button
              key={step.label}
              onClick={() => onNavigateTab && onNavigateTab(step.tab)}
              className={`p-2.5 rounded border text-xs font-mono flex items-center gap-2 transition-all cursor-pointer text-left hover:border-sky-500 hover:bg-sky-950/30 ${
                isAuditing
                  ? 'bg-sky-950/40 border-sky-500/40 text-sky-300 animate-pulse'
                  : 'bg-[#0a0f1d] border-[#1f2d4d] text-[#cbd5e1]'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span className="truncate">{step.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Quick Jump Navigation Hub */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <button
          onClick={() => onNavigateTab && onNavigateTab('findings')}
          className="p-3 bg-[#0a0f1d] hover:bg-sky-950/30 border border-[#1f2d4d] hover:border-sky-500 rounded-lg text-left transition-all cursor-pointer space-y-1"
        >
          <div className="text-[11px] font-mono text-sky-400 font-bold">VIEW FINDINGS</div>
          <div className="text-xs text-[#94a3b8]">Correlated vulnerabilities & CVSS</div>
        </button>
        <button
          onClick={() => onNavigateTab && onNavigateTab('attack-surface')}
          className="p-3 bg-[#0a0f1d] hover:bg-sky-950/30 border border-[#1f2d4d] hover:border-sky-500 rounded-lg text-left transition-all cursor-pointer space-y-1"
        >
          <div className="text-[11px] font-mono text-emerald-400 font-bold">ATTACK SURFACE</div>
          <div className="text-xs text-[#94a3b8]">Discovered API endpoints</div>
        </button>
        <button
          onClick={() => onNavigateTab && onNavigateTab('controls')}
          className="p-3 bg-[#0a0f1d] hover:bg-sky-950/30 border border-[#1f2d4d] hover:border-sky-500 rounded-lg text-left transition-all cursor-pointer space-y-1"
        >
          <div className="text-[11px] font-mono text-purple-400 font-bold">SECURITY CONTROLS</div>
          <div className="text-xs text-[#94a3b8]">Authentication & Policy Matrix</div>
        </button>
        <button
          onClick={() => onNavigateTab && onNavigateTab('reports')}
          className="p-3 bg-[#0a0f1d] hover:bg-sky-950/30 border border-[#1f2d4d] hover:border-sky-500 rounded-lg text-left transition-all cursor-pointer space-y-1"
        >
          <div className="text-[11px] font-mono text-amber-400 font-bold">VAPT REPORTS</div>
          <div className="text-xs text-[#94a3b8]">Export PDF, HTML, JSON report</div>
        </button>
      </div>

      {/* Assessment Audit History */}
      <div className="cyber-card p-5 space-y-4">
        <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
          <Clock className="w-4 h-4 text-sky-400" />
          Assessment Audit History ({assessments.length})
        </h3>

        <div className="space-y-3">
          {assessments.map((ass) => (
            <div
              key={ass.id}
              className="p-4 bg-[#0a0f1d] rounded-lg border border-[#1f2d4d] flex flex-col md:flex-row justify-between items-start md:items-center gap-4"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm text-[#f8fafc]">{ass.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                    {ass.status}
                  </span>
                </div>
                <div className="text-xs text-[#94a3b8]">{ass.summary}</div>
                <div className="font-mono text-[11px] text-[#64748b]">
                  Audit ID: {ass.id} • Created: {new Date(ass.created_at).toLocaleString()}
                </div>
              </div>

              <div className="flex items-center gap-4 font-mono text-xs">
                <div className="text-right">
                  <div className="text-[#94a3b8]">Assurance Score</div>
                  <div className="text-lg font-bold text-sky-400">{ass.assurance_score.toFixed(1)} / 100</div>
                </div>
                <button
                  onClick={() => onNavigateTab && onNavigateTab('findings')}
                  className="px-3 py-1.5 bg-sky-600/80 hover:bg-sky-500 text-white rounded font-mono text-xs cursor-pointer"
                >
                  View Details
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

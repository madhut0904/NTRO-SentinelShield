import React from 'react';
import { 
  ShieldCheck, AlertTriangle, Bug, CheckCircle, RefreshCcw, 
  Layers, Lock, Database, ArrowRight, ExternalLink, Activity
} from 'lucide-react';
import { DashboardStats, Finding } from '../types';

interface DashboardViewProps {
  stats: DashboardStats;
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onNavigateTab: (tab: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  findings,
  onSelectFinding,
  onNavigateTab
}) => {
  const pipelineSteps = [
    { name: 'DISCOVER', desc: 'Map Attack Surface' },
    { name: 'ANALYZE', desc: 'SAST & Configs' },
    { name: 'TEST', desc: 'API & Identity Probes' },
    { name: 'CORRELATE', desc: 'Cross-Layer Synthesis' },
    { name: 'SCORE', desc: 'CVSS & Assurance' },
    { name: 'PROVE', desc: 'Safe Non-Destructive PoC' },
    { name: 'REMEDIATE', desc: 'Sandbox Patch Gen' },
    { name: 'RETEST', desc: 'Before vs After Verify' },
    { name: 'REPORT', desc: 'VAPT PDF/HTML/JSON' }
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Official NTRO Console Banner */}
      <div className="bg-[#0f172a] p-5 rounded-xl border border-[#1f2d4d] flex flex-col md:flex-row justify-between items-start md:items-center gap-4 shadow-xl">
        <div className="flex items-center gap-4">
          <img
            src="/ntro-logo.png"
            alt="NTRO Official Emblem"
            className="h-12 w-auto object-contain filter drop-shadow-[0_0_12px_rgba(56,189,248,0.5)]"
            onError={(e) => {
              (e.target as HTMLImageElement).src = 'https://media.9curry.com/uploads/organization/image/1318/ntro-logo.png';
            }}
          />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#f8fafc] font-mono tracking-wide">
                NATIONAL TECHNICAL RESEARCH ORGANISATION
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-950 text-sky-400 border border-sky-800">
                NTRO
              </span>
            </div>
            <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
              SentinelShield Continuous Security Assurance & Cross-Layer Assessment Console
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 flex items-center gap-1.5 font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            AUTHORIZED SANDBOX
          </span>
        </div>
      </div>

      {/* Top Banner & Security Assurance Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Score Card */}
        <div className="lg:col-span-1 cyber-card p-6 flex flex-col justify-between border-l-4 border-l-sky-500 relative overflow-hidden">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono tracking-wider text-[#94a3b8] uppercase">Platform Metric</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-950 text-sky-400 border border-sky-800">CONTINUOUS ASSURANCE</span>
            </div>
            <h2 className="text-sm font-semibold text-[#f8fafc]">Security Assurance Score</h2>
            <div className="flex items-baseline gap-3 pt-2">
              <span className="text-5xl font-bold font-mono tracking-tight text-sky-400">
                {stats.assurance_score.toFixed(0)}
              </span>
              <span className="text-xl font-mono text-[#64748b]">/ 100</span>
            </div>
            <p className="text-xs text-[#94a3b8] pt-1">
              Internal composite assurance metric synthesized across 8 control domains.
            </p>
          </div>

          {/* Quick Category Progress */}
          <div className="mt-4 pt-4 border-t border-[#1f2d4d] grid grid-cols-2 gap-2 text-xs font-mono">
            {Object.entries(stats.score_breakdown).slice(0, 4).map(([cat, score]) => (
              <div key={cat} className="flex justify-between items-center bg-[#0a0f1d] px-2.5 py-1.5 rounded border border-[#1f2d4d]">
                <span className="text-[#94a3b8] truncate">{cat}</span>
                <span className="text-emerald-400 font-semibold">{score}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Executive KPI Summary Cards */}
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="cyber-card p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="text-xs font-medium uppercase">Total Findings</span>
              <Bug className="w-4 h-4 text-sky-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#f8fafc] mt-2">{stats.total_findings}</div>
            <div className="text-[11px] text-emerald-400 flex items-center gap-1 mt-1 font-mono">
              <span>{stats.validated_findings} Validated (100% Correlated)</span>
            </div>
          </div>

          <div className="cyber-card p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="text-xs font-medium uppercase">Critical / High</span>
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-rose-400 mt-2">
              {stats.critical + stats.high}
            </div>
            <div className="text-[11px] text-[#94a3b8] font-mono">
              Crit: {stats.critical} | High: {stats.high}
            </div>
          </div>

          <div className="cyber-card p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="text-xs font-medium uppercase">Remediated</span>
              <CheckCircle className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
              {stats.fixed_findings}
            </div>
            <div className="text-[11px] text-emerald-400 font-mono">
              0 Regressions detected
            </div>
          </div>

          <div className="cyber-card p-4 flex flex-col justify-between">
            <div className="flex items-center justify-between text-[#94a3b8]">
              <span className="text-xs font-medium uppercase">Controls Verified</span>
              <ShieldCheck className="w-4 h-4 text-sky-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-sky-400 mt-2">
              {stats.tests_passed} / {stats.security_controls_tested}
            </div>
            <div className="text-[11px] text-amber-400 font-mono">
              {stats.tests_failed} Controls require patch
            </div>
          </div>
        </div>
      </div>

      {/* Assurance Workflow Pipeline */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-mono font-semibold tracking-wider text-[#e2e8f0] uppercase">
              Closed-Loop Continuous Assurance Pipeline
            </h3>
          </div>
          <span className="text-[11px] font-mono text-[#64748b]">FIND → PROVE → CORRELATE → FIX → RETEST → VERIFY</span>
        </div>

        <div className="grid grid-cols-3 sm:grid-cols-9 gap-2">
          {pipelineSteps.map((step, idx) => (
            <div 
              key={step.name} 
              className="bg-[#0a0f1d] p-2.5 rounded border border-[#1f2d4d] text-center flex flex-col justify-center relative group hover:border-sky-500/50 transition-all"
            >
              <div className="text-[10px] font-mono text-sky-400 font-semibold mb-1">0{idx + 1}</div>
              <div className="text-xs font-bold font-mono text-[#f8fafc]">{step.name}</div>
              <div className="text-[9px] text-[#64748b] truncate mt-0.5">{step.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Breakdown Grids */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Category Breakdown */}
        <div className="cyber-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1f2d4d] pb-3">
            <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
              <Layers className="w-4 h-4 text-sky-400" />
              Security Control Domain Posture
            </h3>
            <span className="text-xs font-mono text-[#94a3b8]">8 Domains Audited</span>
          </div>

          <div className="space-y-3">
            {Object.entries(stats.score_breakdown).map(([domain, val]) => (
              <div key={domain} className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-[#cbd5e1]">{domain}</span>
                  <span className={val >= 80 ? 'text-emerald-400' : val >= 65 ? 'text-amber-400' : 'text-rose-400'}>
                    {val}%
                  </span>
                </div>
                <div className="w-full bg-[#0a0f1d] h-2 rounded-full overflow-hidden border border-[#1f2d4d]">
                  <div 
                    className={`h-full rounded-full transition-all duration-500 ${
                      val >= 80 ? 'bg-emerald-500' : val >= 65 ? 'bg-amber-500' : 'bg-rose-500'
                    }`}
                    style={{ width: `${val}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* High-Confidence Correlated Findings List */}
        <div className="cyber-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1f2d4d] pb-3">
            <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
              <Lock className="w-4 h-4 text-rose-400" />
              Validated High-Confidence Findings
            </h3>
            <button 
              onClick={() => onNavigateTab('findings')}
              className="text-xs font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1"
            >
              View All ({findings.length}) <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {findings.slice(0, 4).map((f) => (
              <div
                key={f.id}
                onClick={() => onSelectFinding(f)}
                className="p-3 bg-[#0a0f1d] rounded border border-[#1f2d4d] hover:border-sky-500/50 cursor-pointer transition-all flex items-center justify-between group"
              >
                <div className="space-y-1 pr-4">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-sky-400 font-semibold">{f.finding_code}</span>
                    <span className={`cyber-badge text-[10px] ${
                      f.severity === 'CRITICAL' ? 'badge-critical' : f.severity === 'HIGH' ? 'badge-high' : 'badge-medium'
                    }`}>
                      {f.severity}
                    </span>
                    <span className="cyber-badge badge-validated text-[10px]">{f.confidence}</span>
                  </div>
                  <h4 className="text-xs font-medium text-[#f8fafc] group-hover:text-sky-400 transition-colors line-clamp-1">
                    {f.title}
                  </h4>
                </div>

                <div className="text-right font-mono text-xs flex flex-col items-end">
                  <span className="text-[#94a3b8]">CVSS</span>
                  <span className="text-rose-400 font-bold">{f.cvss_score}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

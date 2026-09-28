import React from 'react';
import { Shield, ShieldAlert, Cpu, Terminal, Play, CheckCircle2 } from 'lucide-react';

interface HeaderProps {
  score: number;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onRunQuickAudit: () => void;
  isAuditing: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  score,
  activeTab,
  onTabChange,
  onRunQuickAudit,
  isAuditing
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'targets', label: 'Targets' },
    { id: 'assessments', label: 'Assessments' },
    { id: 'findings', label: 'Findings' },
    { id: 'attack-surface', label: 'Attack Surface' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'controls', label: 'Security Controls' },
    { id: 'remediation', label: 'Remediation' },
    { id: 'retesting', label: 'Retesting' },
    { id: 'reports', label: 'Reports' },
    { id: 'settings', label: 'Settings' }
  ];

  return (
    <header className="sticky top-0 z-50 bg-[#0a0f1d]/90 backdrop-blur-md border-b border-[#1f2d4d]">
      {/* Top Status Bar */}
      <div className="flex items-center justify-between px-6 py-2.5 border-b border-[#162238] text-xs">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5 font-mono font-semibold tracking-wider text-[#38bdf8]">
            <img
              src="/ntro-logo.png"
              alt="NTRO Emblem"
              className="h-7 w-auto object-contain filter drop-shadow-[0_0_8px_rgba(56,189,248,0.4)]"
              onError={(e) => {
                // Fallback if local image fails
                (e.target as HTMLImageElement).src = 'https://media.9curry.com/uploads/organization/image/1318/ntro-logo.png';
              }}
            />
            <span className="text-[#f8fafc] font-bold text-sm tracking-wide">NTRO SENTINELSHIELD</span>
            <span className="text-[#64748b]">•</span>
            <span className="text-[#94a3b8] text-[11px] hidden sm:inline">SECURITY ASSURANCE CONSOLE</span>
          </div>

          <div className="hidden md:flex items-center gap-2 pl-4 border-l border-[#1f2d4d]">
            <span className="text-[#64748b]">Environment:</span>
            <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 font-mono font-medium flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              SANDBOX ONLY
            </span>
          </div>

          <div className="hidden lg:flex items-center gap-2 pl-4 border-l border-[#1f2d4d]">
            <span className="text-[#64748b]">Target:</span>
            <span className="text-[#e2e8f0] font-mono">World Monitor</span>
          </div>
        </div>

        <div className="flex items-center gap-4 font-mono">
          <div className="flex items-center gap-2 bg-[#111827] px-3 py-1 rounded border border-[#1f2d4d]">
            <span className="text-[#94a3b8] text-[11px]">ASSURANCE SCORE:</span>
            <span className={`text-sm font-bold ${score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
              {score.toFixed(1)} / 100
            </span>
          </div>

          <button
            onClick={onRunQuickAudit}
            disabled={isAuditing}
            className="flex items-center gap-2 px-3 py-1 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 disabled:opacity-50 text-white font-medium rounded transition-all shadow-lg shadow-sky-500/20"
          >
            {isAuditing ? (
              <>
                <Cpu className="w-3.5 h-3.5 animate-spin" />
                <span>Auditing Sandbox...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Audit</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center px-6 overflow-x-auto no-scrollbar">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          const isDemo = item.id === 'demo-mode';
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`px-3.5 py-2.5 text-xs font-medium tracking-wide transition-colors relative whitespace-nowrap ${
                isActive
                  ? 'text-[#38bdf8] font-semibold'
                  : 'text-[#94a3b8] hover:text-[#f8fafc]'
              } ${isDemo ? 'text-emerald-400 font-semibold' : ''}`}
            >
              {item.label}
              {isActive && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#38bdf8] shadow-[0_0_8px_#38bdf8]" />
              )}
            </button>
          );
        })}
      </div>
    </header>
  );
};

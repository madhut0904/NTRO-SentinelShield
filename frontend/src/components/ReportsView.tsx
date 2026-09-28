import React, { useState } from 'react';
import { FileText, Download, CheckCircle2, Shield, Cpu, ExternalLink } from 'lucide-react';
import { Assessment, ReportItem } from '../types';

interface ReportsViewProps {
  assessment: Assessment | null;
  onGenerateReport: (type: 'PDF' | 'HTML' | 'JSON') => Promise<ReportItem>;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ assessment, onGenerateReport }) => {
  const [isGenerating, setIsGenerating] = useState<string | null>(null);
  const [reports, setReports] = useState<ReportItem[]>([
    {
      id: 'rep-1',
      assessment_id: assessment?.id || 'ass-latest',
      report_type: 'PDF',
      title: 'VAPT Security Assurance Executive Report (PDF)',
      file_path: '/reports/report_latest.pdf',
      content_summary: 'Comprehensive audit report with executive summary, CVSS scoring, SHA-256 evidence chain, and retest proofs.',
      generated_at: new Date().toISOString()
    },
    {
      id: 'rep-2',
      assessment_id: assessment?.id || 'ass-latest',
      report_type: 'HTML',
      title: 'Interactive Security Assurance Console Export (HTML)',
      file_path: '/reports/report_latest.html',
      content_summary: 'Self-contained interactive HTML security audit artifact.',
      generated_at: new Date().toISOString()
    },
    {
      id: 'rep-3',
      assessment_id: assessment?.id || 'ass-latest',
      report_type: 'JSON',
      title: 'Machine-Readable DevSecOps Telemetry (JSON)',
      file_path: '/reports/report_latest.json',
      content_summary: 'Structured JSON schema for CI/CD and SIEM ingestion.',
      generated_at: new Date().toISOString()
    }
  ]);

  const handleGenerate = async (type: 'PDF' | 'HTML' | 'JSON') => {
    setIsGenerating(type);
    try {
      const rep = await onGenerateReport(type);
      setReports((prev) => [rep, ...prev]);
    } finally {
      setIsGenerating(null);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-4">
        <div>
          <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
            <FileText className="w-4 h-4 text-sky-400" />
            Automated VAPT Report Generation Engine
          </h3>
          <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
            Generates standardized executive and technical security assurance dossiers.
          </p>
        </div>

        {/* Generate Actions */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => handleGenerate('PDF')}
            disabled={isGenerating !== null}
            className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded font-semibold transition-all flex items-center gap-1.5 shadow-lg shadow-sky-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isGenerating === 'PDF' ? 'Compiling PDF...' : 'Generate PDF'}</span>
          </button>
          <button
            onClick={() => handleGenerate('HTML')}
            disabled={isGenerating !== null}
            className="px-3 py-1.5 bg-[#111827] hover:bg-[#1a253c] text-sky-400 border border-[#1f2d4d] rounded font-semibold transition-all flex items-center gap-1.5"
          >
            <span>Generate HTML</span>
          </button>
          <button
            onClick={() => handleGenerate('JSON')}
            disabled={isGenerating !== null}
            className="px-3 py-1.5 bg-[#111827] hover:bg-[#1a253c] text-emerald-400 border border-[#1f2d4d] rounded font-semibold transition-all flex items-center gap-1.5"
          >
            <span>Generate JSON</span>
          </button>
        </div>
      </div>

      {/* Generated Reports List */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {reports.map((rep) => (
          <div key={rep.id} className="cyber-card p-5 flex flex-col justify-between space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className={`cyber-badge text-[10px] ${
                  rep.report_type === 'PDF' ? 'badge-critical' :
                  rep.report_type === 'HTML' ? 'badge-low' : 'badge-validated'
                }`}>
                  {rep.report_type} FORMAT
                </span>
                <span className="text-[10px] font-mono text-[#64748b]">
                  {new Date(rep.generated_at).toLocaleTimeString()}
                </span>
              </div>

              <h4 className="text-xs font-bold text-[#f8fafc]">{rep.title}</h4>
              <p className="text-[11px] text-[#94a3b8] leading-relaxed">{rep.content_summary}</p>
            </div>

            <div className="pt-3 border-t border-[#1f2d4d] flex items-center justify-between font-mono text-xs">
              <span className="text-emerald-400 text-[11px] flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Ready
              </span>
              <a
                href={rep.file_path || '#'}
                target="_blank"
                rel="noreferrer"
                download
                className="px-3 py-1 bg-[#0a0f1d] hover:bg-sky-600 hover:text-white text-sky-400 border border-[#1f2d4d] rounded text-[11px] flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3 h-3" />
                <span>Download</span>
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

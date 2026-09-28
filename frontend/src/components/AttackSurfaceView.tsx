import React, { useState } from 'react';
import { Layers, ShieldAlert, Cpu, Database, Lock, Globe, Server, ArrowRight } from 'lucide-react';
import { Endpoint } from '../types';

interface AttackSurfaceViewProps {
  endpoints: Endpoint[];
}

export const AttackSurfaceView: React.FC<AttackSurfaceViewProps> = ({ endpoints }) => {
  const [selectedNode, setSelectedNode] = useState<string>('dossier_service');

  const nodes = [
    {
      id: 'frontend',
      label: 'Web UI (Next.js / TypeScript)',
      type: 'LAYER',
      risk: 'LOW',
      icon: Globe,
      description: 'Public client application rendering real-time intelligence feeds.'
    },
    {
      id: 'api_gateway',
      label: 'API Gateway & Middleware',
      type: 'GATEWAY',
      risk: 'MEDIUM',
      icon: Server,
      description: 'Handles CORS, Rate Limiting, and Route Dispatching.'
    },
    {
      id: 'auth_service',
      label: 'Authentication & Session RBAC',
      type: 'SECURITY',
      risk: 'HIGH',
      icon: Lock,
      description: 'Validates JWT tokens, tenant identities, and role scopes.'
    },
    {
      id: 'dossier_service',
      label: 'Intel Dossiers Microservice',
      type: 'ENDPOINT',
      risk: 'CRITICAL',
      icon: Cpu,
      description: 'High-risk endpoint discovered with Broken Object Level Authorization (BOLA).'
    },
    {
      id: 'database',
      label: 'Database & Redis State Store',
      type: 'STORAGE',
      risk: 'LOW',
      icon: Database,
      description: 'Encrypted persistence store for telemetry and dossiers.'
    }
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Info */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-[#1f2d4d] pb-4">
        <div>
          <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
            <Layers className="w-4 h-4 text-sky-400" />
            Interactive Attack Surface Map
          </h3>
          <p className="text-xs text-[#94a3b8] font-mono mt-0.5">
            Automated repository architecture discovery & cross-layer trust boundaries.
          </p>
        </div>
      </div>

      {/* Visual Attack Surface Map */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {nodes.map((node) => {
          const Icon = node.icon;
          const isSelected = selectedNode === node.id;
          return (
            <div
              key={node.id}
              onClick={() => setSelectedNode(node.id)}
              className={`cyber-card p-5 cursor-pointer transition-all flex flex-col justify-between ${
                isSelected ? 'cyber-card-active' : ''
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded bg-[#0a0f1d] border border-[#1f2d4d]">
                    <Icon className="w-5 h-5 text-sky-400" />
                  </div>
                  <span className={`cyber-badge text-[10px] ${
                    node.risk === 'CRITICAL' ? 'badge-critical' :
                    node.risk === 'HIGH' ? 'badge-high' :
                    node.risk === 'MEDIUM' ? 'badge-medium' : 'badge-low'
                  }`}>
                    {node.risk} RISK
                  </span>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-[#f8fafc]">{node.label}</h4>
                  <span className="text-[10px] font-mono text-[#64748b] uppercase">{node.type}</span>
                </div>

                <p className="text-[11px] text-[#94a3b8] leading-relaxed">
                  {node.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-[#1f2d4d] flex items-center justify-between font-mono text-[10px] text-sky-400">
                <span>INSPECT NODE</span>
                <ArrowRight className="w-3 h-3" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Discovered Endpoints Catalog */}
      <div className="cyber-card p-5 space-y-4">
        <h3 className="text-sm font-semibold text-[#f8fafc] flex items-center gap-2">
          <Server className="w-4 h-4 text-emerald-400" />
          Discovered API Attack Surface Endpoints ({endpoints.length || 4})
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0a0f1d] border-b border-[#1f2d4d] font-mono uppercase text-[#94a3b8]">
              <tr>
                <th className="py-2.5 px-4">Method</th>
                <th className="py-2.5 px-4">Endpoint Path</th>
                <th className="py-2.5 px-4">Auth Requirement</th>
                <th className="py-2.5 px-4">Sensitive Fields</th>
                <th className="py-2.5 px-4">Risk Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f2d4d]">
              {(endpoints.length > 0 ? endpoints : [
                {
                  id: 'ep-1',
                  method: 'GET',
                  path: '/api/v1/user/intel-dossiers/{id}',
                  auth_required: true,
                  auth_mechanism: 'Bearer Token',
                  sensitive_fields: ['classified_notes', 'custom_alerts', 'owner_id'],
                  risk_level: 'CRITICAL' as const,
                  parameters: [],
                  assessment_id: '',
                  discovered_via: 'AST_ROUTER'
                },
                {
                  id: 'ep-2',
                  method: 'GET',
                  path: '/api/v1/intel/feeds',
                  auth_required: false,
                  auth_mechanism: 'None',
                  sensitive_fields: ['geopolitical_threat_level'],
                  risk_level: 'LOW' as const,
                  parameters: [],
                  assessment_id: '',
                  discovered_via: 'AST_ROUTER'
                }
              ]).map((ep) => (
                <tr key={ep.id} className="hover:bg-[#141e33] font-mono">
                  <td className="py-2.5 px-4 font-bold text-sky-400">{ep.method}</td>
                  <td className="py-2.5 px-4 text-[#f8fafc]">{ep.path}</td>
                  <td className="py-2.5 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] ${
                      ep.auth_required ? 'bg-sky-950 text-sky-400 border border-sky-800' : 'bg-slate-800 text-[#94a3b8]'
                    }`}>
                      {ep.auth_mechanism || (ep.auth_required ? 'JWT Token' : 'Public')}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-amber-400 text-[11px]">
                    {ep.sensitive_fields?.join(', ') || 'None'}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className={`cyber-badge text-[10px] ${
                      ep.risk_level === 'CRITICAL' ? 'badge-critical' :
                      ep.risk_level === 'HIGH' ? 'badge-high' : 'badge-low'
                    }`}>
                      {ep.risk_level}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

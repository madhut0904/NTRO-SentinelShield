"""
NTRO SentinelShield - Automated Security Report Generation Service
Generates comprehensive VAPT & Continuous Assurance Reports in PDF, HTML, and JSON formats.
"""
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

class ReportService:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json_report(self, assessment_data: Dict[str, Any]) -> str:
        report_id = f"report_{assessment_data.get('id', 'latest')}.json"
        file_path = os.path.join(self.output_dir, report_id)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(assessment_data, f, indent=2, default=str)
        return file_path

    def generate_html_report(self, assessment_data: Dict[str, Any]) -> str:
        report_id = f"report_{assessment_data.get('id', 'latest')}.html"
        file_path = os.path.join(self.output_dir, report_id)
        
        findings_html = ""
        for f in assessment_data.get("findings", []):
            sev_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6"
            }.get(f.get("severity", "LOW"), "#94a3b8")
            
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-code">{f.get('finding_code')}</span>
                    <span class="badge" style="background-color: {sev_color}">{f.get('severity')}</span>
                    <span class="confidence-badge">{f.get('confidence')}</span>
                    <h3 style="margin: 8px 0;">{f.get('title')}</h3>
                </div>
                <p><strong>CWE:</strong> {f.get('cwe')} | <strong>CVSS Base Score:</strong> {f.get('cvss_score')}</p>
                <p>{f.get('description')}</p>
                <div class="code-box"><code>{f.get('code_snippet', 'N/A')}</code></div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTRO SentinelShield - Security Assurance Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: auto; background: #1e293b; padding: 32px; border-radius: 12px; border: 1px solid #334155; }}
        .header {{ border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 24px; }}
        .score-box {{ background: #0f172a; border-left: 4px solid #10b981; padding: 16px; border-radius: 6px; margin-bottom: 24px; }}
        .finding-card {{ background: #0f172a; border: 1px solid #334155; padding: 20px; border-radius: 8px; margin-bottom: 16px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; color: white; }}
        .confidence-badge {{ background: #10b981; color: #0f172a; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 8px; }}
        .code-box {{ background: #020617; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #38bdf8; overflow-x: auto; margin-top: 10px; }}
        .footer {{ margin-top: 40px; font-size: 12px; color: #94a3b8; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0; color: #38bdf8;">NTRO SentinelShield</h1>
            <p style="margin: 4px 0 0 0; color: #94a3b8;">Security Assessment & Continuous Assurance Report — World Monitor Sandbox</p>
            <p style="font-size: 13px; color: #64748b;">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Environment: ISOLATED SANDBOX</p>
        </div>
        
        <div class="score-box">
            <h2 style="margin: 0; color: #10b981;">Security Assurance Score: {assessment_data.get('assurance_score', 82.0)} / 100</h2>
            <p style="margin: 6px 0 0 0; color: #cbd5e1;">Target: {assessment_data.get('target', {}).get('name', 'World Monitor Local Sandbox')} ({assessment_data.get('target', {}).get('target_url', 'http://localhost:8080')})</p>
        </div>

        <h2>Executive Summary</h2>
        <p>This automated security assurance assessment was executed strictly against an authorized, isolated digital twin sandbox. Cross-layer correlation verified static AST findings with active runtime identity probes.</p>

        <h2>Validated Findings ({len(assessment_data.get('findings', []))})</h2>
        {findings_html}

        <div class="footer">
            <p>CONFIDENTIAL — FOR AUTHORIZED AUDIT & SIH DEMONSTRATION USE ONLY. NOT FOR PRODUCTION ATTACK.</p>
        </div>
    </div>
</body>
</html>"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return file_path

    def generate_pdf_report(self, assessment_data: Dict[str, Any]) -> str:
        report_id = f"report_{assessment_data.get('id', 'latest')}.pdf"
        file_path = os.path.join(self.output_dir, report_id)
        
        if not HAS_REPORTLAB:
            # Fallback to HTML if reportlab is unavailable
            return self.generate_html_report(assessment_data)

        doc = SimpleDocTemplate(file_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#475569'),
            spaceAfter=14
        )
        heading2_style = ParagraphStyle(
            'Heading2Style',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#334155'),
            spaceAfter=6
        )

        elements = []
        elements.append(Paragraph("NTRO SentinelShield", title_style))
        elements.append(Paragraph("Security Assessment & Assurance Report — World Monitor Sandbox", subtitle_style))
        elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Environment: ISOLATED SANDBOX", subtitle_style))
        elements.append(Spacer(1, 10))

        # Executive Summary Box
        score_val = assessment_data.get('assurance_score', 82.0)
        summary_text = f"<b>Security Assurance Score: {score_val}/100</b><br/>Target: {assessment_data.get('target', {}).get('name', 'World Monitor Sandbox')}<br/>Findings Validated: {len(assessment_data.get('findings', []))}"
        
        score_table = Table([[Paragraph(summary_text, body_style)]], colWidths=[540])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(score_table)
        elements.append(Spacer(1, 14))

        elements.append(Paragraph("Executive Summary & Methodology", heading2_style))
        elements.append(Paragraph("This assessment was executed strictly against an isolated sandbox environment. The SentinelShield Cross-Layer Correlation Engine synthesized static code analysis (SAST), API route discovery, multi-identity authorization tests, and dynamic runtime evidence into verified security controls.", body_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("Validated Security Findings", heading2_style))
        for f in assessment_data.get("findings", []):
            finding_text = f"<b>[{f.get('finding_code')}] {f.get('title')}</b><br/>Severity: {f.get('severity')} | CVSS: {f.get('cvss_score')} | Confidence: {f.get('confidence')}<br/>{f.get('description')}<br/><i>Remediation: {f.get('remediation', {}).get('recommended_fix', 'Enforce access checks')}</i>"
            t = Table([[Paragraph(finding_text, body_style)]], colWidths=[540])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
                ('PADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 8))

        doc.build(elements)
        return file_path

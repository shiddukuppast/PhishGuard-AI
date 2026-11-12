import io
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import inch
from app.models.scan import ScanModel


class ReportService:
    @staticmethod
    def generate_pdf_report(scan_data: Dict[str, Any]) -> io.BytesIO:
        """
        Generate a professional PDF report using ReportLab.
        Contains executive summary, classification, risk gauge metrics,
        indicator table, ML status, threat intel, and actionable guidance.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        styles = getSampleStyleSheet()

        # Custom cybersecurity dark/cyan accents on white paper background
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0B1120"),
        )

        tagline_style = ParagraphStyle(
            "Tagline",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0891B2"),
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0B1120"),
            spaceBefore=10,
            spaceAfter=4,
        )

        body_style = ParagraphStyle(
            "DocBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        )

        code_style = ParagraphStyle(
            "CodeFont",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0F172A"),
        )

        elements = []

        # Header Title
        elements.append(Paragraph("<b>PHISHGUARD AI</b> — Security Analysis Report", title_style))
        elements.append(Paragraph("DETECT. ANALYZE. PROTECT. | Autonomous Threat Intelligence", tagline_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#06B6D4"), spaceAfter=12))

        # Metadata Table
        classification = scan_data.get("classification", "UNKNOWN")
        risk_score = scan_data.get("risk_score", 0)
        risk_level = scan_data.get("risk_level", "LOW")

        badge_color = colors.HexColor("#10B981")  # Emerald
        if classification == "PHISHING":
            badge_color = colors.HexColor("#EF4444")  # Red
        elif classification == "SUSPICIOUS":
            badge_color = colors.HexColor("#F59E0B")  # Amber

        created_str = str(scan_data.get("created_at", datetime.now(timezone.utc)))

        meta_data = [
            [
                Paragraph("<b>Target URL:</b>", body_style),
                Paragraph(scan_data.get("original_url", ""), code_style),
            ],
            [
                Paragraph("<b>Target Domain:</b>", body_style),
                Paragraph(scan_data.get("domain", ""), code_style),
            ],
            [
                Paragraph("<b>Classification:</b>", body_style),
                Paragraph(f"<b>{classification}</b> ({risk_level} RISK)", ParagraphStyle("C", parent=body_style, textColor=badge_color)),
            ],
            [
                Paragraph("<b>Risk Score:</b>", body_style),
                Paragraph(f"<b>{risk_score} / 100</b>", ParagraphStyle("S", parent=body_style, textColor=badge_color)),
            ],
            [
                Paragraph("<b>Scan Timestamp:</b>", body_style),
                Paragraph(created_str, body_style),
            ],
            [
                Paragraph("<b>Scan ID:</b>", body_style),
                Paragraph(str(scan_data.get("id") or scan_data.get("_id") or "N/A"), code_style),
            ],
        ]

        meta_table = Table(meta_data, colWidths=[1.6 * inch, 5.4 * inch])
        meta_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 12))

        # Executive Explanation
        elements.append(Paragraph("1. Executive Threat Assessment", h2_style))
        explanation_text = scan_data.get("explanation", "Analysis completed without critical findings.")
        elements.append(Paragraph(explanation_text, body_style))
        elements.append(Spacer(1, 10))

        # Security Indicators
        elements.append(Paragraph("2. Security Indicator Checks", h2_style))
        indicators = scan_data.get("security_indicators", [])
        if indicators:
            ind_rows = [["Indicator", "Status", "Severity", "Details"]]
            for ind in indicators:
                status_color = colors.HexColor("#10B981") if ind.get("status") == "safe" else colors.HexColor("#EF4444")
                ind_rows.append([
                    Paragraph(f"<b>{ind.get('name', '')}</b>", body_style),
                    Paragraph(f"<b>{ind.get('status', '').upper()}</b>", ParagraphStyle("st", parent=body_style, textColor=status_color)),
                    ind.get("severity", "Low"),
                    Paragraph(ind.get("description", ""), body_style),
                ])
            ind_table = Table(ind_rows, colWidths=[1.8 * inch, 0.9 * inch, 0.9 * inch, 3.4 * inch])
            ind_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1120")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            elements.append(ind_table)
        else:
            elements.append(Paragraph("No individual indicators evaluated.", body_style))
        elements.append(Spacer(1, 10))

        # Machine Learning & Threat Intelligence Telemetry
        elements.append(Paragraph("3. ML Engine & Threat Intelligence Status", h2_style))
        ml_data = scan_data.get("model_prediction", {})
        ml_msg = ml_data.get("message", "Model status not provided.")
        ml_avail = "Available / Active" if ml_data.get("available") else "Unavailable (Rule-based heuristics applied)"

        ti_data = scan_data.get("threat_intelligence", {})
        pt_status = ti_data.get("phishtank", {}).get("message", "Service unconfigured")
        op_status = ti_data.get("openphish", {}).get("message", "Service unconfigured")

        telemetry_rows = [
            [Paragraph("<b>ML Model Status:</b>", body_style), Paragraph(ml_avail, body_style)],
            [Paragraph("<b>ML Inference Note:</b>", body_style), Paragraph(ml_msg, body_style)],
            [Paragraph("<b>PhishTank Feed:</b>", body_style), Paragraph(pt_status, body_style)],
            [Paragraph("<b>OpenPhish Feed:</b>", body_style), Paragraph(op_status, body_style)],
        ]
        telemetry_table = Table(telemetry_rows, colWidths=[1.8 * inch, 5.2 * inch])
        telemetry_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ])
        )
        elements.append(telemetry_table)
        elements.append(Spacer(1, 10))

        # Recommendations
        elements.append(Paragraph("4. Recommended Security Actions", h2_style))
        recs = scan_data.get("recommendations", [])
        if recs:
            for i, rec in enumerate(recs, start=1):
                elements.append(Paragraph(f"• <b>[{i}]</b> {rec}", body_style))
        else:
            elements.append(Paragraph("• Standard browsing hygiene applies.", body_style))

        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=6))
        elements.append(Paragraph(
            "Notice: PhishGuard AI provides automated heuristic and probabilistic assessments. "
            "Report compiled for SOC and digital security analysis.",
            ParagraphStyle("Disclaimer", parent=styles["Normal"], fontName="Helvetica", fontSize=7, textColor=colors.HexColor("#64748B"))
        ))

        doc.build(elements)
        buffer.seek(0)
        return buffer


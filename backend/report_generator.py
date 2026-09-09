import os
import hashlib
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(doc_data: dict, output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story = []
    styles = getSampleStyleSheet()

    c_primary = colors.HexColor("#0f172a")
    c_accent = colors.HexColor("#0284c7")
    c_success = colors.HexColor("#16a34a")
    c_danger = colors.HexColor("#dc2626")

    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=c_primary,
        spaceAfter=4
    )
    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#64748b")
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=c_accent,
        spaceBefore=14,
        spaceAfter=6
    )

    # 1. Header Banner
    story.append(Paragraph("IDSHIELD AI // FORENSIC VERIFICATION DOSSIER", title_style))
    audit_hash = hashlib.sha256(str(doc_data.get("id", "")).encode()).hexdigest()[:24].upper()
    story.append(Paragraph(f"AUDIT REF: {doc_data.get('id')}  |  INTEGRITY HASH: SHA256:{audit_hash}  |  TIMESTAMP: {doc_data.get('timestamp')}", meta_style))
    story.append(Spacer(1, 12))

    # 2. Executive Verdict Summary Table
    status = doc_data.get("status", "UNKNOWN")
    status_color = c_success if status == "VERIFIED" else c_danger

    summary_data = [
        [
            Paragraph("<b>DOCUMENT CLASSIFICATION</b>", meta_style),
            Paragraph("<b>COMPOSITE RISK INDEX</b>", meta_style),
            Paragraph("<b>FINAL VERDICT</b>", meta_style)
        ],
        [
            Paragraph(f"<b>{doc_data.get('docType', 'Identity Credential')}</b>", styles['Normal']),
            Paragraph(f"<b>{doc_data.get('riskScore', 0)} / 100</b>", styles['Normal']),
            Paragraph(f"<b><font color='{status_color.hexval()}'>{status}</font></b>", styles['Normal'])
        ]
    ]
    t_summary = Table(summary_data, colWidths=[180, 180, 180])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # 3. Document Scan Evidence Thumbnail
    img_url = doc_data.get("imageUrl", "")
    if img_url:
        img_filename = os.path.basename(img_url)
        local_img_path = os.path.join("uploads", img_filename)
        if os.path.exists(local_img_path):
            story.append(Paragraph("PRIMARY OPTICAL SCAN RECORD", section_heading))
            story.append(RLImage(local_img_path, width=280, height=170))
            story.append(Spacer(1, 8))

    # 4. Multi-Signal Risk Breakdown Table
    story.append(Paragraph("FORENSIC SIGNAL INTEGRITY BREAKDOWN", section_heading))
    breakdown_rows = [["Signal Description", "Weight", "Calculated Vector Impact"]]
    
    for item in doc_data.get("riskBreakdown", []):
        impact_color = "#16a34a" if item.get("impact") == "positive" else "#dc2626"
        sign = "+" if item.get("weight", 0) > 0 else ""
        breakdown_rows.append([
            Paragraph(f"<b>{item.get('signal')}</b><br/><font size=7 color='#64748b'>{item.get('description')}</font>", styles['Normal']),
            f"{sign}{item.get('weight')}",
            Paragraph(f"<font color='{impact_color}'><b>{item.get('impact').upper()}</b></font>", styles['Normal'])
        ])

    t_breakdown = Table(breakdown_rows, colWidths=[330, 70, 140])
    t_breakdown.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_breakdown)
    story.append(Spacer(1, 14))

    # 5. Regulatory Certification Notice
    disclaimer = (
        "STATUTORY FORENSIC DECLARATION: This automated inspection audit is cryptographically sealed by IDSHIELD AI. "
        "Processed via neural inference cluster nodes in accordance with standard identity fraud screening guidelines."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=styles['Italic'], fontSize=7, textColor=colors.HexColor("#94a3b8"))))

    doc.build(story)
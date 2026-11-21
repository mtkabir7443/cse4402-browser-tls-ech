"""Render a course specification or measurement report from its Markdown source."""
from pathlib import Path
from html import escape
import re
import argparse
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
args_parser = argparse.ArgumentParser()
args_parser.add_argument('--source', default='design.md')
args_parser.add_argument('--output', default='CSE4402_TLS_ECH_Design_Nov22.pdf')
args_parser.add_argument('--label', default='Design and methods')
args_parser.add_argument('--output-dir', type=Path, help='Write a separate edition and its extracted text here.')
args = args_parser.parse_args()
out_dir = args.output_dir or ROOT / "output" / "pdf"
OUT = out_dir / args.output
OUT.parent.mkdir(parents=True, exist_ok=True)
kind = Path(args.source).stem
is_report = kind == "report"
is_design = kind == "design"
INK = colors.HexColor("#262521")
MUTED = colors.HexColor("#57534E")
RULE = colors.HexColor("#C7C3BB")
PAPER_TINT = colors.HexColor("#F3F1ED")
DNS_INK = colors.HexColor("#453B76")
TLS_INK = colors.HexColor("#864323")
ECH_INK = colors.HexColor("#20553D")
ECH_TINT = colors.HexColor("#EAF2EC")
heading_font = "Times-Bold" if is_report else "Helvetica-Bold"
body_font = "Times-Roman" if is_report else "Helvetica"
# The letter-size page has 45 pt margins and 6 pt of frame padding per side.
W = 510

styles = {
    "body": ParagraphStyle("body", fontName=body_font, fontSize=11 if is_report else 9.9, leading=14 if is_report else 13, spaceAfter=6, textColor=INK),
    "title": ParagraphStyle("title", fontName=heading_font, fontSize=25 if is_report else 23, leading=28, spaceAfter=9, textColor=INK),
    "h2": ParagraphStyle("h2", fontName=heading_font, fontSize=15 if is_report else 13.4, leading=17, spaceBefore=9, spaceAfter=7, textColor=INK, keepWithNext=True),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.8, leading=11.3, textColor=INK),
    "thead": ParagraphStyle("thead", fontName="Helvetica-Bold", fontSize=8.8, leading=11.3, textColor=INK),
    "ref": ParagraphStyle("ref", fontName="Helvetica", fontSize=8.4, leading=10.8, spaceAfter=4, textColor=MUTED),
}
styles["count"] = ParagraphStyle("count", parent=styles["cell"], alignment=TA_CENTER)
styles["result_head"] = ParagraphStyle("result_head", parent=styles["thead"], alignment=TA_CENTER)
styles["accepted"] = ParagraphStyle("accepted", parent=styles["count"], fontName="Helvetica-Bold", textColor=ECH_INK)

def inline(text):
    text = text.replace('\u2011', '-').replace('\u2013', '-').replace('\u2014', '-')
    text = escape(text)
    links = {}
    def marked_link(m):
        token = f'LINKPLACEHOLDER{len(links)}END'
        links[token] = f'<link href="{m.group(2)}" color="{INK.hexval()}"><u>{m.group(1)}</u></link>'
        return token
    text = re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', marked_link, text)
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`(.*?)`", r'<font name="Helvetica" size="8.5">\1</font>', text)
    # Short, readable source labels remain in the PDF; targets are clickable.
    def link(m):
        url = m.group(0)
        return f'<link href="{url}" color="{INK.hexval()}"><u>{url}</u></link>'
    text = re.sub(r"https?://[^\s<]+", link, text)
    for token, value in links.items(): text = text.replace(token, value)
    return text

class Architecture(Flowable):
    def __init__(self):
        super().__init__(); self.width=W; self.height=112
    def draw(self):
        c=self.canv
        def box(x,y,w,h,lines,edge=RULE):
            c.setStrokeColor(edge); c.setFillColor(colors.white)
            c.setLineWidth(1 if edge != RULE else 0.65)
            c.rect(x,y,w,h,fill=1,stroke=1)
            for n,line in enumerate(lines):
                c.setFillColor(edge if n == 0 and edge != RULE else INK)
                c.setFont("Helvetica-Bold" if n==0 else "Helvetica",9 if n==0 else 8)
                c.drawCentredString(x+w/2,y+h-15-n*12,line)
        def arrow(x1,y1,x2,y2,shade,dashed=False):
            c.setStrokeColor(shade);c.setFillColor(shade);c.setLineWidth(1)
            if dashed:
                c.setDash(3, 2)
            c.line(x1,y1,x2,y2)
            c.setDash()
            import math
            a=math.atan2(y2-y1,x2-x1)
            p=c.beginPath();p.moveTo(x2,y2)
            for d in (0.45,-0.45):p.lineTo(x2-6*math.cos(a+d),y2-6*math.sin(a+d))
            p.close();c.drawPath(p,fill=1,stroke=0)
        box(0,27,114,63,["Isolated browser","Page + fresh profile","Actual TLS client"])
        dns = DNS_INK if is_design else MUTED
        tls = TLS_INK if is_design else INK
        box(154,66,174,43,["Private DoH service","A + HTTPS/ECH records"],dns)
        box(154,9,174,45,["Controlled TLS endpoints","Go + Node/OpenSSL","Version / suite / ECH"],tls)
        box(369,27,W-369,63,["Results and evidence","Page + IP-tagged JSONL","All-browser comparison"])
        arrow(114,76,154,86,dns,dashed=is_design);arrow(154,70,114,62,dns,dashed=is_design)
        arrow(114,43,154,30,tls);arrow(328,31,369,44,MUTED)
        c.setFillColor(MUTED);c.setFont("Helvetica",7.5)
        c.drawCentredString(W/2,-1,"The browser contacts the TLS endpoint; DNS discovery is a separate exchange.")

def table(lines):
    rows=[[v.strip() for v in line.strip().strip('|').split('|')] for line in lines]
    rows=[r for r in rows if not all(re.fullmatch(r"[: -]+",x) for x in r)]
    n=len(rows[0])
    matrix = is_report and rows[0][:3] == ["Case", "Ch", "FF"]
    if n>3: widths=[43]+[(W-43)/(n-1)]*(n-1)
    elif n==3 and rows[0][0] in ("ID", "Case"): widths=[43,210,W-253]
    elif n==3: widths=[148,197,W-345]
    elif rows[0][0]=="Table code": widths=[70,W-70]
    elif rows[0][0]=="Planned build": widths=[134,W-134]
    else: widths=[158,W-158]
    def style_for(i, j, value):
        if i == 0:
            return styles["result_head" if matrix and j else "thead"]
        if matrix and j:
            # E and REC are the two measured outcomes with accepted ECH.
            return styles["accepted" if value.split()[0] in {"E", "REC"} else "count"]
        return styles["cell"]
    data=[[Paragraph(inline(x),style_for(i,j,x)) for j,x in enumerate(row)] for i,row in enumerate(rows)]
    t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
    rules = [
        ('BACKGROUND',(0,0),(-1,0),PAPER_TINT),('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LINEABOVE',(0,0),(-1,0),1,INK),
        ('LINEBELOW',(0,0),(-1,-1),0.35,RULE),
    ]
    if matrix:
        for i,row in enumerate(rows[1:],1):
            if row[0] in {"C1","E1"}:
                rules.append(('LINEABOVE',(0,i),(-1,i),0.85,MUTED))
            for j,value in enumerate(row[1:],1):
                if value.split()[0] in {"E","REC"}:
                    rules.append(('BACKGROUND',(j,i),(j,i),ECH_TINT))
    t.setStyle(TableStyle(rules))
    return t

def footer(c,doc):
    c.saveState();c.setStrokeColor(RULE);c.setLineWidth(0.5);c.line(51,35,51+W,35)
    c.setFont('Helvetica',8);c.setFillColor(MUTED)
    c.drawString(51,23,'CSE 4402  |  Mohammed Kabir  |  '+args.label)
    c.drawRightString(51+W,23,f'{doc.page}')
    c.restoreState()

lines=(ROOT/args.source).read_text(encoding='utf-8').splitlines()
story=[];i=0;refs=False
while i<len(lines):
    line=lines[i].strip()
    if not line: i+=1;continue
    if line=='<!-- PAGEBREAK -->':story.append(PageBreak());i+=1;continue
    if line=='<!-- ARCHITECTURE -->':story.extend([Architecture(),Spacer(1,7)]);i+=1;continue
    if line.startswith('# '):story.append(Paragraph(inline(line[2:]),styles['title']));i+=1;continue
    if line.startswith('### '):story.append(Paragraph(inline(line[4:]),styles['h2']));i+=1;continue
    if line.startswith('## '):
        refs=line[3:]=='References';story.append(Paragraph(inline(line[3:]),styles['h2']));i+=1;continue
    if line.startswith('|'):
        block=[]
        while i<len(lines) and lines[i].strip().startswith('|'):block.append(lines[i]);i+=1
        story.extend([table(block),Spacer(1,7)]);continue
    para=[line];i+=1
    while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','|','<!--')):
        if re.match(r'^\d+\. ',lines[i]):break
        para.append(lines[i].strip());i+=1
    story.append(Paragraph(inline(' '.join(para)),styles['ref' if refs else 'body']))

doc=SimpleDocTemplate(str(OUT),pagesize=letter,rightMargin=45,leftMargin=45,topMargin=39,bottomMargin=46,
    title='Browser TLS and ECH Compatibility Testbed: '+args.label,author='Mohammed Kabir',
    subject='CSE 4402 solo project')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
reader=PdfReader(OUT)
text='\n\n'.join(p.extract_text() or '' for p in reader.pages)
text_dir = out_dir if args.output_dir else ROOT/'output'
(text_dir/(Path(args.source).stem+'-extracted.txt')).write_text(text,encoding='utf-8')
print(f'Created {OUT}; pages={len(reader.pages)}; characters={len(text)}')

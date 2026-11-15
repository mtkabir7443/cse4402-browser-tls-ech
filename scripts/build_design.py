"""Render the reviewed Markdown design to a printable, four-page PDF."""
from pathlib import Path
from html import escape
import re
import argparse
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
args_parser = argparse.ArgumentParser()
args_parser.add_argument('--source', default='design.md')
args_parser.add_argument('--output', default='CSE4402_TLS_ECH_Design_Nov22.pdf')
args_parser.add_argument('--label', default='Design and methods')
args = args_parser.parse_args()
OUT = ROOT / "output" / "pdf" / args.output
OUT.parent.mkdir(parents=True, exist_ok=True)
NAVY = colors.HexColor("#15374d")
TEAL = colors.HexColor("#167b84")
PALE = colors.HexColor("#edf4f6")
GREY = colors.HexColor("#52636c")
W = 522

styles = {
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.6, leading=12.5, spaceAfter=6, textColor=NAVY),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=22, leading=25, spaceAfter=10, textColor=NAVY),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12.8, leading=16, spaceBefore=8, spaceAfter=7, textColor=TEAL, keepWithNext=True),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.8, leading=11.4, textColor=NAVY),
    "thead": ParagraphStyle("thead", fontName="Helvetica-Bold", fontSize=8.8, leading=11.4, textColor=colors.white),
    "ref": ParagraphStyle("ref", fontName="Helvetica", fontSize=8.2, leading=10.5, spaceAfter=4, textColor=GREY),
}

def inline(text):
    text = text.replace('\u2011', '-').replace('\u2013', '-').replace('\u2014', '-')
    text = escape(text)
    links = {}
    def marked_link(m):
        token = f'LINKPLACEHOLDER{len(links)}END'
        links[token] = f'<link href="{m.group(2)}" color="#167b84">{m.group(1)}</link>'
        return token
    text = re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', marked_link, text)
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`(.*?)`", r'<font name="Helvetica" size="8.5">\1</font>', text)
    # Short, readable source labels remain in the PDF; targets are clickable.
    def link(m):
        url = m.group(0)
        return f'<link href="{url}" color="#167b84">{url}</link>'
    text = re.sub(r"https?://[^\s<]+", link, text)
    for token, value in links.items(): text = text.replace(token, value)
    return text

class Architecture(Flowable):
    def __init__(self):
        super().__init__(); self.width=W; self.height=112
    def draw(self):
        c=self.canv
        def box(x,y,w,h,lines):
            c.setStrokeColor(colors.HexColor("#a8c7cd"));c.setFillColor(PALE)
            c.roundRect(x,y,w,h,5,fill=1,stroke=1)
            c.setFillColor(NAVY)
            for n,line in enumerate(lines):
                c.setFont("Helvetica-Bold" if n==0 else "Helvetica",9 if n==0 else 8)
                c.drawCentredString(x+w/2,y+h-15-n*12,line)
        def arrow(x1,y1,x2,y2):
            c.setStrokeColor(TEAL);c.setFillColor(TEAL);c.setLineWidth(1)
            c.line(x1,y1,x2,y2)
            import math
            a=math.atan2(y2-y1,x2-x1)
            p=c.beginPath();p.moveTo(x2,y2)
            for d in (0.45,-0.45):p.lineTo(x2-6*math.cos(a+d),y2-6*math.sin(a+d))
            p.close();c.drawPath(p,fill=1,stroke=0)
        box(0,27,114,63,["Isolated browser","Page + fresh profile","Actual TLS client"])
        box(154,66,174,43,["Private DoH service","A + HTTPS/ECH records"])
        box(154,7,174,47,["Controlled TLS endpoints","Go + Node/OpenSSL","Version / suite / ECH"])
        box(371,27,151,63,["Results and evidence","Page + IP-tagged JSONL","All-browser comparison"])
        arrow(114,76,154,86);arrow(154,70,114,62)
        arrow(114,43,154,30);arrow(328,31,371,44)
        c.setFillColor(GREY);c.setFont("Helvetica",7)
        c.drawCentredString(261,0,"The browser contacts the TLS endpoint; DNS discovery is a separate exchange.")

def table(lines):
    rows=[[v.strip() for v in line.strip().strip('|').split('|')] for line in lines]
    rows=[r for r in rows if not all(re.fullmatch(r"[: -]+",x) for x in r)]
    n=len(rows[0])
    if n>3: widths=[43]+[(W-43)/(n-1)]*(n-1)
    elif n==3 and rows[0][0] in ("ID", "Case"): widths=[43,218,261]
    elif n==3: widths=[152,205,165]
    elif rows[0][0]=="Table code": widths=[70,452]
    elif rows[0][0]=="Planned build": widths=[134,388]
    else: widths=[170,352]
    data=[[Paragraph(inline(x),styles['thead' if i==0 else 'cell']) for x in row] for i,row in enumerate(rows)]
    t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),NAVY),('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),
        ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),
        ('LINEBELOW',(0,-1),(-1,-1),0.5,colors.HexColor('#aec5cc')),
    ]))
    return t

def footer(c,doc):
    c.saveState();c.setStrokeColor(colors.HexColor('#c8d5dc'));c.line(45,35,567,35)
    c.setFont('Helvetica',8);c.setFillColor(GREY)
    c.drawString(45,23,'CSE 4402  |  Mohammed Kabir  |  '+args.label)
    c.drawRightString(567,23,f'{doc.page}')
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
(ROOT/'output'/(Path(args.source).stem+'-extracted.txt')).write_text(text,encoding='utf-8')
print(f'Created {OUT}; pages={len(reader.pages)}; characters={len(text)}')

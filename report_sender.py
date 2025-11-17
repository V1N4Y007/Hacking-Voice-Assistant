# report_sender.py
import os
import tempfile
import datetime
import smtplib
from email.message import EmailMessage

# Try import reportlab; if not available we'll fall back to text
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


def generate_pdf_report(text: str, output_path: str):
    """
    Generate a simple PDF containing `text`.
    If reportlab isn't available, write a .txt instead (output_path will be used).
    """
    if REPORTLAB_AVAILABLE:
        c = canvas.Canvas(output_path, pagesize=A4)
        width, height = A4
        left_margin = 15 * mm
        top = height - 20 * mm
        line_height = 7.5  # points

        # Header
        c.setFont("Helvetica-Bold", 14)
        c.drawString(left_margin, top, "HackSpeak - Session Report")
        c.setFont("Helvetica", 9)
        c.drawString(left_margin, top - 14, f"Generated: {datetime.datetime.now().isoformat(sep=' ', timespec='seconds')}")
        y = top - 30

        # Body (wrap lines)
        c.setFont("Courier", 8)
        max_width = width - left_margin * 2
        # split text into lines that fit
        for paragraph in text.splitlines():
            # naive wrapping
            words = paragraph.split(" ")
            line = ""
            for w in words:
                test = (line + " " + w).strip()
                if c.stringWidth(test, "Courier", 8) > max_width:
                    c.drawString(left_margin, y, line)
                    y -= line_height
                    line = w
                    if y < 20 * mm:
                        c.showPage()
                        c.setFont("Courier", 8)
                        y = height - 20 * mm
                else:
                    line = test
            if line:
                c.drawString(left_margin, y, line)
                y -= line_height
            # small gap between paragraphs
            y -= 2
            if y < 20 * mm:
                c.showPage()
                c.setFont("Courier", 8)
                y = height - 20 * mm

        c.save()
        return output_path
    else:
        # fallback: write plain text file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("HackSpeak - Session Report\n")
            f.write("Generated: " + datetime.datetime.now().isoformat(sep=' ', timespec='seconds') + "\n\n")
            f.write(text)
        return output_path


def send_email_with_attachment(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
                               from_addr: str, to_addrs: list, subject: str, body: str, attachment_path: str):
    """
    Send email with attachment_path. Raises exceptions on failures.
    """
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, (list, tuple)) else to_addrs
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach file (binary)
    with open(attachment_path, "rb") as f:
        data = f.read()
    # choose mime type by extension (simple heuristic)
    if attachment_path.lower().endswith(".pdf"):
        maintype, subtype = "application", "pdf"
    else:
        maintype, subtype = "text", "plain"

    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=os.path.basename(attachment_path))

    # Send via SMTP with STARTTLS
    server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(smtp_user, smtp_pass)
    server.send_message(msg)
    server.quit()

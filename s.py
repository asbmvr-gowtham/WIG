import socket
import requests
import ssl
import whois
import json
from tkinter import *
from tkinter import ttk, messagebox
from fpdf import FPDF
import dns.resolver

# Helper functions
def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error: {e}"

def get_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return "\n".join([f"{key}: {value}" for key, value in response.headers.items()])
    except Exception as e:
        return f"Error: {e}"

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            return json.dumps(s.getpeercert(), indent=2)
    except Exception as e:
        return f"Error: {e}"

def get_whois_info(domain):
    try:
        return str(whois.whois(domain))
    except Exception as e:
        return f"Error: {e}"

def get_dns_records(domain):
    try:
        record_types = ["A", "AAAA", "MX", "CNAME", "NS"]
        records = []
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=3)
                for rdata in answers:
                    records.append(f"{rtype}: {rdata.to_text()}")
                    if len(records) == 10:
                        return "\n".join(records)
            except Exception:
                pass
        return "\n".join(records[:10]) if records else "No DNS records found."
    except Exception as e:
        return f"Error: {e}"

# PDF generation
def generate_pdf_report(domain, ip, headers, ssl_info, whois_info, dns_records):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.set_fill_color(0, 102, 204)
    pdf.cell(0, 10, "Domain Information Report", align="C", ln=1, fill=True)
    pdf.ln(10)

    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Domain: {domain}", ln=1)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "IP Address:", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 10, ip)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "HTTP Headers:", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 10, headers)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "SSL Information:", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 10, ssl_info)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "WHOIS Information:", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 10, whois_info)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "DNS Records (First 10):", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 10, dns_records)
    pdf.ln(5)

    filename = f"{domain}_report.pdf"
    pdf.output(filename)
    messagebox.showinfo("Success", f"Report generated: {filename}")

# GUI Application
def fetch_and_generate():
    domain = entry_domain.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain name.")
        return

    try:
        ip = get_ip_address(domain)
        headers = get_http_headers(domain)
        ssl_info = get_ssl_info(domain)
        whois_info = get_whois_info(domain)
        dns_records = get_dns_records(domain)

        generate_pdf_report(domain, ip, headers, ssl_info, whois_info, dns_records)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = Tk()
root.title("Domain Information Tool - DIT")
root.geometry("650x400")
root.configure(bg="#F5F5F5")

# Style configuration
style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", font=("Arial", 12), background="#F5F5F5")
style.configure("TButton", font=("Arial", 12), background="#4CAF50", foreground="white")
style.configure("Header.TLabel", font=("Arial", 16, "bold"), background="#0066CC", foreground="white", anchor="center")

# Title Label
title_label = ttk.Label(root, text="Domain Information Tool", style="Header.TLabel")
title_label.pack(fill=X, pady=10)

# Input Frame
frame_input = Frame(root, bg="#F5F5F5")
frame_input.pack(fill=X, padx=20, pady=10)

ttk.Label(frame_input, text="Enter Domain Name:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
entry_domain = ttk.Entry(frame_input, font=("Arial", 12), width=40)
entry_domain.grid(row=0, column=1, padx=5, pady=5, sticky=W)

# Action Buttons
frame_buttons = Frame(root, bg="#F5F5F5")
frame_buttons.pack(fill=X, padx=20, pady=20)

btn_generate = ttk.Button(frame_buttons, text="Generate Report", command=fetch_and_generate)
btn_generate.pack(pady=10)

# Run the application
root.mainloop()

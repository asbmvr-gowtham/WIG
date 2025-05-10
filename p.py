import socket
import requests
import ssl
import whois
import json
from fpdf import FPDF
import dns.resolver

class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.set_text_color(255, 255, 255)  # White text
        self.set_fill_color(0, 102, 204)  # Blue background
        self.cell(0, 10, "Domain Information Report", border=0, ln=1, align="C", fill=True)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(128, 128, 128)  # Gray text
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

    def add_section(self, title, content):
        # Section title
        self.set_font("Arial", "B", 12)
        self.set_text_color(255, 255, 255)  # White text
        self.set_fill_color(51, 153, 102)  # Green background
        self.cell(0, 8, title, ln=1, border=0, fill=True)
        self.ln(2)

        # Section content
        self.set_font("Arial", "", 10)
        self.set_text_color(0, 0, 0)  # Black text
        self.multi_cell(0, 6, content)
        self.ln(5)

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return f"IP Address: {ip_address}"
    except Exception as e:
        return f"Failed to get IP address: {e}"

def get_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        headers = response.headers
        header_info = "\n".join([f"{key}: {value}" for key, value in headers.items()])
        return header_info
    except Exception as e:
        return f"Failed to get HTTP headers: {e}"

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return json.dumps(cert, indent=2)
    except Exception as e:
        return f"Failed to get SSL info: {e}"

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return str(domain_info)
    except Exception as e:
        return f"Failed to get WHOIS information: {e}"

def get_dns_records(domain):
    try:
        record_types = ["A", "AAAA", "MX", "CNAME", "NS"]
        records = []
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=3)
                for rdata in answers:
                    records.append(f"{rtype}: {rdata.to_text()}")
                    if len(records) == 10:  # Limit to 10 records
                        return "\n".join(records)
            except Exception as e:
                continue  # Skip record types that fail
        return "\n".join(records[:10])  # Fallback to the first 10
    except Exception as e:
        return f"Failed to get DNS records: {e}"

# Generate PDF report
def generate_pdf_report(domain, ip_info, http_headers, ssl_info, whois_info, dns_records):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)

    pdf.add_section("Domain:", domain)
    pdf.add_section("IP Address Information:", ip_info)
    pdf.add_section("HTTP Headers:", http_headers)
    pdf.add_section("SSL Certificate Information:", ssl_info)
    pdf.add_section("WHOIS Information:", whois_info)
    pdf.add_section("DNS Records :", dns_records)

    report_filename = f"{domain}_report.pdf"
    pdf.output(report_filename)
    print(f"\nPDF report generated: {report_filename}")

# Main function
if __name__ == "__main__":
    domain = input("Enter the domain name: ")
    print(f"Gathering information for {domain}...\n")

    ip_info = get_ip_address(domain)
    http_headers = get_http_headers(domain)
    ssl_info = get_ssl_info(domain)
    whois_info = get_whois_info(domain)
    dns_records = get_dns_records(domain)

    # Display information in the console
    print("\n" + ip_info)
    print("\n" + http_headers)
    print("\n" + ssl_info)
    print("\n" + whois_info)
    print("\nDNS Records:\n" + dns_records)

    # Generate PDF
    generate_pdf_report(domain, ip_info, http_headers, ssl_info, whois_info, dns_records)

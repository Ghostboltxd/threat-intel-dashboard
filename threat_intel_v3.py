import time
import os
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
import ipaddress
import certifi
import re

# Inicialización de la consola
console = Console()

# Cargar variables de entorno (.env)
load_dotenv()
VT_API_KEY = os.getenv("VT_API")
ABUSE_API_KEY = os.getenv("ABUSE_API")
IP_INFO_API_KEY = os.getenv("IP_INFO_API")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def mostrar_banner():
    """Limpia la terminal y muestra un banner de inicio elegante."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner_text = Text()
    banner_text.append("🛡️  THREAT INTELLIGENCE MODULE\n", style="bold cyan")
    banner_text.append("Powered by VirusTotal, AbuseIPDB, IPinfo & Gemini AI", style="italic white")
    
    panel = Panel(
        Align.center(banner_text),
        border_style="cyan",
        padding=(1, 2),
        width=80
    )
    console.print(panel)
    console.print("\n")

def detectar_tipo_ioc(ioc):
    ioc = ioc.strip()
    if ioc == "0": return "EXIT"
    try:
        ipaddress.ip_address(ioc)
        return "IP"
    except ValueError: pass
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
        return "HASH"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
        return "DOMAIN"
    return "INVALID"

def check_virustotal(ioc, tipo):
    if not VT_API_KEY: return {"malicious": 0, "suspicious": 0, "reputation": 0}
    endpoint = f"ip_addresses/{ioc}" if tipo == "IP" else f"files/{ioc}" if tipo == "HASH" else f"domains/{ioc}"
    try:
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, verify=certifi.where(), timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "reputation": data.get("reputation", 0)}
        return {"malicious": "N/A", "suspicious": 0, "reputation": 0}
    except Exception: return {"malicious": "Err", "suspicious": 0, "reputation": 0}

def check_abuseipdb(ip):
    if not ABUSE_API_KEY: return {"abuseConfidenceScore": 0, "totalReports": 0}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        response = requests.get(url, headers=headers, verify=certifi.where(), timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {"abuseConfidenceScore": data.get("abuseConfidenceScore", 0), "totalReports": data.get("totalReports", 0)}
        return {"abuseConfidenceScore": 0, "totalReports": 0}
    except Exception: return {"abuseConfidenceScore": 0, "totalReports": 0}

def check_ipinfo(ip):
    if not IP_INFO_API_KEY: return {"country": "N/A", "org": "N/A"}
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IP_INFO_API_KEY}"
        response = requests.get(url, verify=certifi.where(), timeout=10)
        return response.json() if response.status_code == 200 else {"country": "N/A", "org": "N/A"}
    except Exception: return {"country": "N/A", "org": "N/A"}

def generar_recomendacion_ia(ioc, tipo, vt, abuse=None, ipinfo=None):
    if not GEMINI_API_KEY:
        return "Módulo de IA no configurado: Falta GEMINI_API_KEY."
    
    prompt = f"""
    Actúa como un experto Analista de Ciberseguridad. Analiza el siguiente IoC:
    - Valor: {ioc} ({tipo})
    - VirusTotal: Malicioso={vt['malicious']}, Sospechoso={vt['suspicious']}, Reputación={vt['reputation']}
    """
    if tipo == "IP" and abuse and ipinfo:
        prompt += f"""
        - AbuseIPDB: Score={abuse['abuseConfidenceScore']}%, Reportes={abuse['totalReports']}
        - ISP/Geo: País={ipinfo.get('country')}, Org={ipinfo.get('org')}
        """
        
    prompt += """
    Entrégame un veredicto estructurado:
    1. **Nivel de Riesgo**: (Crítico, Alto, Medio, Bajo o Limpio) y justificación.
    2. **Análisis Breve**: Contexto técnico rápido.
    3. **Acciones Recomendadas**: 3 acciones inmediatas.
    Sé conciso y directo al grano.
    """

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        response = requests.post(url, headers=headers, json=payload, verify=certifi.where(), timeout=15)
        if response.status_code == 200:
            return response.json()['candidates'][0]['content']['parts'][0]['text']
        else:
            return f"Error en API (Status {response.status_code}): {response.text}"
    except Exception as e:
        return f"Error de conexión: {str(e)}"

# --- Bucle Principal ---
mostrar_banner()

while True:
    console.print("[bold yellow]Input your IOC (IP, Hash, Domain) or 0 to quit:[/bold yellow]")
    entrada = input("> ").strip()
    
    tipo_ioc = detectar_tipo_ioc(entrada)
    
    if tipo_ioc == "INVALID":
        console.print("[bold red]Invalid format. Try again.[/bold red]\n")
        continue
    if tipo_ioc == "EXIT":
        console.print("\n[bold magenta]Exiting Threat Intelligence Module. Stay safe![/bold magenta]\n")
        break

    console.print(f"\n[dim cyan]Fetching data for {tipo_ioc}: {entrada}...[/dim cyan]\n")
    
    # 1. Recolección de Datos
    vt_result = check_virustotal(entrada, tipo_ioc)
    abuse_result = check_abuseipdb(entrada) if tipo_ioc == "IP" else None
    ipinfo_result = check_ipinfo(entrada) if tipo_ioc == "IP" else None
    
    # 2. Desplegar Tabla Técnica Moderna (SECCIONADA POR FUENTE)
    table = Table(title=f"Threat Intelligence Summary for [bold]{entrada}[/bold]", header_style="bold cyan", style="blue")
    table.add_column("Source", justify="left", style="cyan")
    table.add_column("Malicious", justify="center", style="red")
    table.add_column("Suspicious", justify="center", style="yellow")
    table.add_column("Reputation", justify="center", style="green")
    table.add_column("Abuse Score", justify="center", style="magenta")
    table.add_column("Total Reports", justify="center", style="magenta")
    table.add_column("Country", justify="center", style="blue")
    table.add_column("Organization", justify="left", style="blue")

    # Fila 1: VirusTotal (Aplica para todo)
    table.add_row(
        "VirusTotal", 
        str(vt_result['malicious']), 
        str(vt_result['suspicious']), 
        str(vt_result['reputation']), 
        "-", "-", "-", "-"
    )
    
    # Fila 2 y 3: AbuseIPDB e IPinfo (Solo aplican si es IP)
    if tipo_ioc == "IP":
        table.add_row(
            "AbuseIPDB", 
            "-", "-", "-", 
            f"{abuse_result['abuseConfidenceScore']}%", 
            str(abuse_result['totalReports']), 
            "-", "-"
        )
        table.add_row(
            "IPinfo", 
            "-", "-", "-", "-", "-", 
            ipinfo_result.get('country', 'N/A'), 
            ipinfo_result.get('org', 'N/A')
        )
    
    console.print(table)
    
    # 3. Mostrar Versión Copy-Paste
    console.print("\n[bold]Copy and paste version:[/bold]")
    print(f"ioc={entrada}")
    print(f"type={tipo_ioc}")
    print(f"vt_malicious={vt_result['malicious']}")
    print(f"vt_suspicious={vt_result['suspicious']}")
    print(f"vt_reputation={vt_result['reputation']}")
    if tipo_ioc == "IP":
        print(f"abuse_confidence={abuse_result['abuseConfidenceScore']}%")
        print(f"abuse_reports={abuse_result['totalReports']}")
        print(f"country={ipinfo_result.get('country', 'N/A')}")
        print(f"organization={ipinfo_result.get('org', 'N/A')}")
    print("\n")
    
    # 4. Reporte IA en Panel Elegante
    with console.status("[bold violet]Generando reporte de IA de Gemini...[/bold violet]", spinner="dots"):
        analisis_ia = generar_recomendacion_ia(entrada, tipo_ioc, vt_result, abuse_result, ipinfo_result)
    
    ia_panel = Panel(
        analisis_ia,
        title="[bold sparkler] AI ANALYSIS REPORT [/bold sparkler]",
        border_style="green",
        padding=(1, 2)
    )
    console.print(ia_panel)
    console.print("-" * 80 + "\n")
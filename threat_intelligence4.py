import sys

try:
    import time
    import os
    import requests
    import sqlite3
    import json
    from datetime import datetime, timedelta
    from dotenv import load_dotenv
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    import ipaddress
    import certifi
    import re
    import urllib.parse

    # Inicialización
    console = Console()
    
    # --- RUTA ABSOLUTA PARA EL .ENV ---
    # Obliga a Python a leer el archivo .env de la misma carpeta donde está el script
    ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    load_dotenv(ENV_PATH)

    VT_API_KEY = os.getenv("VT_API")
    ABUSE_API_KEY = os.getenv("ABUSE_API")
    IP_INFO_API_KEY = os.getenv("IP_INFO_API")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
    PROXYCHECK_API_KEY = os.getenv("PROXYCHECK_API_KEY")

    # Alerta de diagnóstico rápida (te avisará si el archivo .env sigue sin leerse)
    if not PROXYCHECK_API_KEY:
        console.print("\n[bold red][!] ALERTA DE DEBUG: No se detectó PROXYCHECK_API_KEY en el archivo .env[/bold red]")
        time.sleep(2)

    # --- RUTA ABSOLUTA PARA LA BASE DE DATOS ---
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'threat_intel_cache.db')

    # --- FUNCIONES DE BASE DE DATOS ---
    def iniciar_base_datos():
        """Crea la base de datos local si no existe."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc TEXT PRIMARY KEY,
                tipo TEXT,
                api_data JSON,
                ia_report TEXT,
                timestamp DATETIME,
                query_count INTEGER
            )
        ''')
        conn.commit()
        conn.close()

    # --- FUNCIONES DE UTILIDAD ---
    def limpiar_ioc(ioc):
        """Realiza 'Defanging': limpia corchetes y formatos seguros para evitar errores."""
        ioc_limpio = ioc.replace('[.]', '.').replace('[', '').replace(']', '').replace('(', '').replace(')', '')
        ioc_limpio = ioc_limpio.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
        return ioc_limpio.strip()

    def detectar_tipo_ioc(ioc):
        if ioc == "0": return "EXIT"
        try:
            ipaddress.ip_address(ioc)
            return "IP"
        except ValueError: pass
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
            return "HASH"
        if ioc.startswith("http://") or ioc.startswith("https://") or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
            return "URL_OR_DOMAIN"
        return "INVALID"

    def mostrar_banner():
        """Limpia la terminal en cada ciclo para mantener un diseño pulcro."""
        os.system('cls' if os.name == 'nt' else 'clear')
        ascii_banner = r"""
      ___________.__                        __    .___        __         .__  
      \__    ___/|  |_________  ____ _____ _/  |_  |   | _____/  |_  ____ |  | 
        |    |   |  |  \_  __ \/ __ \\__  \\   __\ |   |/    \   __\/ __ \|  | 
        |    |   |   Y  \  | \/\  ___/ / __ \|  |   |   |   |  \  | \  ___/|  |__
        |____|   |___|  /__|    \___  >____  /__|   |___|___|  /__|  \___  >____/
                      \/            \/     \/                \/          \/      
        """
        banner_text = Text(ascii_banner, style="bold cyan")
        subtitle = Text("\nSOC Automated Triage & Intelligence Analysis (Con Caché Local)", style="italic white")
        header = Text.assemble(banner_text, subtitle, justify="center")
        console.print(Panel(header, border_style="cyan", padding=(1, 2)))
        console.print("\n")

    # --- FUNCIONES DE APIs ---
    def check_virustotal(ioc, tipo):
        if not VT_API_KEY: return {"malicious": 0, "suspicious": 0, "reputation": 0}
        endpoint = f"ip_addresses/{ioc}" if tipo == "IP" else f"files/{ioc}" if tipo == "HASH" else f"domains/{ioc}"
        if tipo == "URL_OR_DOMAIN" and (ioc.startswith("http://") or ioc.startswith("https://")):
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"urls/{url_id}"
        elif tipo == "URL_OR_DOMAIN":
            endpoint = f"domains/{ioc}"

        try:
            url = f"https://www.virustotal.com/api/v3/{endpoint}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(url, headers=headers, verify=certifi.where(), timeout=10)
            
            if response.status_code == 429:
                return {"malicious": "Lim.", "suspicious": "429", "reputation": "Espera"}
                
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

    def check_proxycheck(ip):
        """Consulta Proxycheck.io para detectar VPNs, Tor y Proxies utilizando API Key."""
        if not PROXYCHECK_API_KEY: return {"proxy": "N/A", "type": "N/A", "risk": 0}
        try:
            url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_API_KEY}&vpn=1&asn=1"
            response = requests.get(url, verify=certifi.where(), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if ip in data and data.get("status") == "ok":
                    ip_data = data[ip]
                    return {
                        "proxy": ip_data.get("proxy", "no"),
                        "type": ip_data.get("type", "Clear"),
                        "risk": ip_data.get("risk", 0)
                    }
            return {"proxy": "Err", "type": "Err", "risk": 0}
        except Exception: return {"proxy": "Err", "type": "Err", "risk": 0}

    def check_urlscan(target_url):
        if not URLSCAN_API_KEY:
            return {"result_url": "N/A", "screenshot": "N/A", "status": "Disabled"}
        
        clean_target_url = target_url
        if not (clean_target_url.startswith("http://") or clean_target_url.startswith("https://")):
            clean_target_url = f"http://{clean_target_url}"
            
        try:
            api_url = "https://urlscan.io/api/v1/scan/"
            headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
            payload = {"url": clean_target_url, "visibility": "public"}
            response = requests.post(api_url, headers=headers, json=payload, verify=certifi.where(), timeout=12)
            
            if response.status_code == 201:
                uuid = response.json().get("uuid")
                return {
                    "result_url": f"https://urlscan.io/result/{uuid}/",
                    "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
                    "status": "Submitted"
                }
            
            elif response.status_code in [400, 200]: 
                parsed_url = urllib.parse.urlparse(clean_target_url)
                domain = parsed_url.hostname
                search_url = f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}"
                search_response = requests.get(search_url, headers=headers, verify=certifi.where(), timeout=10)
                
                if search_response.status_code == 200:
                    results = search_response.json().get("results", [])
                    if results:
                        latest_scan = results[0]
                        uuid = latest_scan.get("task", {}).get("uuid")
                        if uuid:
                            return {"result_url": f"https://urlscan.io/result/{uuid}/", "screenshot": f"https://urlscan.io/screenshots/{uuid}.png", "status": "Found in Cache"}
                return {"result_url": f"Err HTTP {response.status_code}", "screenshot": "N/A", "status": "API Rechazó Petición"}
            else:
                return {"result_url": f"Err HTTP {response.status_code}", "screenshot": "N/A", "status": f"Fallo HTTP {response.status_code}"}
        except Exception as e:
            return {"result_url": "Err Conexión", "screenshot": "N/A", "status": f"Error de Red"}

    def generar_recomendacion_ia(ioc, tipo, vt, abuse=None, ipinfo=None, urlscan=None, proxycheck_data=None):
        if not GEMINI_API_KEY: return "Módulo de IA no configurado: Falta GEMINI_API_KEY."
        
        prompt = f"""
        Actúa como un analista experto del SOC y Threat Intelligence.
        Analiza la siguiente entidad sospechosa con los datos provistos de nuestras APIs:

        - Entidad Investigada: {ioc} ({tipo})
        - Resultados de VirusTotal: Malicioso={vt['malicious']}, Sospechoso={vt['suspicious']}, Reputación={vt['reputation']}
        """
        
        if tipo == "IP" and abuse and ipinfo:
            prompt += f"""
            - Datos de AbuseIPDB: Score={abuse.get('abuseConfidenceScore', 0)}%, Reportes={abuse.get('totalReports', 0)}
            - Datos de Geolocalización/ISP: País={ipinfo.get('country', 'N/A')}, Org={ipinfo.get('org', 'N/A')}
            """
            
        if tipo == "IP" and proxycheck_data:
            proxy_status = proxycheck_data.get('proxy', 'no').upper()
            proxy_type = proxycheck_data.get('type', 'Clear')
            prompt += f"""
            - Datos de Anonimato (Proxycheck): ¿Es Proxy/VPN/Tor? = {proxy_status}, Tipo de Nodo = {proxy_type}
            """
            
        if tipo == "URL_OR_DOMAIN" and urlscan:
            if urlscan.get("status") in ["Submitted", "Found in Cache"]:
                prompt += f"""
                - Estado Urlscan.io: {urlscan['status']}
                - Enlace de Reporte Sandbox: {urlscan['result_url']}
                - Enlace de Captura del Sandbox: {urlscan['screenshot']}
                """
            else: prompt += f"\n- Estado Urlscan.io: Fallido ({urlscan.get('status')})"
            
        prompt += """
        Por favor, entrégame un veredicto estructurado en español:
        1. **Nivel de Riesgo**: (Crítico, Alto, Medio, Bajo o Limpio) y justificación técnica basándote en TODAS las fuentes.
        2. **Análisis de Amenaza**: Explica los hallazgos técnicos.
        3. **Acciones Recomendadas**: 3 acciones inmediatas que el equipo de ciberseguridad debe tomar.
        Sé directo, conciso y técnico.
        """

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
        headers = {"Content-Type": "application/json"}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        try:
            response = requests.post(url, headers=headers, json=payload, verify=certifi.where(), timeout=60)
            if response.status_code == 200:
                return response.json()['candidates'][0]['content']['parts'][0]['text']
            else:
                return f"Error en API de Google (Status {response.status_code}): {response.text}"
        except Exception as e:
            return f"Error de conexión con IA: {str(e)}"

    # --- BUCLE PRINCIPAL CON MEMORIA CACHÉ ---
    iniciar_base_datos()

    while True:
        mostrar_banner()
        console.print("[bold yellow]► Ingrese IoC (IP, Hash, Dominio) o '0' para salir:[/bold yellow]")
        entrada = input("  > ").strip()
        
        ioc_limpio = limpiar_ioc(entrada)
        tipo_ioc = detectar_tipo_ioc(ioc_limpio)
        
        if tipo_ioc == "INVALID":
            console.print("[bold red]❌ Formato inválido. Presione Enter para continuar.[/bold red]\n")
            input()
            continue
        if tipo_ioc == "EXIT":
            console.print("\n[bold magenta]Saliendo del módulo de Threat Intelligence. ¡Mantente seguro![/bold magenta]\n")
            break

        console.print(f"\n[dim cyan]🔄 Evaluando caché e inteligencia para {tipo_ioc}: {ioc_limpio}...[/dim cyan]\n")
        
        # --- GESTIÓN DE BASE DE DATOS / CACHÉ ---
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT api_data, ia_report, timestamp, query_count FROM ioc_cache WHERE ioc=?", (ioc_limpio,))
        row = cursor.fetchone()
        
        usar_cache = False
        historial_consultas = 1
        dias_caducidad = 7
        
        if row:
            db_timestamp = datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
            historial_consultas = row[3] + 1
            
            if datetime.now() - db_timestamp < timedelta(days=dias_caducidad):
                usar_cache = True
                api_data = json.loads(row[0])
                vt_result = api_data.get('vt')
                abuse_result = api_data.get('abuse')
                ipinfo_result = api_data.get('ipinfo')
                urlscan_result = api_data.get('urlscan')
                proxycheck_result = api_data.get('proxycheck')
                analisis_ia = row[1]
                
                cursor.execute("UPDATE ioc_cache SET query_count=? WHERE ioc=?", (historial_consultas, ioc_limpio))
                conn.commit()
        
        if not usar_cache:
            vt_result = check_virustotal(ioc_limpio, tipo_ioc)
            abuse_result = check_abuseipdb(ioc_limpio) if tipo_ioc == "IP" else None
            ipinfo_result = check_ipinfo(ioc_limpio) if tipo_ioc == "IP" else None
            proxycheck_result = check_proxycheck(ioc_limpio) if tipo_ioc == "IP" else None
            urlscan_result = check_urlscan(ioc_limpio) if tipo_ioc == "URL_OR_DOMAIN" else None
            
            with console.status("[bold violet]🧠 Sintetizando análisis con Gemini AI (API en vivo)...[/bold violet]", spinner="dots"):
                analisis_ia = generar_recomendacion_ia(ioc_limpio, tipo_ioc, vt_result, abuse_result, ipinfo_result, urlscan_result, proxycheck_result)
            
            api_data_dump = json.dumps({'vt': vt_result, 'abuse': abuse_result, 'ipinfo': ipinfo_result, 'urlscan': urlscan_result, 'proxycheck': proxycheck_result})
            fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                REPLACE INTO ioc_cache (ioc, tipo, api_data, ia_report, timestamp, query_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ioc_limpio, tipo_ioc, api_data_dump, analisis_ia, fecha_actual, historial_consultas))
            conn.commit()

        conn.close()
        
        # --- DISEÑO VISUAL SECCIONADO ---
        if usar_cache:
            console.print(Panel(f"[bold bright_green]✅ Cargado desde Base de Datos Local[/bold bright_green]\nEsta entidad ha sido investigada [bold white]{historial_consultas} veces[/bold white] por el equipo. Tokens Ahorrados.", border_style="green", expand=False))
        
        target_text = f"[bold white]Objetivo:[/bold white] {ioc_limpio}\n[bold white]Clasificación:[/bold white] {tipo_ioc}"
        console.print(Panel(target_text, title="🎯 Detalles del Objetivo", border_style="blue", expand=False))
        
        leyenda = "[dim]* [cyan]VirusTotal[/cyan]: Votos de reputación de la comunidad | [cyan]AbuseIPDB[/cyan]: Probabilidad de comportamiento abusivo[/dim]"
        rep_table = Table(show_header=True, header_style="bold magenta", caption=leyenda, caption_justify="left")
        
        rep_table.add_column("Fuente", style="cyan", width=15)
        rep_table.add_column("Detecciones (Mal/Sos)", justify="center", style="red")
        rep_table.add_column("Score / Confianza", justify="center", style="green")
        rep_table.add_column("Total Reportes", justify="center", style="yellow")
        
        rep_table.add_row("VirusTotal", f"{vt_result.get('malicious', 0)} / {vt_result.get('suspicious', 0)}", f"{vt_result.get('reputation', 0)} (Votos)", "-")
        if tipo_ioc == "IP" and abuse_result:
            score_abuso = abuse_result.get('abuseConfidenceScore', 0)
            color_abuso = "green" if score_abuso == 0 else "yellow" if score_abuso < 50 else "red"
            rep_table.add_row("AbuseIPDB", "-", f"[{color_abuso}]{score_abuso}% (Riesgo)[/{color_abuso}]", str(abuse_result.get('totalReports', 0)))
            
        console.print(Panel(rep_table, title="🛡️ Análisis de Reputación Estática", border_style="magenta", expand=False))

        if tipo_ioc == "IP" and ipinfo_result:
            ctx_table = Table(show_header=False, box=None)
            ctx_table.add_column("Atributo", style="bold cyan")
            ctx_table.add_column("Valor", style="white")
            ctx_table.add_row("País de Origen:", ipinfo_result.get('country', 'N/A'))
            ctx_table.add_row("Organización/ISP:", ipinfo_result.get('org', 'N/A'))
            
            if proxycheck_result:
                is_proxy = proxycheck_result.get('proxy', 'no')
                tipo_proxy = proxycheck_result.get('type', 'Clear')
                color_proxy = "red" if is_proxy == "yes" else "green"
                ctx_table.add_row("Anonimato (VPN/Proxy):", f"[{color_proxy}]{is_proxy.upper()} ({tipo_proxy})[/{color_proxy}]")
            
            console.print(Panel(ctx_table, title="🌍 Contexto de Red (IPinfo & Proxycheck)", border_style="green", expand=False))
            
        elif tipo_ioc == "URL_OR_DOMAIN" and urlscan_result:
            estado_urlscan = urlscan_result.get("status")
            ctx_text = f"[bold cyan]Estado de Escaneo:[/bold cyan] "
            if estado_urlscan in ["Submitted", "Found in Cache"]:
                ctx_text += f"[bold green]{estado_urlscan}[/bold green]\n[bold cyan]Reporte Sandbox:[/bold cyan] {urlscan_result['result_url']}\n[bold cyan]Captura de Pantalla:[/bold cyan] {urlscan_result['screenshot']}"
            else: ctx_text += f"[bold red]Fallo ({estado_urlscan})[/bold red]"
            console.print(Panel(ctx_text, title="🔍 Análisis Dinámico (Urlscan.io)", border_style="green", expand=False))

        console.print(Panel(analisis_ia, title="[bold yellow]🤖 Veredicto y Mitigación (Gemini AI)[/bold yellow]", border_style="yellow", padding=(1, 2)))
        
        export_data = f"ioc={ioc_limpio}\ntype={tipo_ioc}\nvt_malicious={vt_result.get('malicious', 'N/A')}\nvt_suspicious={vt_result.get('suspicious', 'N/A')}\nvt_reputation={vt_result.get('reputation', 'N/A')}"
        if tipo_ioc == "IP" and abuse_result and ipinfo_result:
            export_data += f"\nabuse_confidence={abuse_result.get('abuseConfidenceScore', 0)}%\nabuse_reports={abuse_result.get('totalReports', 0)}\ncountry={ipinfo_result.get('country', 'N/A')}\norganization={ipinfo_result.get('org', 'N/A')}"
            if proxycheck_result:
                export_data += f"\nis_proxy={proxycheck_result.get('proxy', 'N/A')}\nproxy_type={proxycheck_result.get('type', 'N/A')}"
        elif tipo_ioc == "URL_OR_DOMAIN" and urlscan_result:
             export_data += f"\nurlscan_status={urlscan_result.get('status', 'N/A')}"
             if urlscan_result.get("status") in ["Submitted", "Found in Cache"]:
                 export_data += f"\nurlscan_report={urlscan_result.get('result_url', 'N/A')}"
                 
        console.print(Panel(export_data, title="📋 Exportación (Raw Data)", border_style="dim white", expand=False))
        
        # Pausa antes del siguiente análisis
        input("\n[dim]Presione ENTER para analizar otro indicador...[/dim]")

except Exception as e:
    import traceback
    print("\n" + "="*50)
    print("🛑 ERROR FATAL DETECTADO 🛑")
    print("="*50)
    traceback.print_exc()
    print("\n[El programa no se cerrará para que puedas leer el error]")
    print("Por favor, copia el texto de arriba y pásamelo por el chat.")
    input("Presiona ENTER para salir...")
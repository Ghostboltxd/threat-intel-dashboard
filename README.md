cite_start]Para solucionarlo, abre tu archivo **`README.md`** en tu computadora, borra todo lo que tiene, **copia textualmente este único bloque gris de abajo**, pégalo y guárdalo[cite: 323]:

```markdown
# 🛡️ Threat Intelligence Dashboard

Módulo interactivo de Inteligencia de Amenazas diseñado para analistas de ciberseguridad. [cite_start]Permite verificar de forma automatizada y centralizada la reputación de direcciones IP, Hashes y Dominios utilizando múltiples fuentes de confianza e Inteligencia Artificial[cite: 323].

---

## 🚀 Instrucciones de Instalación

### 1. Clonar el repositorio y acceder al directorio
la ultima version de threat_intel_VX, copialo en un block de notas y guardalo como un archivo.py

### 3. Instalar la librería de Google AI y demás dependencias
[cite_start]Este paso instalará el SDK oficial de Google para interactuar de forma nativa con los modelos de Gemini, junto con los componentes gráficos de consola y gestión de variables de entorno[cite: 323]:
```bash
pip install google-generativeai python-dotenv rich requests certifi
```

---

## 🔑 Configuración de Credenciales (Archivo .env)

[cite_start]Para que el script funcione correctamente, debes crear un archivo de texto plano llamado `.env` en la raíz de tu proyecto[cite: 324]. [cite_start]Copia y pega la siguiente estructura rellenando los campos con tus credenciales privadas[cite: 325]:

```env
VT_API=tu_api_key_de_virustotal
ABUSE_API=tu_api_key_de_abuseipdb
IP_INFO_API=tu_api_key_de_ipinfo
GEMINI_API_KEY=tu_api_key_de_gemini
URLSCAN_API_KEY=tu_api_key_de_urlscan
PROXYCHECK_API_KEY=tu_api_key_de_proxycheck
```

> [cite_start]⚠️ **IMPORTANTE:** El archivo `.env` almacena credenciales críticas[cite: 325]. [cite_start]Asegúrate de incluirlo dentro de tu archivo `.gitignore` para garantizar que **nunca** se suba de forma pública a GitHub[cite: 326].

---

## 🛰️ Paso a Paso: Cómo obtener la API Key de Gemini (Google AI)

[cite_start]Para activar las funciones de análisis e inteligencia contextual, necesitas generar una clave gratuita en el motor de Google AI Studio siguiendo estos pasos[cite: 327]:

1. [cite_start]**Acceder al portal de desarrollo:** Dirígete a la plataforma oficial en [Google AI Studio](https://aistudio.google.com/)[cite: 327].
2. [cite_start]**Iniciar sesión:** Autentícate utilizando cualquier cuenta activa de Google (Gmail institucional o personal)[cite: 328].
3. [cite_start]**Generar el Token de Acceso:** * En la esquina superior izquierda de la interfaz, haz clic en el botón **"Get API key"**[cite: 329].
   * [cite_start]En la ventana emergente, haz clic en **"Create API key"**[cite: 330].
4. [cite_start]**Vincular Proyecto:** Selecciona la opción para generar la clave en un proyecto nuevo o vincúlala a un entorno de Google Cloud existente[cite: 331].
5. [cite_start]**Guardar Credencial:** Una vez generada la cadena alfanumérica, presiona el botón **"Copy"**[cite: 332]. [cite_start]Abre tu archivo `.env` local y pégala directamente en la variable `GEMINI_API_KEY`[cite: 333].

---

## 🏃‍♂️ Ejecución del Módulo

[cite_start]Una vez completadas las instalaciones y la configuración del archivo de credenciales, arranca la interfaz del tablero ejecutando[cite: 334]:

```bash
python threat_intel_v3.py
```

[cite_start]Introduce la dirección IP, Hash o Dominio que desees auditar[cite: 334]. [cite_start]El sistema listará de forma ordenada las respuestas de cada proveedor y desplegará un informe analítico redactado por la IA con las acciones de mitigación recomendadas[cite: 335]. [cite_start]Para cerrar la sesión, ingresa `0`[cite: 336].
```

[cite_start]Una vez guardado localmente, lánzalo a GitHub desde tu terminal ejecutando[cite: 141]:
```bash
git add README.md
git commit -m "Fix: Formato de bloques de código en README"
git push

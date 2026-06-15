# threat_intelligence_tool
# 🛡️ Threat Intelligence Dashboard

[cite_start]Módulo interactivo de Inteligencia de Amenazas diseñado para analistas de ciberseguridad. [cite_start]Permite verificar de forma automatizada y centralizada la reputación de direcciones IP, Hashes y Dominios utilizando múltiples fuentes de confianza e Inteligencia Artificial.

---

## 🚀 Instrucciones de Instalación

[cite_start]Sigue estos pasos en tu terminal o PowerShell para configurar el entorno local:

### 1. Clonar el repositorio y acceder al directorio
```bash
git clone [https://github.com/Ghostboltxd/threat-intel-dashboard.git](https://github.com/Ghostboltxd/threat-intel-dashboard.git)
cd threat-intel-dashboard

Instalar la librería de Google AI y demás dependencias
Este paso instalará el SDK oficial de Google para interactuar de forma nativa con los modelos de Gemini, junto con los componentes gráficos de consola y gestión de variables de entorno:

Bash
pip install google-generativeai python-dotenv rich requests certifi

🔑 Configuración de Credenciales (Archivo .env)
Para que el script funcione correctamente, debes crear un archivo de texto plano llamado .env en la raíz de tu proyecto. Copia y pega la siguiente estructura rellenando los campos con tus credenciales privadas:

Fragmento de código
VT_API=tu_api_key_de_virustotal
ABUSE_API=tu_api_key_de_abuseipdb
IP_INFO_API=tu_api_key_de_ipinfo
GEMINI_API_KEY=tu_api_key_de_gemini

Paso a Paso: Cómo obtener la API Key de Gemini (Google AI)
Para activar las funciones de análisis e inteligencia contextual, necesitas generar una clave gratuita en el motor de Google AI Studio siguiendo estos pasos:


Acceder al portal de desarrollo: Dirígete a la plataforma oficial en Google AI Studio.


Iniciar sesión: Autentícate utilizando cualquier cuenta activa de Google (Gmail institucional o personal).


Generar el Token de Acceso: * En la esquina superior izquierda de la interfaz, haz clic en el botón "Get API key".

En la ventana emergente, haz clic en "Create API key".


Vincular Proyecto: Selecciona la opción para generar la clave en un proyecto nuevo o vincúlala a un entorno de Google Cloud existente.


Guardar Credencial: Una vez generada la cadena alfanumérica, presiona el botón "Copy". Abre tu archivo .env local y pégala directamente en la variable GEMINI_API_KEY.

🏃‍♂️ Ejecución del Módulo
Una vez completadas las instalaciones y la configuración del archivo de credenciales, arranca la interfaz del tablero ejecutando:

Bash
python threat_intel_v3.py

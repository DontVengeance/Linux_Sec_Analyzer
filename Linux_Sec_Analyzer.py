import os
import subprocess
import re
import argparse
from colorama import Fore, Style, init

# Inicializa colorama para que los colores funcionen en diferentes terminales
init(autoreset=True)

# --- Funciones de Ayuda para Colores ---
def print_critical(message):
    print(f"{Fore.RED}CRÍTICO: {message}{Style.RESET_ALL}")

def print_medium(message):
    print(f"{Fore.YELLOW}MEDIO: {message}{Style.RESET_ALL}")

def print_info(message):
    print(f"{Fore.GREEN}INFO: {message}{Style.RESET_ALL}")

# --- Verificaciones de Seguridad ---

def check_ssh_config():
    """Verifica configuraciones débiles en SSH."""
    print(f"\n{Fore.CYAN}--- Verificando Configuración de SSH ---{Style.RESET_ALL}")
    ssh_config_path = "/etc/ssh/sshd_config"
    if not os.path.exists(ssh_config_path):
        print_info("No se encontró el archivo de configuración de SSH.")
        return

    try:
        with open(ssh_config_path, 'r') as f:
            ssh_config = f.read()

        # PermitRootLogin
        if re.search(r"^\s*PermitRootLogin\s+yes", ssh_config, re.IGNORECASE | re.MULTILINE):
            print_critical("PermitRootLogin está configurado como 'yes'. Esto es una vulnerabilidad crítica. Desactívalo.")
        elif re.search(r"^\s*PermitRootLogin\s+without-password", ssh_config, re.IGNORECASE | re.MULTILINE):
            print_medium("PermitRootLogin está configurado como 'without-password'. Considera deshabilitarlo.")
        else:
            print_info("PermitRootLogin parece estar configurado correctamente (deshabilitado o 'prohibit-password').")

        # PasswordAuthentication
        if re.search(r"^\s*PasswordAuthentication\s+yes", ssh_config, re.IGNORECASE | re.MULTILINE):
            print_medium("PasswordAuthentication está habilitado. Considera usar autenticación por clave SSH.")
        else:
            print_info("PasswordAuthentication parece estar deshabilitado o configurado correctamente.")

        # PermitEmptyPasswords
        if re.search(r"^\s*PermitEmptyPasswords\s+yes", ssh_config, re.IGNORECASE | re.MULTILINE):
            print_critical("PermitEmptyPasswords está habilitado. Esto es una vulnerabilidad crítica.")
        else:
            print_info("PermitEmptyPasswords parece estar deshabilitado.")

    except Exception as e:
        print_medium(f"Error al leer la configuración de SSH: {e}")

def check_unsecured_files_permissions():
    """Verifica permisos de archivos sensibles (ej. /etc/shadow, /etc/passwd, /etc/sudoers)."""
    print(f"\n{Fore.CYAN}--- Verificando Permisos de Archivos Sensibles ---{Style.RESET_ALL}")
    sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
    for s_file in sensitive_files:
        if os.path.exists(s_file):
            permissions = oct(os.stat(s_file).st_mode)[-4:]
            
            if s_file == "/etc/shadow" and permissions not in ["0400", "0640"]:
                print_critical(f"Permisos débiles en {s_file}: {permissions}. Se espera 0400 o 0640.")
            elif s_file == "/etc/passwd" and permissions != "0644":
                print_medium(f"Permisos inesperados en {s_file}: {permissions}. Se espera 0644.")
            elif s_file == "/etc/sudoers" and permissions != "0440":
                print_critical(f"Permisos débiles en {s_file}: {permissions}. Se espera 0440.")
            else:
                print_info(f"Permisos correctos para {s_file}: {permissions}.")
        else:
            print_info(f"Archivo no encontrado: {s_file}")

def check_suspicious_connections():
    """Verifica conexiones de red sospechosas o puertos abiertos inusuales."""
    print(f"\n{Fore.CYAN}--- Verificando Conexiones de Red y Puertos Abiertos ---{Style.RESET_ALL}")
    try:
        netstat_output = subprocess.check_output(["netstat", "-tuln"]).decode('utf-8')
        print("Puertos abiertos (TCP/UDP en modo listening):")
        for line in netstat_output.splitlines():
            if "LISTEN" in line:
                if "127.0.0.1" in line or "::1" in line:
                    print_info(f"  {line.strip()} (Solo local)")
                else:
                    print_medium(f"  {line.strip()} (Puerto abierto globalmente - verificar si es intencional)")
        
        print("\nConexiones establecidas (ESTABLISHED):")
        established_connections = subprocess.check_output(["netstat", "-antp"]).decode('utf-8')
        
        suspicious_ports = []
        suspicious_ips = []

        for line in established_connections.splitlines():
            if "ESTABLISHED" in line and not "127.0.0.1" in line and not "::1" in line:
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", line)
                if match:
                    remote_ip = match.group(1)
                    remote_port = match.group(2)
                    
                    if remote_ip in suspicious_ips:
                        print_critical(f"Conexión sospechosa a IP conocida como maliciosa: {line.strip()}")
                    elif remote_port in suspicious_ports:
                        print_critical(f"Conexión sospechosa a puerto conocido como sospechoso: {line.strip()}")
                    elif remote_port not in ["22", "53", "80", "443"]:
                        print_medium(f"Conexión a puerto inusual: {line.strip()} (Puerto {remote_port})")
                    else:
                        print_info(f"Conexión establecida: {line.strip()}")
                else:
                    print_info(f"Conexión establecida: {line.strip()}")

    except FileNotFoundError:
        print_medium("Netstat no encontrado. Asegúrate de que esté instalado (ej. sudo apt install net-tools).")
    except Exception as e:
        print_medium(f"Error al verificar conexiones de red: {e}")

def check_running_services(full_analysis=False):
    """Lista los servicios en ejecución. En modo full_analysis, intenta listar todos."""
    print(f"\n{Fore.CYAN}--- Listando Servicios en Ejecución ---{Style.RESET_ALL}")
    try:
        if full_analysis:
            services_output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"]).decode('utf-8')
        else:
            services_output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--state=running"]).decode('utf-8')
        
        service_lines = [line for line in services_output.splitlines() if ".service" in line and "running" in line]
        
        if service_lines:
            print_info(f"Se encontraron {len(service_lines)} servicios en ejecución.")
            display_count = len(service_lines) if full_analysis else 10
            for service in service_lines[:display_count]:
                parts = service.split()
                if len(parts) >= 2:
                    print(f"  {parts[0]} - {parts[2]}")
                else:
                    print(f"  {service.strip()}")
            if not full_analysis and len(service_lines) > 10:
                print_info("... (usa --full para ver la lista completa)")
        else:
            print_info("No se encontraron servicios en ejecución (o el comando falló al listarlos).")
            
    except FileNotFoundError:
        print_medium("systemctl no encontrado. ¿Es un sistema basado en systemd?")
    except Exception as e:
        print_medium(f"Error al listar servicios: {e}")

def check_cron_jobs():
    """Verifica trabajos cron inusuales."""
    print(f"\n{Fore.CYAN}--- Verificando Trabajos Cron ---{Style.RESET_ALL}")
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=False)
        
        user_cron_output = result.stdout
        user_cron_error = result.stderr

        if result.returncode == 0:
            if user_cron_output.strip():
                print_medium("Se encontraron trabajos cron para el usuario actual. Revísalos:")
                print(f"{user_cron_output.strip()}")
            else:
                print_info("No hay trabajos cron para el usuario actual (crontab vacío).")
        elif result.returncode == 1:
            if "no crontab for" in user_cron_error.lower():
                print_info("No hay trabajos cron para el usuario actual.")
            else:
                print_medium(f"Error inesperado al verificar crontab de usuario: {user_cron_error.strip()}")
        else:
            print_medium(f"Error al verificar crontab de usuario (código: {result.returncode}): {user_cron_error.strip()}")


        print("\nVerificando directorios de cron del sistema:")
        cron_dirs = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]
        found_system_cron = False
        for c_dir in cron_dirs:
            if os.path.exists(c_dir) and os.path.isdir(c_dir):
                files = os.listdir(c_dir)
                files = [f for f in files if not f.startswith('.') and os.path.isfile(os.path.join(c_dir, f))]
                if files:
                    print_medium(f"Archivos encontrados en {c_dir}:")
                    for f in files:
                        print(f"  - {f}")
                    found_system_cron = True
        if not found_system_cron:
            print_info("No se encontraron trabajos cron en los directorios del sistema comunes.")

    except FileNotFoundError:
        print_medium("crontab no encontrado. Asegúrate de que esté instalado.")
    except Exception as e:
        print_medium(f"Error general al verificar cron: {e}")

def check_passwd_entries(full_analysis=False):
    """Verifica las entradas de /etc/passwd en busca de usuarios sospechosos (ej. UIDs 0 distintos de root)."""
    print(f"\n{Fore.CYAN}--- Verificando Entradas de /etc/passwd ---{Style.RESET_ALL}")
    try:
        with open("/etc/passwd", 'r') as f:
            passwd_lines = f.readlines()
        
        suspicious_users_found = False
        for line in passwd_lines:
            parts = line.strip().split(':')
            if len(parts) == 7:
                username = parts[0]
                uid = parts[2]
                gid = parts[3]
                shell = parts[6]

                if uid == '0' and username != 'root':
                    print_critical(f"El usuario '{username}' tiene UID 0 (privilegios de root). Esto es altamente sospechoso.")
                    suspicious_users_found = True
                
                if full_analysis:
                    if shell in ["/bin/nologin", "/usr/sbin/nologin", "/bin/false"]:
                        print_info(f"El usuario '{username}' tiene shell de nologin (esperado para cuentas de sistema).")
                    elif not os.path.exists(shell):
                        print_medium(f"El usuario '{username}' tiene un shell inexistente: {shell}. Verifícalo.")
                    
                    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
                        print_medium(f"El usuario '{username}' tiene un patrón de nombre de usuario inusual. Revísalo.")

        if not suspicious_users_found:
            print_info("No se encontraron usuarios sospechosos con UID 0 en /etc/passwd.")

    except FileNotFoundError:
        print_medium("Archivo /etc/passwd no encontrado.")
    except Exception as e:
        print_medium(f"Error al verificar /etc/passwd: {e}")

def check_sudoers_file():
    """Verifica el archivo /etc/sudoers en busca de entradas inusuales."""
    print(f"\n{Fore.CYAN}--- Verificando Archivo /etc/sudoers ---{Style.RESET_ALL}")
    sudoers_path = "/etc/sudoers"
    if not os.path.exists(sudoers_path):
        print_info("Archivo /etc/sudoers no encontrado.")
        return

    try:
        permissions = oct(os.stat(sudoers_path).st_mode)[-4:]
        if permissions != "0440":
            print_critical(f"Permisos incorrectos en {sudoers_path}: {permissions}. Se espera 0440. Esto es una vulnerabilidad crítica.")
        else:
            print_info(f"Permisos correctos para {sudoers_path}: {permissions}.")

        with open(sudoers_path, 'r') as f:
            sudoers_content = f.read()
        
        suspicious_entries = []
        for line in sudoers_content.splitlines():
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith('#') and "NOPASSWD:" in stripped_line:
                suspicious_entries.append(stripped_line)
        
        if suspicious_entries:
            print_medium("Se encontraron entradas 'NOPASSWD' en /etc/sudoers. Revísalas cuidadosamente:")
            for entry in suspicious_entries:
                print(f"  - {entry}")
            print_medium("Asegúrate de que estas entradas sean legítimas y no proporcionen acceso sudo sin contraseña innecesario.")
        else:
            print_info("No se encontraron entradas 'NOPASSWD' explícitas en /etc/sudoers (excluyendo comentarios).")

    except Exception as e:
        print_medium(f"Error al verificar /etc/sudoers: {e}")

# --- Función Principal de Análisis ---

def analyze_linux_system(full_analysis=False):
    """Ejecuta todas las verificaciones de seguridad."""

    # --- Banner o Marca de Agua (ASCII Art) ---
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print(r"""

██████╗  ██████╗ ███╗   ██╗██╗   ██╗███████╗███╗   ██╗ ██████╗ ███████╗ █████╗ ███╗   ██╗ ██████╗███████╗
██╔══██╗██╔═══██╗████╗  ██║██║   ██║██╔════╝████╗  ██║██╔════╝ ██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝
██║  ██║██║   ██║██╔██╗ ██║██║   ██║█████╗  ██╔██╗ ██║██║  ███╗█████╗  ███████║██╔██╗ ██║██║     █████╗  
██║  ██║██║   ██║██║╚██╗██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██╔══██║██║╚██╗██║██║     ██╔══╝  
██████╔╝╚██████╔╝██║ ╚████║ ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝███████╗██║  ██║██║ ╚████║╚██████╗███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝

    """)
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  Linux Security Analyzer - Creado por DonVengeance{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  Version 1.0.0{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  GitHub: https://github.com/DontVengeance{Style.RESET_ALL}")
    print(f"{Fore.BLUE}--- Iniciando Análisis de Seguridad del Sistema Linux ---{Style.RESET_ALL}")

    check_ssh_config()
    check_unsecured_files_permissions()
    check_suspicious_connections()
    check_running_services(full_analysis)
    check_cron_jobs()

    if full_analysis:
        print(f"\n{Fore.MAGENTA}--- Realizando Análisis Exhaustivo (modo --full) ---{Style.RESET_ALL}")
        check_passwd_entries(full_analysis)
        check_sudoers_file()
        # Aquí puedes añadir más verificaciones exhaustivas para el modo --full
        # Por ejemplo: check_installed_packages(), check_active_logins(), etc.

    print(f"\n{Fore.BLUE}--- Análisis Completado ---{Style.RESET_ALL}")
    print(f"{Fore.RED}Revisa los elementos marcados como CRÍTICO.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Revisa los elementos marcados como MEDIO para posibles mejoras.{Style.RESET_ALL}")

# --- Bloque de Ejecución Principal ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Una herramienta básica para analizar la seguridad de un sistema Linux.\n"
                    "Busca configuraciones débiles, posibles backdoors y otras debilidades.\n"
                    "Los resultados se muestran con colores para indicar la severidad.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-f', '--full',
        action='store_true',
        help='Realiza un análisis de seguridad más exhaustivo, incluyendo verificaciones adicionales.'
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0.0',
        help="Muestra el número de versión del programa y sale."
    )

    args = parser.parse_args()

    if os.geteuid() != 0:
        print_critical("Este script necesita ser ejecutado con permisos de root (sudo).")
        print("Ejemplo: sudo python3 tu_script_nombre.py")
    else:
        analyze_linux_system(full_analysis=args.full)

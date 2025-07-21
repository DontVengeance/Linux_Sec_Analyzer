# Linux Security Analyzer 🛡️

Un script de Python simple para realizar un análisis de seguridad básico en sistemas Linux. Busca configuraciones incorrectas comunes, permisos inseguros y otros posibles indicadores de compromiso para ayudarte a fortalecer la seguridad de tu sistema.

El script utiliza un sistema de colores para clasificar la severidad de los hallazgos, facilitando la identificación de los problemas más urgentes.

## 📋 Características Principales

- **Análisis de Configuración SSH**: Revisa el archivo `/etc/ssh/sshd_config` en busca de configuraciones peligrosas como `PermitRootLogin yes`.
    
- **Verificación de Permisos**: Comprueba los permisos de archivos críticos como `/etc/passwd`, `/etc/shadow` y `/etc/sudoers`.
    
- **Monitoreo de Red**: Lista los puertos abiertos y las conexiones establecidas usando `netstat` para identificar actividad sospechosa.
    
- **Revisión de Servicios**: Muestra los servicios que se están ejecutando actualmente con `systemctl`.
    
- **Inspección de Tareas Programadas (Cron)**: Busca trabajos cron configurados para el usuario actual y en los directorios del sistema.
    
- **Auditoría de Usuarios (Modo `--full`)**: Revisa `/etc/passwd` en busca de usuarios no autorizados con privilegios de root (UID 0).
    
- **Análisis de `sudoers` (Modo `--full`)**: Busca reglas `NOPASSWD` que permitan a usuarios ejecutar comandos como root sin contraseña.
    

## ⚙️ Requisitos e Instalación

Antes de ejecutar el script, asegúrate de tener lo siguiente:

1. **Python 3**: El script está escrito en Python 3.
    
2. **Librería `colorama`**: Se usa para mostrar los resultados en colores. Instálala con pip:

```bash
pip install colorama
```

3.  **Herramientas de Red**: El script utiliza `netstat` para analizar las conexiones. Si no está instalado, puedes instalarlo en sistemas basados en Debian/Ubuntu con:
 
```bash
sudo apt update sudo apt install net-tools
```

## 🚀 Uso del Script

El script **debe ejecutarse con privilegios de superusuario (sudo)** para poder acceder a los archivos y comandos del sistema necesarios.

1. Clona o descarga el repositorio.
    
2. Navega al directorio del script.
    
3. Ejecuta el análisis básico:

```bash
sudo python3 nombre_del_script.py
```

### Análisis Completo

Para un análisis más profundo que incluye la revisión de todos los usuarios y el archivo `sudoers`, utiliza la bandera `-f` o `--full`:

```shell
sudo python3 nombre_del_script.py --full
```

## 📊 Entendiendo los Resultados

El script clasifica los hallazgos en tres niveles de severidad:

- 🔴 **CRÍTICO**: Indica una vulnerabilidad grave que debe ser corregida de inmediato. Por ejemplo, permitir el acceso root por SSH.
    
- 🟡 **MEDIO**: Es una advertencia sobre una configuración que podría ser insegura. Se recomienda revisarla para mejorar la seguridad.
    
- 🟢 **INFO**: Muestra que una configuración es correcta o simplemente proporciona datos informativos sobre el sistema.
    

## 🖼️ Ejemplos de Funcionamiento

![[imagen1.png]]

**Sistema Seguro (Ejemplo Básico)**

![[imagen2.png]]

**Vulnerabilidad Detectada (Ejemplo)**

## ✍️ Autor

Creado por **DonVengeance**.

- **GitHub**: [https://github.com/DontVengeance](https://github.com/DontVengeance)

**Disclaimer**: Esta herramienta proporciona un análisis básico y no debe considerarse una auditoría de seguridad completa. Úsala como un punto de partida para fortalecer tu sistema. El autor no se hace responsable del uso que se le dé a este script.
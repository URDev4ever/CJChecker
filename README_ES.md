<h1 ALIGN="center">CJChecker</h1>
<p align="center"> 🇺🇸 <a href="README.md"><b>English</b></a> | 🇪🇸 <a href="README_ES.md">Español</a> </p>
<p align="center">
 <img width="423" height="87" alt="image" src="https://github.com/user-attachments/assets/5b2b398f-1bc2-4b25-9212-4e7e2c4708c0" />
</p>

<h3 align="center">
  CJChecker es una herramienta ligera de línea de comandos que analiza aplicaciones web en busca de protección básica contra Clickjacking mediante el análisis de los encabezados de respuesta HTTP.

Se centra en identificar la presencia de mecanismos anti-clickjacking comunes como `X-Frame-Options` y `Content-Security-Policy`, sin intentar confirmar la explotación.

</h3>

---

## Características

* Detecta el encabezado **X-Frame-Options** y evalúa su valor
* Detecta **Content-Security-Policy** y comprueba la directiva `frame-ancestors`
* Soporta escaneo de una sola URL y escaneo masivo desde un archivo
* Escaneo concurrente con número de *workers* configurable
* Salida en terminal coloreada y legible
* Reporte resumen para escaneos masivos
* Salida opcional a archivo
* Códigos de salida adecuados para uso en scripts

---

## Requisitos

* Python **3.8+**
* Acceso a Internet hacia las URLs objetivo

### Dependencias de Python

* `requests`

Instala las dependencias con:

```bash
pip install requests
```

---

## Instalación

Clona el repositorio:

```bash
git clone https://github.com/urdev4ever/cjchecker.git
cd cjchecker
```

(Opcional) Haz el script ejecutable:

```bash
chmod +x cjchecker.py
```

---

## Uso

### Escanear una sola URL

```bash
python3 cjchecker.py -u https://example.com
```

<img width="574" height="384" alt="image" src="https://github.com/user-attachments/assets/9d6c7752-62bc-4f25-b084-884efd624b88" />

---

### Escanear múltiples URLs desde un archivo

```bash
python3 cjchecker.py -l urls.txt
```

<img width="431" height="480" alt="image" src="https://github.com/user-attachments/assets/c6bc1d77-2e48-4d73-9c5b-2dd92b2ead32" />

---

### Establecer timeout de la petición

```bash
python3 cjchecker.py -u https://example.com -t 5
```

### Establecer número de workers concurrentes

```bash
python3 cjchecker.py -l urls.txt -w 10
```

### Guardar resultados en un archivo

```bash
python3 cjchecker.py -l urls.txt -o results.txt
```

---

## Formato del archivo de entrada

Al usar el modo lista (`-l`), el archivo debe contener una URL por línea:

```txt
https://example.com
https://test.example
example.org
# las líneas que comienzan con # se ignoran
```

Las URLs sin esquema usarán `https://` por defecto.

---

## Salida

Para cada objetivo escaneado, CJChecker muestra:

* URL objetivo
* Código de estado HTTP
* Tiempo de respuesta
* Encabezados relacionados con clickjacking detectados
* Estado general de seguridad
* Recomendaciones cuando las protecciones están ausentes o son débiles

### Estado de seguridad

* **PROTEGIDO** → Se detectó al menos una defensa contra clickjacking
* **VULNERABLE** → No se encontró ninguna protección contra clickjacking

### Reporte resumen (modo lista)

* Total de URLs escaneadas
* Comprobaciones exitosas
* Objetivos protegidos vs vulnerables
* Porcentaje de protección
* Lista de URLs vulnerables

---

## Lógica de detección

Un objetivo se considera **protegido** si está presente al menos uno de los siguientes:

* `X-Frame-Options: DENY`
* `X-Frame-Options: SAMEORIGIN`
* `Content-Security-Policy` que contenga la directiva `frame-ancestors`

CJChecker evita intencionalmente el análisis profundo de CSP para reducir falsos positivos.

---

## Limitaciones

* Detección basada únicamente en encabezados
* No se realizan intentos de explotación ni pruebas con iframes
* No se ejecuta JavaScript ni se analiza el DOM
* Las redirecciones se siguen automáticamente
* Los resultados indican presencia de defensas, no explotabilidad real

---

## Códigos de salida

* `0` → Todas las URLs verificadas están protegidas
* `1` → Se encontró una o más URLs vulnerables
* `130` → Escaneo interrumpido por el usuario (Ctrl+C)

---

## Contribuir

Las pull requests son bienvenidas si:

* Mejoran la precisión en la detección de headers, el manejo de casos límite o la confiabilidad del parsing de respuestas
* Mejoran el rendimiento en escaneos masivos, la estabilidad de la concurrencia o la claridad del output sin aumentar la complejidad innecesaria
* Mantienen la filosofía ligera y basada en headers (sin intentos de explotación, sin PoCs con iframes, sin comportamiento intrusivo)

---

## Descargo de responsabilidad

Esta herramienta está destinada únicamente a fines educativos y de seguridad defensiva.
Los resultados deben tratarse como indicadores, no como vulnerabilidades confirmadas.

---

hecho con <3 por URDev

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&height=120&section=header&text=FBBisturi&fontSize=48&fontColor=00FFFF&animation=twinkle&color=0,10,20,30,40,50" />
</p>



<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Orbitron&size=18&pause=1000&color=FF0055&center=true&vCenter=true&width=650&lines=OBSERVING+NETWORK+SIGNALS...;CORRELATING+DOMAIN+DATA...;BACKEND+FINGERPRINTING...;SECURE+FORENSIC+MODE+ACTIVE" />
</p>
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=16&pause=900&color=FFAA00&center=true&vCenter=true&width=700&lines=ACTIVATING+FORENSIC+CORE...;SIGNAL+PROCESSING+INITIATED...;LATENCY+AND+ENTROPY+MEASURED...;READY+FOR+ANALYSIS" />
</p>
 
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Roboto+Mono&size=18&pause=1200&color=00FFAA&center=true&vCenter=true&width=600&lines=PROBING+HOSTS...;SCANNING+ROUTES...;DETECTING+GATES+AND+SERVERS...;CRITICAL+SIGNALS+FOUND" />
</p>
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=18&pause=800&color=FF33FF&center=true&vCenter=true&width=700&lines=CAPTURING+ENTROPY+SIGNALS...;MAPPING+ROUTES+FOR+ANALYSIS...;CLASSIFYING+LATENCY+IMPACT...;FORENSIC+VISUALIZER+ACTIVE" />
</p>
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Orbitron&size=20&pause=1000&color=00FFD5&center=true&vCenter=true&width=650&lines=FORNSIC+ENGINE+ONLINE;NEON+ALCHEMY+ACTIVATED;SURGICAL+TRACE+MODE;SIGNALS+BEING+CORRELATED" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/FORENSIC--ENGINE-LIVE%20INTELLIGENCE-00ffd5?style=for-the-badge" />
  <img src="https://img.shields.io/badge/TELEMETRY-OPEN%20TELEMETRY-7c4dff?style=for-the-badge" />
  <img src="https://img.shields.io/badge/ANALYSIS-SURGICAL%20MODE-ff006e?style=for-the-badge" />
</p>

<p align="center">
🧠 Observabilidad profunda · ⏱️ Huellas temporales · 🧬 Entropía · 🛡️ Ética forense
</p>

---

## 🌌 ¿Qué es **BISTURÍ**?

**BISTURÍ** es una herramienta de **análisis forense de comportamiento backend**.

No escanea. No explota. No fuerza.

👉 **Observa, compara y deduce** cómo se comporta un sistema web **desde fuera**, usando únicamente:

* diferencias temporales
* variaciones semánticas
* entropía de respuestas
* trazas de telemetría

Es un **estetoscopio digital** para sistemas vivos.

---

## 🧬 Filosofía de diseño

> *"No rompo sistemas. Los entiendo mejor que nadie."*

BISTURÍ está construido bajo principios **forenses y éticos**:

* 🧘‍♂️ **No intrusivo** – solo HTTP estándar
* 🧠 **Causal, no ruidoso** – señales, no floods
* ⚖️ **Ético por diseño** – requiere token explícito
* 🔍 **Comparativo** – el poder está en las diferencias

Nada aquí busca evadir defensas.
Todo aquí busca **comprender arquitectura, rutas y capas**.

---

## 🧠 ¿Para qué sirve realmente?

### 🏗️ Arquitectura & SRE

* Detectar **múltiples backends** detrás de un dominio
* Identificar **CDN, WAF, edge vs origin**
* Ver **colas, balanceadores y rutas asíncronas**

### 🛡️ Blue Team & Forense

* Analizar **gates lógicos (401/403)**
* Detectar **rutas protegidas vs públicas**
* Entender **comportamiento por User-Agent**

### 🧪 Debugging avanzado

* Cambios de serialización
* Plantillas dinámicas vs rígidas
* Respuestas cacheadas vs generadas

### 📊 Auditoría técnica

* Comparar entornos
* Validar coherencia de infraestructura
* Detectar exposición accidental

---

## 🔬 ¿Qué analiza?

### ⏱️ Huella temporal

* Media
* Desviación estándar
* Jitter

👉 Revela colas, dependencias internas y routing.

---

### 🧬 Entropía de respuesta

Usa **entropía de Shannon** para estimar:

* respuestas rígidas (edge / cache)
* serialización dinámica
* backends data-driven

Interpretación humana incluida.

---

### 🌐 Diferencias por User-Agent

Compara:

* Desktop
* Mobile
* Cliente de servicio

👉 Detecta **rutas lógicas distintas** según contexto declarado.

---

### 🧿 Forense de rutas

* Métodos seguros (GET / HEAD / OPTIONS)
* Entropía por método
* Status diferenciales
* Headers `Allow`

👉 Identifica **gates, routers y placeholders**.

---

### 🌍 Forense de dominio

* `example.com`
* `www.example.com`
* Variantes canónicas

Detecta:

* multi-backend
* divergencia de representación
* routing cruzado

---

## 🛰️ Telemetría viva (OpenTelemetry)

Cada acción genera **spans forenses** con:

* identidad del instrumento
* clasificación temporal
* severidad semántica
* marcas para correlación futura

Todo se visualiza en consola **NEON CRYSTAL**.

---

## 🎨 Interfaz (NEON CRYSTAL)

* Panels reactivos
* Alertas visuales
* Tablas comparativas
* Lectura humana inmediata

No necesitas dashboards externos.

La consola **vive contigo** durante el análisis.

---

## 🔐 Seguridad & ética

* Requiere **token explícito**
* Headers declaran intención diagnóstica
* Sin payloads
* Sin fuzzing
* Sin explotación

Diseñado para:

* laboratorios
* entornos autorizados
* auditorías conscientes

---

## 🚀 Cómo usarlo

```bash
python FBBisturi.py
```

Luego:

1. Introduce una **URL autorizada**
2. Introduce un **token diagnóstico**
3. Observa las señales

---

## 🧠 Cómo leer los resultados

* **Latencias altas** → gates / colas
* **Entropía baja** → edge / cache
* **Entropía alta** → backend dinámico
* **Cambios por UA** → lógica condicionada
* **Divergencia entre hosts** → multi-backend

No hay "vulnerable".
Hay **interpretaciones**.

---

## 🧩 ¿Qué NO es?

❌ Scanner de vulnerabilidades
❌ Herramienta de ataque
❌ Pentesting agresivo

BISTURÍ es **observación avanzada**.

---

## 🌱 Futuro del proyecto

Ideas naturales de evolución:

* Memoria forense entre ejecuciones
* Modo pasivo 100%
* Exportación de trazas
* Timeline histórico
* Visualización gráfica

---

## 🧿 Mantra final

> *"Los sistemas hablan.
> Solo hay que aprender a escucharlos."*
> Autor: ByMakaveli
> El futuro empieza con un primer paso y no importa si es pequeño.

---
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=24&pause=1000&color=00FFDD&center=true&vCenter=true&width=700&lines=ByMakaveli;HUNTER+HACKER+NINJA;PHILOSOPHY+IN+CODE;SHADOWS+OF+THE+NET" />
</p>

<p align="center">
⚡ Hecho con mente clara, ética firme y curiosidad infinita ⚡
</p>


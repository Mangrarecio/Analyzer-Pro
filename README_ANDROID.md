# 🤖 Android App Analyzer Pro

Analizador completo de aplicaciones Android que soporta JavaScript, archivos DEX, SMALI y APK completos.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.31.0-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 📋 Descripción

**Android App Analyzer Pro** es una herramienta avanzada para analizar aplicaciones Android en profundidad. Soporta múltiples formatos y proporciona análisis exhaustivos de seguridad, permisos, recursos y código.

## ✨ Características Principales

### 📱 Formatos Soportados

- **JavaScript/JSX**: Análisis de código React Native y WebView
- **DEX (Dalvik Executable)**: Archivos compilados de Android
- **SMALI**: Lenguaje ensamblador de Android
- **APK**: Análisis completo de aplicaciones Android

### 🔧 Funcionalidades

#### 🏠 Conversión Básica
- Conversión de JS/JSX a texto plano
- Lectura y formateo de archivos SMALI
- Extracción de información de archivos DEX
- Numeración de líneas y metadatos

#### 📱 Análisis de JavaScript
- Contador de funciones, clases y componentes
- Detección de componentes React/React Native
- Análisis de dependencias (imports/requires)
- Detección de problemas de seguridad
- Estadísticas completas de código

#### 🔧 Análisis DEX/SMALI
- Parseo de estructura DEX
- Contador de clases, métodos y strings
- Lectura de archivos SMALI
- Extracción de información de bytecode
- Análisis de complejidad

#### 📦 Análisis de APK Completo
- Extracción de todos los archivos
- Análisis del AndroidManifest.xml
- Detección de permisos (normales y peligrosos)
- Extracción de recursos (strings.xml, layouts, etc.)
- Análisis de Activities, Services, Receivers
- Detección de librerías nativas (.so)
- Generación de reportes completos

#### 🔐 Seguridad y Permisos
- Detección de permisos peligrosos
- Análisis de código malicioso
- Verificación de URLs HTTP vs HTTPS
- Detección de API keys hardcoded
- Análisis de uso de eval() e innerHTML
- Verificación de almacenamiento inseguro

#### 📊 Recursos y Manifiestos
- Lectura del AndroidManifest.xml
- Extracción de strings.xml
- Análisis de archivos Gradle
- Listado de recursos (imágenes, layouts, etc.)
- Información de versiones y SDK

#### 🔍 Dependencias y Librerías
- Detección de librerías nativas por arquitectura
- Análisis de dependencias JavaScript
- Identificación de frameworks usados
- Listado de librerías Android

#### ⚖️ Comparación de Versiones
- Comparar dos versiones de APK
- Detectar cambios en permisos
- Identificar archivos nuevos/eliminados
- Calcular diferencia de tamaño
- Generar reporte de diferencias

## 🚀 Instalación Local

### Requisitos previos
- Python 3.8 o superior
- pip

### Pasos de instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/TU_USUARIO/android-app-analyzer.git
cd android-app-analyzer
```

2. **Instalar dependencias**
```bash
pip install -r requirements_android.txt
```

3. **Ejecutar la aplicación**
```bash
streamlit run android_app.py
```

4. **Abrir en el navegador**
La aplicación se abrirá en `http://localhost:8501`

## ☁️ Despliegue en Streamlit Cloud

1. Sube los archivos a GitHub
2. Ve a [Streamlit Cloud](https://share.streamlit.io)
3. Conecta tu repositorio
4. Selecciona `android_app.py` como archivo principal
5. ¡Deploy!

## 📖 Cómo Usar

### Analizar JavaScript/React Native

1. Ve a **"📱 Análisis de JavaScript"**
2. Sube tus archivos .js o .jsx
3. Explora las diferentes pestañas:
   - Estadísticas: Métricas del código
   - Funciones y Clases: Elementos detectados
   - Dependencias: Imports y requires
   - Problemas: Issues de seguridad

### Analizar Archivos DEX

1. Ve a **"🔧 Análisis DEX/SMALI"**
2. Selecciona "DEX (.dex)"
3. Sube tu archivo classes.dex
4. Visualiza:
   - Número de clases y métodos
   - Strings en el DEX
   - Estructura del archivo

### Analizar Archivos SMALI

1. Ve a **"🔧 Análisis DEX/SMALI"**
2. Selecciona "SMALI (.smali)"
3. Sube tus archivos .smali
4. Lee el código ensamblador

### Analizar APK Completo

1. Ve a **"📦 Análisis de APK Completo"**
2. Sube tu archivo .apk
3. Selecciona opciones de análisis
4. Explora:
   - Información general
   - Permisos solicitados
   - AndroidManifest.xml
   - Recursos extraídos
   - Reporte completo

### Análisis de Seguridad

1. Ve a **"🔐 Seguridad y Permisos"**
2. Sube APK o código fuente
3. Ejecuta el escaneo
4. Revisa problemas por severidad:
   - 🔴 Alto: Requiere atención inmediata
   - 🟡 Medio: Revisar cuando sea posible
   - 🔵 Bajo: Informativo

### Comparar Versiones

1. Ve a **"⚖️ Comparación de Versiones"**
2. Sube la versión original
3. Sube la versión nueva
4. Visualiza diferencias

## 🎯 Casos de Uso

### Desarrollo de Apps
- Analizar tu propia aplicación antes del release
- Verificar permisos solicitados
- Revisar dependencias usadas
- Detectar problemas de seguridad

### Seguridad y Auditoría
- Análisis de seguridad de APKs de terceros
- Detección de malware básico
- Verificación de permisos excesivos
- Análisis de código ofuscado

### Ingeniería Inversa (Legal)
- Estudiar estructura de aplicaciones
- Entender flujo de la app
- Extraer recursos
- Análisis educativo

### Testing y QA
- Comparar versiones antes/después de cambios
- Verificar que no se agregaron permisos innecesarios
- Revisar tamaño de la app
- Validar builds

## 📁 Estructura del Proyecto

```
android-app-analyzer/
│
├── android_app.py              # Aplicación principal
├── android_converter.py        # Funciones de análisis
├── requirements_android.txt    # Dependencias
├── README_ANDROID.md          # Este archivo
├── .gitignore                 # Archivos a ignorar
└── .streamlit/
    └── config.toml            # Configuración de tema
```

## 🛠️ Tecnologías Utilizadas

- **Python 3.8+**: Lenguaje principal
- **Streamlit**: Framework web
- **zipfile**: Manejo de APKs (archivos ZIP)
- **re (regex)**: Análisis de patrones
- **json**: Manejo de datos

## ⚠️ Limitaciones

- **Manifest XML**: Los archivos AndroidManifest.xml en APKs están en formato binario (AXML). Para parsing completo se recomienda usar `androguard`
- **DEX parsing**: El parseo de DEX es básico. Para análisis avanzado usar `dex2jar` o `baksmali`
- **Descompilación**: No incluye descompilación completa de DEX a Java (usar `jadx` externamente)
- **Ofuscación**: El código ofuscado es difícil de analizar
- **Archivos grandes**: APKs muy grandes pueden tardar en procesarse

## 🔮 Mejoras Futuras

- [ ] Integración con `androguard` para parsing completo
- [ ] Soporte para descompilación DEX→Java
- [ ] Análisis de flujo de datos
- [ ] Detección avanzada de malware
- [ ] Generación de reportes PDF detallados
- [ ] Análisis de tráfico de red
- [ ] Soporte para AAB (Android App Bundle)
- [ ] Análisis de permisos runtime

## 🔧 Herramientas Complementarias

Para análisis más avanzado, considera usar:

- **apktool**: Descompilación de APK
- **jadx**: DEX a Java
- **baksmali/smali**: DEX a SMALI y viceversa
- **androguard**: Análisis Python de APKs
- **dex2jar**: DEX a JAR
- **jd-gui**: Visualizar código Java

## 📝 Ejemplo de Uso

```python
# Ejemplo de cómo usar las funciones internamente

from android_converter import analyze_js_statistics

# Analizar archivo JavaScript
with open('app.js', 'rb') as f:
    stats = analyze_js_statistics([f])
    print(f"Funciones: {stats['functions']}")
    print(f"Componentes React: {stats['react_components']}")
```

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas!

1. Fork del repositorio
2. Crea tu rama (`git checkout -b feature/NuevaCaracteristica`)
3. Commit (`git commit -m 'Agregar nueva característica'`)
4. Push (`git push origin feature/NuevaCaracteristica`)
5. Abre un Pull Request

## ⚖️ Consideraciones Legales

**IMPORTANTE**: Esta herramienta está diseñada para:
- Análisis de tus propias aplicaciones
- Investigación de seguridad ética
- Propósitos educativos
- Auditorías autorizadas

**NO usar para:**
- Ingeniería inversa no autorizada
- Distribución de código pirata
- Violación de términos de servicio
- Actividades ilegales

Respeta siempre los derechos de autor y licencias.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT.

## 👨‍💻 Autor

Desarrollado con ❤️ por [Tu Nombre]

## 📧 Contacto

- GitHub Issues: Para reportar bugs
- Pull Requests: Para contribuciones

---

**Nota**: Esta herramienta proporciona análisis básico/intermedio. Para análisis forense profesional o de malware, usar herramientas especializadas.

⭐ Si te resultó útil, considera darle una estrella en GitHub ⭐

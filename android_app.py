import streamlit as st
import os
from pathlib import Path
import zipfile
import io
from android_converter import (
    convert_js_to_txt,
    analyze_js_statistics,
    parse_dex_file,
    parse_smali_file,
    decompile_apk,
    analyze_manifest,
    extract_resources,
    detect_permissions,
    analyze_dependencies,
    detect_security_issues_android,
    generate_apk_report,
    compare_apk_versions,
    extract_strings_xml,
    analyze_gradle_files,
    detect_native_libs
)

# Configuración de la página
st.set_page_config(
    page_title="Android App Analyzer Pro",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado para fondo claro y texto en negrita
st.markdown("""
    <style>
    .main {
        background-color: #f8f9fa;
    }
    
    [data-testid="stSidebar"] {
        background-color: #e9ecef;
    }
    
    body, p, div, span, label, h1, h2, h3, h4, h5, h6 {
        font-weight: bold !important;
    }
    
    h1, h2, h3 {
        color: #212529;
        font-weight: 900 !important;
    }
    
    .stButton>button {
        font-weight: bold;
        border: 2px solid #495057;
    }
    
    code {
        background-color: #e9ecef;
        color: #212529;
        font-weight: bold;
    }
    
    .stSelectbox label {
        color: #212529;
        font-weight: bold;
    }
    
    .stAlert {
        background-color: #ffffff;
        border: 2px solid #495057;
    }
    
    .metric-card {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #4CAF50;
        margin: 10px 0;
    }
    </style>
""", unsafe_allow_html=True)

# Título principal
st.title("🤖 Android App Analyzer Pro")
st.markdown("**Analizador de código Android: JavaScript, DEX, SMALI, Manifiestos**")
st.info("**ℹ️ Nota:** Por restricciones de seguridad, no se pueden subir APKs completos. Descompila primero con apktool y sube archivos individuales.")

# Sidebar con categorías
st.sidebar.title("📋 Categorías")
st.sidebar.markdown("---")

categoria = st.sidebar.radio(
    "**Selecciona una categoría:**",
    [
        "🏠 Conversión Básica",
        "📱 Análisis de JavaScript",
        "🔧 Análisis DEX/SMALI",
        "📊 Análisis de Manifiestos",
        "🔐 Seguridad de Código",
        "🔍 Dependencias JavaScript",
        "📝 Análisis Gradle/Config",
        "💡 Guía de Uso"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("**💡 Tip:** Sube archivos .js, .dex, .smali o AndroidManifest.xml")
st.sidebar.warning("**⚠️ Nota:** Por seguridad, no se pueden subir archivos APK completos. Extrae los archivos individualmente.")

# ==================== CONVERSIÓN BÁSICA ====================
if categoria == "🏠 Conversión Básica":
    st.header("Conversión Básica de Archivos Android")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("**Subir Archivos**")
        file_type = st.selectbox(
            "**Tipo de archivo:**",
            ["JavaScript (.js, .jsx)", "SMALI (.smali)", "DEX (.dex)", "Todos"]
        )
        
        if file_type == "JavaScript (.js, .jsx)":
            extensions = ['js', 'jsx']
        elif file_type == "SMALI (.smali)":
            extensions = ['smali']
        elif file_type == "DEX (.dex)":
            extensions = ['dex']
        else:
            extensions = ['js', 'jsx', 'smali', 'dex']
        
        uploaded_files = st.file_uploader(
            "**Arrastra o selecciona archivos**",
            type=extensions,
            accept_multiple_files=True,
            key="basic_upload"
        )
    
    with col2:
        st.subheader("**Opciones**")
        preserve_comments = st.checkbox("**Preservar comentarios**", value=True)
        add_line_numbers = st.checkbox("**Numerar líneas**", value=False)
        add_metadata = st.checkbox("**Agregar metadatos**", value=True)
        beautify_code = st.checkbox("**Formatear código**", value=True)
    
    if uploaded_files:
        st.success(f"**✅ {len(uploaded_files)} archivo(s) cargado(s)**")
        
        if st.button("**🔄 Convertir Archivos**", key="convert_basic"):
            with st.spinner("**Convirtiendo archivos...**"):
                result = convert_js_to_txt(
                    uploaded_files,
                    preserve_comments=preserve_comments,
                    add_line_numbers=add_line_numbers,
                    add_metadata=add_metadata,
                    beautify_code=beautify_code
                )
                
                st.text_area("**📄 Contenido Convertido:**", result, height=400)
                
                st.download_button(
                    label="**⬇️ Descargar como .txt**",
                    data=result,
                    file_name="android_code_converted.txt",
                    mime="text/plain"
                )

# ==================== ANÁLISIS DE JAVASCRIPT ====================
elif categoria == "📱 Análisis de JavaScript":
    st.header("Análisis Completo de Código JavaScript")
    
    uploaded_files = st.file_uploader(
        "**Subir archivos JavaScript (.js, .jsx)**",
        type=['js', 'jsx'],
        accept_multiple_files=True,
        key="js_upload"
    )
    
    if uploaded_files:
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "**📊 Estadísticas**",
            "**🔍 Funciones y Clases**",
            "**📦 Dependencias**",
            "**⚠️ Problemas Detectados**",
            "**🎨 Exportar**"
        ])
        
        with tab1:
            st.subheader("**Estadísticas del Código JavaScript**")
            if st.button("**Analizar Estadísticas**", key="analyze_js_stats"):
                stats = analyze_js_statistics(uploaded_files)
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("**Líneas Totales**", stats['total_lines'])
                with col2:
                    st.metric("**Funciones**", stats['functions'])
                with col3:
                    st.metric("**Componentes React**", stats.get('react_components', 0))
                with col4:
                    st.metric("**Archivos**", stats['files'])
                
                st.markdown("### **Detalles Completos:**")
                st.json(stats)
        
        with tab2:
            st.subheader("**Funciones y Componentes Detectados**")
            if st.button("**Listar Elementos**", key="list_js_elements"):
                stats = analyze_js_statistics(uploaded_files)
                
                if stats.get('function_list'):
                    st.markdown("**🔹 Funciones encontradas:**")
                    for func in stats['function_list']:
                        st.code(f"function {func}()", language="javascript")
                
                if stats.get('class_list'):
                    st.markdown("**🔹 Clases/Componentes:**")
                    for cls in stats['class_list']:
                        st.code(f"class {cls}", language="javascript")
        
        with tab3:
            st.subheader("**Análisis de Dependencias**")
            if st.button("**Analizar Imports**", key="analyze_js_deps"):
                deps = analyze_dependencies(uploaded_files)
                
                st.markdown("**📦 Dependencias externas:**")
                for file, imports in deps.items():
                    with st.expander(f"📄 {file}"):
                        for imp in imports:
                            st.write(f"- `{imp}`")
        
        with tab4:
            st.subheader("**Problemas y Advertencias**")
            if st.button("**Escanear Código**", key="scan_js_issues"):
                issues = detect_security_issues_android(uploaded_files, 'javascript')
                
                if issues:
                    for issue in issues:
                        if issue['severity'] == 'HIGH':
                            st.error(f"**🔴 {issue['type']}:** {issue['description']}")
                        elif issue['severity'] == 'MEDIUM':
                            st.warning(f"**🟡 {issue['type']}:** {issue['description']}")
                        else:
                            st.info(f"**🔵 {issue['type']}:** {issue['description']}")
                else:
                    st.success("**✅ No se detectaron problemas**")
        
        with tab5:
            st.subheader("**Exportar Análisis**")
            formato = st.selectbox("**Formato:**", ["Markdown", "HTML", "JSON", "TXT"])
            
            if st.button("**Generar Reporte**", key="export_js"):
                stats = analyze_js_statistics(uploaded_files)
                
                if formato == "JSON":
                    import json
                    output = json.dumps(stats, indent=2)
                    st.download_button("**⬇️ Descargar JSON**", output, "js_analysis.json")
                else:
                    st.info("**Generando reporte...**")

# ==================== ANÁLISIS DEX/SMALI ====================
elif categoria == "🔧 Análisis DEX/SMALI":
    st.header("Análisis de Archivos DEX y SMALI")
    
    st.info("**ℹ️ Los archivos DEX contienen el bytecode compilado de Android. SMALI es su representación en lenguaje ensamblador.**")
    
    file_type = st.radio("**Tipo de archivo:**", ["DEX (.dex)", "SMALI (.smali)"])
    
    if file_type == "DEX (.dex)":
        uploaded_files = st.file_uploader(
            "**Subir archivos DEX**",
            type=['dex'],
            accept_multiple_files=True,
            key="dex_upload"
        )
        
        if uploaded_files:
            tab1, tab2, tab3 = st.tabs([
                "**🔍 Estructura DEX**",
                "**📊 Estadísticas**",
                "**💾 Extraer SMALI**"
            ])
            
            with tab1:
                st.subheader("**Analizar Estructura DEX**")
                if st.button("**Analizar DEX**", key="analyze_dex"):
                    for dex_file in uploaded_files:
                        with st.expander(f"📦 {dex_file.name}"):
                            dex_info = parse_dex_file(dex_file)
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("**Clases**", dex_info.get('class_count', 0))
                            with col2:
                                st.metric("**Métodos**", dex_info.get('method_count', 0))
                            with col3:
                                st.metric("**Strings**", dex_info.get('string_count', 0))
                            
                            st.json(dex_info)
            
            with tab2:
                st.subheader("**Estadísticas Detalladas**")
                st.info("**Información sobre métodos, clases y referencias**")
                
                if st.button("**Generar Estadísticas**", key="dex_stats"):
                    st.write("**Análisis en progreso...**")
            
            with tab3:
                st.subheader("**Descompilar DEX a SMALI**")
                if st.button("**Convertir a SMALI**", key="dex_to_smali"):
                    st.warning("**Esta función requiere herramientas externas como baksmali**")
                    st.code("baksmali disassemble classes.dex -o output/", language="bash")
    
    else:  # SMALI
        uploaded_files = st.file_uploader(
            "**Subir archivos SMALI**",
            type=['smali'],
            accept_multiple_files=True,
            key="smali_upload"
        )
        
        if uploaded_files:
            tab1, tab2 = st.tabs([
                "**📖 Leer SMALI**",
                "**🔄 Convertir a Java**"
            ])
            
            with tab1:
                st.subheader("**Contenido de Archivos SMALI**")
                for smali_file in uploaded_files:
                    with st.expander(f"📄 {smali_file.name}"):
                        smali_content = parse_smali_file(smali_file)
                        st.code(smali_content, language="smali")
            
            with tab2:
                st.subheader("**Reconstruir Código Java**")
                st.info("**SMALI puede ser convertido de vuelta a Java aproximado**")
                
                if st.button("**Intentar Conversión**", key="smali_to_java"):
                    st.warning("**Esta conversión es aproximada y puede no ser exacta**")

# ==================== ANÁLISIS DE MANIFIESTOS ====================
elif categoria == "📊 Análisis de Manifiestos":
    st.header("Análisis de AndroidManifest.xml")
    
    st.info("""
    **💡 Importante:** Por restricciones de seguridad, no se pueden subir archivos APK directamente.
    
    **Soluciones alternativas:**
    1. Usa herramientas externas como `apktool` para descompilar el APK
    2. Sube el AndroidManifest.xml extraído aquí
    3. Sube archivos DEX o SMALI individuales
    """)
    
    st.markdown("""
    **📱 Puedes analizar:**
    - AndroidManifest.xml (formato texto o binario)
    - Archivos de configuración
    - Permisos y activities
    """)
    
    manifest_file = st.file_uploader(
        "**Subir AndroidManifest.xml**",
        type=['xml', 'txt'],
        key="manifest_upload"
    )
    
    if manifest_file:
        st.success(f"**✅ Archivo cargado: {manifest_file.name}**")
        
        tab1, tab2, tab3 = st.tabs([
            "**📄 Contenido**",
            "**🔐 Permisos**",
            "**📱 Componentes**"
        ])
        
        with tab1:
            st.subheader("**Contenido del Manifest**")
            try:
                content = manifest_file.read().decode('utf-8')
                st.code(content, language="xml")
                manifest_file.seek(0)
            except:
                st.error("**Error al leer el archivo. Asegúrate que sea un archivo XML válido.**")
        
        with tab2:
            st.subheader("**Análisis de Permisos**")
            if st.button("**Extraer Permisos**", key="extract_perms"):
                try:
                    content = manifest_file.read().decode('utf-8')
                    
                    # Buscar permisos
                    perm_pattern = r'<uses-permission\s+android:name="([^"]+)"'
                    permissions = re.findall(perm_pattern, content)
                    
                    if permissions:
                        st.write(f"**Total de permisos encontrados:** {len(permissions)}")
                        
                        dangerous_keywords = ['CAMERA', 'LOCATION', 'CONTACTS', 'SMS', 'PHONE', 'STORAGE', 'MICROPHONE']
                        
                        dangerous = [p for p in permissions if any(kw in p.upper() for kw in dangerous_keywords)]
                        normal = [p for p in permissions if p not in dangerous]
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**🔴 Permisos Peligrosos:**")
                            for perm in dangerous:
                                st.code(perm)
                        
                        with col2:
                            st.markdown("**🔵 Permisos Normales:**")
                            for perm in normal:
                                st.code(perm)
                    else:
                        st.info("**No se encontraron permisos en el manifest**")
                    
                    manifest_file.seek(0)
                except Exception as e:
                    st.error(f"**Error:** {str(e)}")
        
        with tab3:
            st.subheader("**Componentes de la App**")
            if st.button("**Extraer Componentes**", key="extract_components"):
                try:
                    content = manifest_file.read().decode('utf-8')
                    
                    # Buscar activities
                    activity_pattern = r'<activity\s+android:name="([^"]+)"'
                    activities = re.findall(activity_pattern, content)
                    
                    # Buscar services
                    service_pattern = r'<service\s+android:name="([^"]+)"'
                    services = re.findall(service_pattern, content)
                    
                    # Buscar receivers
                    receiver_pattern = r'<receiver\s+android:name="([^"]+)"'
                    receivers = re.findall(receiver_pattern, content)
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("**Activities**", len(activities))
                        for act in activities:
                            st.code(act, language="java")
                    
                    with col2:
                        st.metric("**Services**", len(services))
                        for srv in services:
                            st.code(srv, language="java")
                    
                    with col3:
                        st.metric("**Receivers**", len(receivers))
                        for rcv in receivers:
                            st.code(rcv, language="java")
                    
                    manifest_file.seek(0)
                except Exception as e:
                    st.error(f"**Error:** {str(e)}")

# ==================== SEGURIDAD DE CÓDIGO ====================
elif categoria == "🔐 Seguridad de Código":
    st.header("Análisis de Seguridad de Código")
    
    st.markdown("""
    **🔒 Análisis de seguridad para código JavaScript/React Native:**
    - Detección de eval() e innerHTML
    - API keys hardcoded
    - Uso de HTTP en lugar de HTTPS
    - Almacenamiento inseguro de datos
    - Problemas comunes de seguridad
    """)
    
    source_files = st.file_uploader(
        "**Subir archivos de código JavaScript**",
        type=['js', 'jsx'],
        accept_multiple_files=True,
        key="security_source"
    )
    
    if source_files:
        if st.button("**🔍 Escanear Seguridad**", key="scan_source_security"):
            with st.spinner("**Escaneando código...**"):
                issues = detect_security_issues_android(source_files, 'javascript')
                
                if issues:
                    high = [i for i in issues if i['severity'] == 'HIGH']
                    medium = [i for i in issues if i['severity'] == 'MEDIUM']
                    low = [i for i in issues if i['severity'] == 'LOW']
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("**🔴 Alto**", len(high))
                    with col2:
                        st.metric("**🟡 Medio**", len(medium))
                    with col3:
                        st.metric("**🔵 Bajo**", len(low))
                    
                    st.markdown("### **Problemas Detectados:**")
                    
                    if high:
                        st.markdown("#### **🔴 Prioridad Alta:**")
                        for issue in high:
                            st.error(f"**{issue['file']}** (línea {issue.get('line', '?')}): {issue['description']}")
                    
                    if medium:
                        st.markdown("#### **🟡 Prioridad Media:**")
                        for issue in medium:
                            st.warning(f"**{issue['file']}** (línea {issue.get('line', '?')}): {issue['description']}")
                    
                    if low:
                        with st.expander("**🔵 Prioridad Baja**"):
                            for issue in low:
                                st.info(f"**{issue['file']}** (línea {issue.get('line', '?')}): {issue['description']}")
                else:
                    st.success("**✅ No se detectaron problemas de seguridad**")
                    st.balloons()

# ==================== DEPENDENCIAS JAVASCRIPT ====================
elif categoria == "🔍 Dependencias JavaScript":
    st.header("Análisis de Dependencias")
    
    st.markdown("""
    **📦 Analiza las dependencias de tu proyecto JavaScript/React Native:**
    - Imports ES6 (`import ... from`)
    - Requires CommonJS (`require()`)
    - Dependencias externas vs internas
    - Análisis de package.json
    """)
    
    tab1, tab2 = st.tabs([
        "**📄 Archivos JavaScript**",
        "**📦 package.json**"
    ])
    
    with tab1:
        st.subheader("**Analizar Archivos JavaScript**")
        js_files = st.file_uploader(
            "**Subir archivos .js o .jsx**",
            type=['js', 'jsx'],
            accept_multiple_files=True,
            key="deps_js"
        )
        
        if js_files:
            if st.button("**Analizar Dependencias**", key="analyze_js_deps"):
                deps = analyze_dependencies(js_files)
                
                st.markdown("### **Dependencias Detectadas:**")
                
                all_imports = []
                for file, imports in deps.items():
                    all_imports.extend(imports)
                
                # Separar dependencias externas vs relativas
                external = [imp for imp in all_imports if not imp.startswith('.')]
                relative = [imp for imp in all_imports if imp.startswith('.')]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📦 Dependencias Externas:**")
                    st.metric("Total", len(set(external)))
                    for imp in sorted(set(external)):
                        st.code(imp)
                
                with col2:
                    st.markdown("**📁 Imports Relativos:**")
                    st.metric("Total", len(set(relative)))
                    for imp in sorted(set(relative)):
                        st.code(imp)
                
                # Detalle por archivo
                with st.expander("**Ver detalle por archivo**"):
                    for file, imports in deps.items():
                        st.markdown(f"**📄 {file}**")
                        for imp in imports:
                            st.write(f"  └─ `{imp}`")
    
    with tab2:
        st.subheader("**Analizar package.json**")
        package_file = st.file_uploader(
            "**Subir package.json**",
            type=['json'],
            key="package_json"
        )
        
        if package_file:
            try:
                import json
                package_data = json.load(package_file)
                
                st.markdown("### **Información del Proyecto:**")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Nombre:** `{package_data.get('name', 'N/A')}`")
                    st.write(f"**Versión:** `{package_data.get('version', 'N/A')}`")
                    st.write(f"**Descripción:** {package_data.get('description', 'N/A')}")
                
                with col2:
                    deps_count = len(package_data.get('dependencies', {}))
                    devdeps_count = len(package_data.get('devDependencies', {}))
                    st.metric("**Dependencies**", deps_count)
                    st.metric("**DevDependencies**", devdeps_count)
                
                # Dependencies
                if package_data.get('dependencies'):
                    with st.expander("**📦 Dependencies**"):
                        for dep, version in package_data['dependencies'].items():
                            st.code(f"{dep}: {version}")
                
                # DevDependencies
                if package_data.get('devDependencies'):
                    with st.expander("**🔧 DevDependencies**"):
                        for dep, version in package_data['devDependencies'].items():
                            st.code(f"{dep}: {version}")
                
                # Scripts
                if package_data.get('scripts'):
                    with st.expander("**⚙️ Scripts**"):
                        for script, command in package_data['scripts'].items():
                            st.write(f"**{script}:**")
                            st.code(command, language="bash")
                
            except Exception as e:
                st.error(f"**Error al leer package.json:** {str(e)}")

# ==================== ANÁLISIS GRADLE/CONFIG ====================
elif categoria == "📝 Análisis Gradle/Config":
    st.header("Análisis de Archivos de Configuración")
    
    st.markdown("""
    **⚙️ Analiza archivos de configuración de tu proyecto Android:**
    - build.gradle (app y project)
    - settings.gradle
    - Configuración de SDK
    - Dependencias Android
    """)
    
    tab1, tab2 = st.tabs([
        "**📝 Archivos Gradle**",
        "**⚙️ Configuraciones**"
    ])
    
    with tab1:
        st.subheader("**Analizar build.gradle**")
        gradle_files = st.file_uploader(
            "**Subir archivos .gradle**",
            type=['gradle'],
            accept_multiple_files=True,
            key="gradle_upload"
        )
        
        if gradle_files:
            for gradle_file in gradle_files:
                with st.expander(f"📄 {gradle_file.name}"):
                    gradle_info = analyze_gradle_files(gradle_file)
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**🔧 Configuración SDK:**")
                        st.write(f"**Min SDK:** `{gradle_info.get('min_sdk', 'N/A')}`")
                        st.write(f"**Target SDK:** `{gradle_info.get('target_sdk', 'N/A')}`")
                        st.write(f"**Version Name:** `{gradle_info.get('version_name', 'N/A')}`")
                        st.write(f"**Version Code:** `{gradle_info.get('version_code', 'N/A')}`")
                    
                    with col2:
                        st.markdown("**📦 Plugins:**")
                        for plugin in gradle_info.get('plugins', []):
                            st.code(plugin)
                    
                    st.markdown("**📚 Dependencias:**")
                    deps = gradle_info.get('dependencies', [])
                    if deps:
                        st.write(f"**Total:** {len(deps)}")
                        for dep in deps:
                            st.code(dep)
                    else:
                        st.info("**No se encontraron dependencias**")
    
    with tab2:
        st.subheader("**Archivos de Configuración Personalizados**")
        
        config_file = st.file_uploader(
            "**Subir archivo de configuración (JSON, XML, properties)**",
            type=['json', 'xml', 'properties', 'txt'],
            key="config_upload"
        )
        
        if config_file:
            st.success(f"**✅ Archivo cargado: {config_file.name}**")
            
            try:
                content = config_file.read().decode('utf-8')
                st.code(content, language="text")
                
                # Buscar configuraciones sensibles
                st.markdown("### **⚠️ Verificación de Seguridad:**")
                
                sensitive_patterns = {
                    'API Key': r'api[_-]?key',
                    'Password': r'password',
                    'Secret': r'secret',
                    'Token': r'token',
                    'Private Key': r'private[_-]?key'
                }
                
                found_sensitive = []
                for name, pattern in sensitive_patterns.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        found_sensitive.append(name)
                
                if found_sensitive:
                    st.warning(f"**⚠️ Se detectaron posibles configuraciones sensibles:**")
                    for item in found_sensitive:
                        st.write(f"- {item}")
                    st.info("**💡 Tip:** No incluyas API keys o secrets directamente en los archivos de configuración.")
                else:
                    st.success("**✅ No se detectaron configuraciones sensibles expuestas**")
                
            except Exception as e:
                st.error(f"**Error al leer el archivo:** {str(e)}")

# ==================== GUÍA DE USO ====================
elif categoria == "💡 Guía de Uso":
    st.header("Guía de Uso de la Aplicación")
    
    st.markdown("""
    # 🤖 Bienvenido a Android App Analyzer Pro
    
    Esta aplicación te permite analizar aplicaciones Android sin necesidad de herramientas complejas.
    
    ---
    
    ## 📱 ¿Qué puedes hacer?
    
    ### 🏠 **Conversión Básica**
    Convierte archivos JavaScript, DEX o SMALI a texto legible:
    - ✅ Archivos .js y .jsx (React Native)
    - ✅ Archivos .dex (bytecode Android)
    - ✅ Archivos .smali (ensamblador)
    
    ### 📱 **Análisis de JavaScript**
    Analiza código JavaScript/React Native:
    - 📊 Estadísticas (líneas, funciones, componentes)
    - 🔍 Detección de componentes React
    - 📦 Análisis de dependencias
    - ⚠️ Problemas de seguridad
    
    ### 🔧 **Análisis DEX/SMALI**
    Examina bytecode Android:
    - 📦 Información de archivos DEX
    - 📖 Lectura de archivos SMALI
    - 📊 Contador de clases y métodos
    
    ### 📊 **Análisis de Manifiestos**
    Lee AndroidManifest.xml:
    - 🔐 Extracción de permisos
    - 📱 Listado de Activities/Services
    - ⚙️ Configuración de la app
    
    ### 🔐 **Seguridad de Código**
    Detecta problemas de seguridad:
    - 🚨 eval() e innerHTML
    - 🔑 API keys hardcoded
    - 🌐 Uso de HTTP vs HTTPS
    - 💾 Almacenamiento inseguro
    
    ### 🔍 **Dependencias JavaScript**
    Analiza dependencias del proyecto:
    - 📦 Imports y requires
    - 📄 Análisis de package.json
    - 🔗 Dependencias externas vs internas
    
    ### 📝 **Análisis Gradle/Config**
    Examina configuración del proyecto:
    - ⚙️ build.gradle
    - 🔧 Configuración de SDK
    - 📚 Dependencias Android
    
    ---
    
    ## 🚀 Cómo Empezar
    
    ### Paso 1: Selecciona una categoría
    Usa el menú de la izquierda para elegir qué quieres hacer.
    
    ### Paso 2: Sube tus archivos
    Arrastra o selecciona los archivos que quieres analizar.
    
    ### Paso 3: Analiza
    Haz clic en el botón correspondiente para iniciar el análisis.
    
    ### Paso 4: Descarga resultados
    Guarda los resultados en formato texto, JSON o PDF.
    
    ---
    
    ## ⚠️ Limitación Importante
    
    **No se pueden subir archivos APK completos** debido a restricciones de seguridad de Streamlit Cloud.
    
    ### 📝 Soluciones alternativas:
    
    1. **Descompila el APK primero:**
       ```bash
       apktool d app.apk -o output/
       ```
       Luego sube los archivos individuales (AndroidManifest.xml, .dex, .smali)
    
    2. **Extrae archivos específicos:**
       - Usa WinRAR/7-Zip para abrir el APK (es un ZIP)
       - Extrae AndroidManifest.xml, classes.dex, etc.
       - Sube esos archivos aquí
    
    3. **Usa herramientas externas:**
       - jadx: Para ver código Java
       - dex2jar: Para convertir DEX a JAR
       - baksmali: Para convertir DEX a SMALI
    
    ---
    
    ## 💡 Casos de Uso
    
    ### Para Desarrolladores
    - ✅ Analizar tu código antes de publicar
    - ✅ Verificar dependencias usadas
    - ✅ Detectar problemas de seguridad
    - ✅ Revisar configuración de permisos
    
    ### Para Seguridad
    - ✅ Auditar código de terceros
    - ✅ Detectar código malicioso
    - ✅ Analizar permisos solicitados
    - ✅ Verificar URLs y endpoints
    
    ### Para Aprendizaje
    - ✅ Estudiar estructura de apps
    - ✅ Entender bytecode Android
    - ✅ Aprender React Native
    - ✅ Análisis de código
    
    ---
    
    ## 🛠️ Herramientas Complementarias
    
    Para análisis más avanzado:
    - **apktool**: Descompilación de APK
    - **jadx**: DEX a código Java
    - **baksmali**: DEX a SMALI
    - **androguard**: Análisis Python
    - **dex2jar**: DEX a JAR
    
    ---
    
    ## 📧 ¿Necesitas Ayuda?
    
    Si tienes problemas o sugerencias:
    - Revisa esta guía
    - Consulta el README en GitHub
    - Abre un Issue en el repositorio
    
    ---
    
    ## ⚖️ Uso Responsable
    
    Esta herramienta es para:
    - ✅ Analizar tus propias apps
    - ✅ Investigación de seguridad ética
    - ✅ Propósitos educativos
    - ✅ Auditorías autorizadas
    
    **NO usar para actividades ilegales o no éticas.**
    
    ---
    
    ¡Gracias por usar Android App Analyzer Pro! 🚀
    """)
    
    # Tips útiles
    with st.expander("**💡 Tips y Trucos**"):
        st.markdown("""
        - **Tip 1**: Para archivos grandes, el análisis puede tardar. Ten paciencia.
        - **Tip 2**: Puedes analizar múltiples archivos a la vez.
        - **Tip 3**: Los problemas de seguridad HIGH requieren atención inmediata.
        - **Tip 4**: Usa el análisis de dependencias para detectar librerías obsoletas.
        - **Tip 5**: Exporta los resultados antes de cerrar la página.
        """)
    
    # Atajos de teclado
    with st.expander("**⌨️ Atajos de Teclado**"):
        st.markdown("""
        - **Ctrl + R**: Recargar la aplicación
        - **Ctrl + S**: (en editor) Guardar archivo
        - **Esc**: Cerrar menú lateral
        """)

# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #495057;'>
        <p><strong>🤖 Android App Analyzer Pro v1.0</strong></p>
        <p><strong>Desarrollado con ❤️ usando Streamlit | Soporta JS, DEX, SMALI, APK</strong></p>
    </div>
""", unsafe_allow_html=True)

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
st.markdown("**Analizador completo de aplicaciones Android: JavaScript, DEX, SMALI, APK**")

# Sidebar con categorías
st.sidebar.title("📋 Categorías")
st.sidebar.markdown("---")

categoria = st.sidebar.radio(
    "**Selecciona una categoría:**",
    [
        "🏠 Conversión Básica",
        "📱 Análisis de JavaScript",
        "🔧 Análisis DEX/SMALI",
        "📦 Análisis de APK Completo",
        "🔐 Seguridad y Permisos",
        "📊 Recursos y Manifiestos",
        "🔍 Dependencias y Librerías",
        "⚖️ Comparación de Versiones"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("**💡 Tip:** Sube tus archivos .js, .dex, .smali o .apk para análisis completo.")

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

# ==================== ANÁLISIS DE APK COMPLETO ====================
elif categoria == "📦 Análisis de APK Completo":
    st.header("Análisis Completo de APK")
    
    st.markdown("""
    **🎯 Sube un archivo APK para análisis completo:**
    - Extracción de archivos
    - Análisis del AndroidManifest.xml
    - Conversión DEX a SMALI
    - Extracción de recursos
    - Análisis de permisos
    - Detección de librerías nativas
    """)
    
    apk_file = st.file_uploader(
        "**Subir archivo APK**",
        type=['apk'],
        key="apk_upload"
    )
    
    if apk_file:
        st.success(f"**✅ APK cargado: {apk_file.name}**")
        
        col1, col2 = st.columns(2)
        with col1:
            analyze_full = st.checkbox("**Análisis completo (lento)**", value=False)
        with col2:
            extract_all = st.checkbox("**Extraer todos los archivos**", value=False)
        
        if st.button("**🚀 Analizar APK**", key="analyze_apk"):
            with st.spinner("**Analizando APK... Esto puede tardar varios minutos**"):
                
                # Crear tabs para diferentes análisis
                tab1, tab2, tab3, tab4, tab5 = st.tabs([
                    "**📋 Información General**",
                    "**🔐 Permisos**",
                    "**📱 Manifest**",
                    "**📦 Recursos**",
                    "**📊 Reporte Completo**"
                ])
                
                with tab1:
                    st.subheader("**Información General del APK**")
                    apk_info = decompile_apk(apk_file, extract_all)
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("**Tamaño**", f"{apk_info.get('size', 0) / 1024 / 1024:.2f} MB")
                    with col2:
                        st.metric("**Archivos DEX**", apk_info.get('dex_count', 0))
                    with col3:
                        st.metric("**Recursos**", apk_info.get('resource_count', 0))
                    
                    st.json(apk_info)
                
                with tab2:
                    st.subheader("**Permisos Solicitados**")
                    permissions = detect_permissions(apk_file)
                    
                    if permissions:
                        dangerous = [p for p in permissions if p.get('level') == 'dangerous']
                        normal = [p for p in permissions if p.get('level') == 'normal']
                        
                        st.warning(f"**⚠️ {len(dangerous)} permisos peligrosos detectados**")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**🔴 Permisos Peligrosos:**")
                            for perm in dangerous:
                                st.code(perm['name'])
                        
                        with col2:
                            st.markdown("**🔵 Permisos Normales:**")
                            for perm in normal:
                                st.code(perm['name'])
                
                with tab3:
                    st.subheader("**AndroidManifest.xml**")
                    manifest_info = analyze_manifest(apk_file)
                    
                    st.markdown("**📱 Información de la App:**")
                    st.write(f"**Package:** `{manifest_info.get('package')}`")
                    st.write(f"**Version Name:** `{manifest_info.get('version_name')}`")
                    st.write(f"**Version Code:** `{manifest_info.get('version_code')}`")
                    st.write(f"**Min SDK:** `{manifest_info.get('min_sdk')}`")
                    st.write(f"**Target SDK:** `{manifest_info.get('target_sdk')}`")
                    
                    with st.expander("**Ver Manifest completo**"):
                        st.code(manifest_info.get('raw_xml', ''), language="xml")
                
                with tab4:
                    st.subheader("**Recursos Extraídos**")
                    resources = extract_resources(apk_file)
                    
                    st.write(f"**Total de recursos:** {len(resources)}")
                    
                    resource_types = {}
                    for res in resources:
                        res_type = res.split('.')[-1]
                        resource_types[res_type] = resource_types.get(res_type, 0) + 1
                    
                    for res_type, count in resource_types.items():
                        st.write(f"**{res_type}:** {count} archivos")
                
                with tab5:
                    st.subheader("**Reporte Completo**")
                    if st.button("**Generar Reporte PDF**", key="gen_apk_report"):
                        report = generate_apk_report(apk_file, analyze_full)
                        
                        st.download_button(
                            "**⬇️ Descargar Reporte**",
                            report,
                            f"{apk_file.name}_report.pdf",
                            "application/pdf"
                        )

# ==================== SEGURIDAD Y PERMISOS ====================
elif categoria == "🔐 Seguridad y Permisos":
    st.header("Análisis de Seguridad")
    
    st.markdown("""
    **🔒 Análisis de seguridad para aplicaciones Android:**
    - Detección de permisos peligrosos
    - Análisis de código malicioso
    - Verificación de certificados
    - Detección de ofuscación
    - Análisis de URLs sospechosas
    """)
    
    upload_type = st.radio("**Tipo de análisis:**", ["Archivo APK", "Código fuente (JS/Java)"])
    
    if upload_type == "Archivo APK":
        apk_file = st.file_uploader("**Subir APK**", type=['apk'], key="security_apk")
        
        if apk_file:
            if st.button("**🔍 Escanear Seguridad**", key="scan_apk_security"):
                with st.spinner("**Escaneando...**"):
                    issues = detect_security_issues_android(apk_file, 'apk')
                    
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
                    for issue in high:
                        st.error(f"**{issue['type']}:** {issue['description']}")
                    
                    for issue in medium:
                        st.warning(f"**{issue['type']}:** {issue['description']}")
    
    else:
        source_files = st.file_uploader(
            "**Subir archivos de código**",
            type=['js', 'java'],
            accept_multiple_files=True,
            key="security_source"
        )
        
        if source_files:
            if st.button("**🔍 Analizar Código**", key="scan_source_security"):
                issues = detect_security_issues_android(source_files, 'javascript')
                
                for issue in issues:
                    if issue['severity'] == 'HIGH':
                        st.error(f"**Línea {issue.get('line', '?')}:** {issue['description']}")

# ==================== RECURSOS Y MANIFIESTOS ====================
elif categoria == "📊 Recursos y Manifiestos":
    st.header("Análisis de Recursos y Configuración")
    
    tab1, tab2, tab3 = st.tabs([
        "**📄 Manifest**",
        "**🎨 Recursos**",
        "**🔧 Gradle**"
    ])
    
    with tab1:
        st.subheader("**AndroidManifest.xml**")
        apk_file = st.file_uploader("**Subir APK**", type=['apk'], key="manifest_apk")
        
        if apk_file:
            if st.button("**Analizar Manifest**", key="analyze_manifest_btn"):
                manifest = analyze_manifest(apk_file)
                
                st.markdown("### **Información de la Aplicación:**")
                st.write(f"**📦 Package:** `{manifest.get('package')}`")
                st.write(f"**🏷️ Nombre:** `{manifest.get('app_name')}`")
                st.write(f"**📱 Version:** `{manifest.get('version_name')} ({manifest.get('version_code')})`")
                
                st.markdown("### **Activities:**")
                for activity in manifest.get('activities', []):
                    st.code(activity)
                
                st.markdown("### **Services:**")
                for service in manifest.get('services', []):
                    st.code(service)
    
    with tab2:
        st.subheader("**Strings.xml y Recursos**")
        apk_file = st.file_uploader("**Subir APK**", type=['apk'], key="resources_apk")
        
        if apk_file:
            if st.button("**Extraer Strings**", key="extract_strings"):
                strings = extract_strings_xml(apk_file)
                
                st.markdown(f"**Total de strings:** {len(strings)}")
                
                for key, value in list(strings.items())[:50]:
                    st.write(f"**{key}:** {value}")
    
    with tab3:
        st.subheader("**Archivos Gradle**")
        gradle_files = st.file_uploader(
            "**Subir build.gradle**",
            type=['gradle'],
            accept_multiple_files=True,
            key="gradle_upload"
        )
        
        if gradle_files:
            for gradle_file in gradle_files:
                with st.expander(f"📄 {gradle_file.name}"):
                    gradle_info = analyze_gradle_files(gradle_file)
                    st.json(gradle_info)

# ==================== DEPENDENCIAS Y LIBRERÍAS ====================
elif categoria == "🔍 Dependencias y Librerías":
    st.header("Análisis de Dependencias")
    
    apk_file = st.file_uploader("**Subir APK**", type=['apk'], key="deps_apk")
    
    if apk_file:
        tab1, tab2, tab3 = st.tabs([
            "**📦 Librerías Nativas**",
            "**🔗 Dependencias JS**",
            "**📚 Librerías Android**"
        ])
        
        with tab1:
            st.subheader("**Librerías Nativas (.so)**")
            if st.button("**Detectar Librerías**", key="detect_native"):
                native_libs = detect_native_libs(apk_file)
                
                if native_libs:
                    for arch, libs in native_libs.items():
                        with st.expander(f"**{arch}** ({len(libs)} librerías)"):
                            for lib in libs:
                                st.code(lib)
                else:
                    st.info("**No se encontraron librerías nativas**")
        
        with tab2:
            st.subheader("**Dependencias JavaScript**")
            st.info("**Analiza package.json o archivos JS para detectar dependencias**")
        
        with tab3:
            st.subheader("**Librerías Android Detectadas**")
            st.info("**Basado en análisis de DEX y Manifest**")

# ==================== COMPARACIÓN DE VERSIONES ====================
elif categoria == "⚖️ Comparación de Versiones":
    st.header("Comparar Versiones de APK")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("**Versión Original**")
        apk1 = st.file_uploader("**APK v1**", type=['apk'], key="compare_apk1")
    
    with col2:
        st.subheader("**Versión Nueva**")
        apk2 = st.file_uploader("**APK v2**", type=['apk'], key="compare_apk2")
    
    if apk1 and apk2:
        if st.button("**⚖️ Comparar Versiones**", key="compare_versions"):
            with st.spinner("**Comparando APKs...**"):
                diff = compare_apk_versions(apk1, apk2)
                
                st.markdown("### **Diferencias Detectadas:**")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("**Cambio de Tamaño**", f"{diff.get('size_diff', 0):.2f} MB")
                with col2:
                    st.metric("**Nuevos Permisos**", diff.get('new_permissions', 0))
                with col3:
                    st.metric("**Archivos Modificados**", diff.get('modified_files', 0))
                
                st.markdown("### **Detalles:**")
                st.json(diff)

# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #495057;'>
        <p><strong>🤖 Android App Analyzer Pro v1.0</strong></p>
        <p><strong>Desarrollado con ❤️ usando Streamlit | Soporta JS, DEX, SMALI, APK</strong></p>
    </div>
""", unsafe_allow_html=True)

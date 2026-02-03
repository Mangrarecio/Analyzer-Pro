"""
Módulo de conversión y análisis de aplicaciones Android
Soporta JavaScript, DEX, SMALI y APK
"""

import re
import zipfile
import io
from datetime import datetime
import json


def convert_js_to_txt(files, preserve_comments=True, add_line_numbers=False, 
                      add_metadata=True, beautify_code=True):
    """Convierte archivos JavaScript a texto plano"""
    result = []
    
    if add_metadata:
        result.append("=" * 80)
        result.append("CONVERSIÓN DE ARCHIVOS JAVASCRIPT/ANDROID")
        result.append(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        result.append(f"Total de archivos: {len(files)}")
        result.append("=" * 80)
        result.append("\n")
    
    for idx, file in enumerate(files, 1):
        try:
            content = file.read().decode('utf-8')
        except:
            try:
                content = file.read().decode('latin-1')
            except:
                content = "[Error: No se pudo decodificar el archivo]"
        
        result.append(f"\n{'=' * 80}")
        result.append(f"ARCHIVO {idx}: {file.name}")
        result.append(f"Tipo: {file.name.split('.')[-1].upper()}")
        result.append(f"Líneas: {len(content.splitlines())}")
        result.append(f"{'=' * 80}\n")
        
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            if not preserve_comments:
                if line.strip().startswith('//') or line.strip().startswith('/*'):
                    continue
            
            if add_line_numbers:
                result.append(f"{line_num:4d} | {line}")
            else:
                result.append(line)
        
        result.append("\n")
        file.seek(0)
    
    return "\n".join(result)


def analyze_js_statistics(files):
    """Analiza estadísticas de código JavaScript"""
    stats = {
        'total_lines': 0,
        'code_lines': 0,
        'comment_lines': 0,
        'blank_lines': 0,
        'functions': 0,
        'classes': 0,
        'react_components': 0,
        'imports': 0,
        'exports': 0,
        'files': len(files),
        'function_list': [],
        'class_list': [],
        'component_list': [],
        'jsx_used': False
    }
    
    # Patrones regex para JavaScript
    function_pattern = r'\bfunction\s+(\w+)\s*\('
    arrow_function_pattern = r'\bconst\s+(\w+)\s*=\s*\([^)]*\)\s*=>'
    class_pattern = r'\bclass\s+(\w+)'
    react_component_pattern = r'\b(const|function)\s+([A-Z]\w+)\s*=?\s*\([^)]*\)\s*(?:=>)?\s*\{?'
    import_pattern = r'\bimport\s+.*\s+from\s+["\'](.+)["\']'
    export_pattern = r'\bexport\s+(default|const|function|class)'
    
    for file in files:
        try:
            content = file.read().decode('utf-8')
        except:
            content = file.read().decode('latin-1', errors='ignore')
        
        lines = content.splitlines()
        stats['total_lines'] += len(lines)
        
        # Detectar si usa JSX
        if '.jsx' in file.name or '<' in content and '>' in content:
            stats['jsx_used'] = True
        
        for line in lines:
            stripped = line.strip()
            
            if not stripped:
                stats['blank_lines'] += 1
            elif stripped.startswith('//') or stripped.startswith('/*'):
                stats['comment_lines'] += 1
            else:
                stats['code_lines'] += 1
        
        # Detectar funciones
        functions = re.findall(function_pattern, content)
        arrow_functions = re.findall(arrow_function_pattern, content)
        stats['function_list'].extend(functions + arrow_functions)
        stats['functions'] += len(functions) + len(arrow_functions)
        
        # Detectar clases
        classes = re.findall(class_pattern, content)
        stats['class_list'].extend(classes)
        stats['classes'] += len(classes)
        
        # Detectar componentes React
        components = re.findall(react_component_pattern, content)
        for comp in components:
            comp_name = comp[1] if isinstance(comp, tuple) else comp
            if comp_name[0].isupper():  # Componentes empiezan con mayúscula
                stats['component_list'].append(comp_name)
                stats['react_components'] += 1
        
        # Detectar imports
        imports = re.findall(import_pattern, content)
        stats['imports'] += len(imports)
        
        # Detectar exports
        exports = re.findall(export_pattern, content)
        stats['exports'] += len(exports)
        
        file.seek(0)
    
    # Eliminar duplicados
    stats['function_list'] = list(set(stats['function_list']))
    stats['class_list'] = list(set(stats['class_list']))
    stats['component_list'] = list(set(stats['component_list']))
    
    return stats


def parse_dex_file(dex_file):
    """Analiza un archivo DEX (Dalvik Executable)"""
    dex_info = {
        'filename': dex_file.name,
        'size': 0,
        'class_count': 0,
        'method_count': 0,
        'string_count': 0,
        'field_count': 0,
        'classes': [],
        'magic': '',
        'version': ''
    }
    
    try:
        content = dex_file.read()
        dex_info['size'] = len(content)
        
        # Leer magic number (primeros 8 bytes)
        magic = content[:8]
        if magic.startswith(b'dex\n'):
            dex_info['magic'] = magic.decode('ascii', errors='ignore')
            dex_info['version'] = magic[4:7].decode('ascii', errors='ignore')
        
        # Parseo básico del header DEX
        # Offset 0x38: string_ids_size (4 bytes)
        if len(content) >= 0x3C:
            dex_info['string_count'] = int.from_bytes(content[0x38:0x3C], 'little')
        
        # Offset 0x58: class_defs_size (4 bytes)
        if len(content) >= 0x5C:
            dex_info['class_count'] = int.from_bytes(content[0x58:0x5C], 'little')
        
        # Offset 0x48: method_ids_size (4 bytes)
        if len(content) >= 0x4C:
            dex_info['method_count'] = int.from_bytes(content[0x48:0x4C], 'little')
        
        # Offset 0x40: field_ids_size (4 bytes)
        if len(content) >= 0x44:
            dex_info['field_count'] = int.from_bytes(content[0x40:0x44], 'little')
        
        dex_file.seek(0)
        
    except Exception as e:
        dex_info['error'] = str(e)
    
    return dex_info


def parse_smali_file(smali_file):
    """Lee y parsea un archivo SMALI"""
    try:
        content = smali_file.read().decode('utf-8')
        smali_file.seek(0)
        return content
    except Exception as e:
        return f"Error leyendo archivo SMALI: {str(e)}"


def decompile_apk(apk_file, extract_all=False):
    """Descompila y analiza un archivo APK"""
    apk_info = {
        'filename': apk_file.name,
        'size': 0,
        'files': [],
        'dex_files': [],
        'dex_count': 0,
        'native_libs': [],
        'resource_count': 0,
        'has_manifest': False,
        'structure': {}
    }
    
    try:
        content = apk_file.read()
        apk_info['size'] = len(content)
        
        # Un APK es básicamente un archivo ZIP
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            file_list = zf.namelist()
            apk_info['files'] = file_list
            apk_info['resource_count'] = len(file_list)
            
            # Detectar archivos DEX
            dex_files = [f for f in file_list if f.endswith('.dex')]
            apk_info['dex_files'] = dex_files
            apk_info['dex_count'] = len(dex_files)
            
            # Detectar librerías nativas
            native_libs = [f for f in file_list if f.startswith('lib/') and f.endswith('.so')]
            apk_info['native_libs'] = native_libs
            
            # Verificar AndroidManifest.xml
            if 'AndroidManifest.xml' in file_list:
                apk_info['has_manifest'] = True
            
            # Estructura de directorios
            dirs = {}
            for file in file_list:
                parts = file.split('/')
                if len(parts) > 1:
                    dir_name = parts[0]
                    dirs[dir_name] = dirs.get(dir_name, 0) + 1
            
            apk_info['structure'] = dirs
        
        apk_file.seek(0)
        
    except Exception as e:
        apk_info['error'] = str(e)
    
    return apk_info


def analyze_manifest(apk_file):
    """Analiza el AndroidManifest.xml de un APK"""
    manifest_info = {
        'package': '',
        'version_name': '',
        'version_code': '',
        'min_sdk': '',
        'target_sdk': '',
        'permissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
        'app_name': '',
        'raw_xml': ''
    }
    
    try:
        content = apk_file.read()
        
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            if 'AndroidManifest.xml' in zf.namelist():
                manifest_bytes = zf.read('AndroidManifest.xml')
                
                # El manifest está en formato binario XML (AXML)
                # Aquí haríamos un parsing básico
                # Para producción, usar librerías como androguard o axmlprinter
                
                # Parseo muy básico buscando strings
                manifest_str = manifest_bytes.decode('latin-1', errors='ignore')
                manifest_info['raw_xml'] = manifest_str
                
                # Buscar patrones comunes
                package_match = re.search(r'package="([^"]+)"', manifest_str)
                if package_match:
                    manifest_info['package'] = package_match.group(1)
                
                # Nota: Para un parsing completo del AXML se necesitaría androguard
                manifest_info['note'] = 'El manifest está en formato binario. Se requiere androguard para parsing completo.'
        
        apk_file.seek(0)
        
    except Exception as e:
        manifest_info['error'] = str(e)
    
    return manifest_info


def extract_resources(apk_file):
    """Extrae lista de recursos del APK"""
    resources = []
    
    try:
        content = apk_file.read()
        
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            file_list = zf.namelist()
            
            # Filtrar recursos comunes
            resource_dirs = ['res/', 'assets/', 'resources/']
            
            for file in file_list:
                for res_dir in resource_dirs:
                    if file.startswith(res_dir):
                        resources.append(file)
                        break
        
        apk_file.seek(0)
        
    except Exception as e:
        resources = [f"Error: {str(e)}"]
    
    return resources


def detect_permissions(apk_file):
    """Detecta permisos del APK"""
    permissions = []
    
    # Permisos peligrosos conocidos
    dangerous_permissions = {
        'READ_CONTACTS': 'dangerous',
        'WRITE_CONTACTS': 'dangerous',
        'READ_SMS': 'dangerous',
        'SEND_SMS': 'dangerous',
        'RECEIVE_SMS': 'dangerous',
        'CAMERA': 'dangerous',
        'RECORD_AUDIO': 'dangerous',
        'ACCESS_FINE_LOCATION': 'dangerous',
        'ACCESS_COARSE_LOCATION': 'dangerous',
        'READ_EXTERNAL_STORAGE': 'dangerous',
        'WRITE_EXTERNAL_STORAGE': 'dangerous',
        'READ_PHONE_STATE': 'dangerous',
        'CALL_PHONE': 'dangerous',
        'READ_CALL_LOG': 'dangerous',
        'WRITE_CALL_LOG': 'dangerous'
    }
    
    try:
        manifest_info = analyze_manifest(apk_file)
        raw_xml = manifest_info.get('raw_xml', '')
        
        # Buscar permisos en el manifest
        perm_pattern = r'android\.permission\.(\w+)'
        found_perms = re.findall(perm_pattern, raw_xml)
        
        for perm in set(found_perms):
            level = dangerous_permissions.get(perm, 'normal')
            permissions.append({
                'name': f'android.permission.{perm}',
                'level': level
            })
        
    except Exception as e:
        permissions = [{'error': str(e)}]
    
    return permissions


def analyze_dependencies(files):
    """Analiza dependencias en archivos JavaScript"""
    dependencies = {}
    
    import_pattern = r'import\s+.*\s+from\s+["\'](.+)["\']'
    require_pattern = r'require\(["\'](.+)["\']\)'
    
    for file in files:
        try:
            content = file.read().decode('utf-8')
        except:
            content = file.read().decode('latin-1', errors='ignore')
        
        imports = []
        
        # Buscar imports ES6
        es6_imports = re.findall(import_pattern, content)
        imports.extend(es6_imports)
        
        # Buscar requires CommonJS
        commonjs_imports = re.findall(require_pattern, content)
        imports.extend(commonjs_imports)
        
        dependencies[file.name] = list(set(imports))
        file.seek(0)
    
    return dependencies


def detect_security_issues_android(files, file_type='javascript'):
    """Detecta problemas de seguridad en código Android"""
    issues = []
    
    if file_type == 'javascript':
        security_patterns = {
            'eval': (r'\beval\s*\(', 'HIGH', 'Uso de eval() puede ejecutar código arbitrario'),
            'innerHTML': (r'\.innerHTML\s*=', 'MEDIUM', 'innerHTML puede causar XSS'),
            'dangerouslySetInnerHTML': (r'dangerouslySetInnerHTML', 'HIGH', 'Riesgo de XSS en React'),
            'localStorage_password': (r'localStorage.*password', 'HIGH', 'No guardar passwords en localStorage'),
            'http_urls': (r'http://(?!localhost)', 'MEDIUM', 'Uso de HTTP en lugar de HTTPS'),
            'hardcoded_key': (r'api[_-]?key\s*[:=]\s*["\'].+["\']', 'HIGH', 'API key hardcoded'),
            'console_log': (r'console\.log', 'LOW', 'console.log en producción puede exponer datos'),
        }
        
        for file in files:
            try:
                content = file.read().decode('utf-8')
            except:
                content = file.read().decode('latin-1', errors='ignore')
            
            for issue_type, (pattern, severity, description) in security_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    issues.append({
                        'file': file.name,
                        'line': line_num,
                        'type': issue_type,
                        'severity': severity,
                        'description': description
                    })
            
            file.seek(0)
    
    elif file_type == 'apk':
        # Analizar APK
        try:
            manifest = analyze_manifest(files)
            permissions = detect_permissions(files)
            
            # Verificar permisos peligrosos
            dangerous_perms = [p for p in permissions if p.get('level') == 'dangerous']
            if len(dangerous_perms) > 5:
                issues.append({
                    'type': 'excessive_permissions',
                    'severity': 'MEDIUM',
                    'description': f'La app solicita {len(dangerous_perms)} permisos peligrosos'
                })
            
            # Verificar uso de HTTP
            apk_info = decompile_apk(files)
            if any('http://' in f for f in apk_info.get('files', [])):
                issues.append({
                    'type': 'http_usage',
                    'severity': 'MEDIUM',
                    'description': 'La app puede usar conexiones HTTP no seguras'
                })
            
        except Exception as e:
            issues.append({
                'type': 'analysis_error',
                'severity': 'LOW',
                'description': f'Error en análisis: {str(e)}'
            })
    
    return issues


def generate_apk_report(apk_file, detailed=False):
    """Genera un reporte completo del APK"""
    report = "REPORTE DE ANÁLISIS APK\n"
    report += "=" * 80 + "\n\n"
    
    # Información básica
    apk_info = decompile_apk(apk_file, extract_all=detailed)
    report += f"Archivo: {apk_info['filename']}\n"
    report += f"Tamaño: {apk_info['size'] / 1024 / 1024:.2f} MB\n"
    report += f"Archivos DEX: {apk_info['dex_count']}\n"
    report += f"Total de archivos: {apk_info['resource_count']}\n\n"
    
    # Permisos
    permissions = detect_permissions(apk_file)
    report += "PERMISOS:\n"
    report += "-" * 40 + "\n"
    for perm in permissions:
        report += f"- {perm.get('name')} [{perm.get('level')}]\n"
    report += "\n"
    
    # Problemas de seguridad
    issues = detect_security_issues_android(apk_file, 'apk')
    if issues:
        report += "PROBLEMAS DE SEGURIDAD:\n"
        report += "-" * 40 + "\n"
        for issue in issues:
            report += f"[{issue['severity']}] {issue['description']}\n"
    
    return report.encode('utf-8')


def compare_apk_versions(apk1, apk2):
    """Compara dos versiones de APK"""
    diff = {
        'size_diff': 0,
        'new_permissions': 0,
        'removed_permissions': 0,
        'modified_files': 0,
        'new_files': [],
        'removed_files': []
    }
    
    try:
        info1 = decompile_apk(apk1)
        info2 = decompile_apk(apk2)
        
        # Diferencia de tamaño
        diff['size_diff'] = (info2['size'] - info1['size']) / 1024 / 1024
        
        # Archivos nuevos y eliminados
        files1 = set(info1.get('files', []))
        files2 = set(info2.get('files', []))
        
        diff['new_files'] = list(files2 - files1)
        diff['removed_files'] = list(files1 - files2)
        diff['modified_files'] = len(files1.intersection(files2))
        
        # Permisos
        perms1 = set(p['name'] for p in detect_permissions(apk1))
        perms2 = set(p['name'] for p in detect_permissions(apk2))
        
        diff['new_permissions'] = len(perms2 - perms1)
        diff['removed_permissions'] = len(perms1 - perms2)
        
    except Exception as e:
        diff['error'] = str(e)
    
    return diff


def extract_strings_xml(apk_file):
    """Extrae strings.xml del APK"""
    strings = {}
    
    try:
        content = apk_file.read()
        
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            # Buscar strings.xml en diferentes locales
            string_files = [f for f in zf.namelist() if 'strings.xml' in f]
            
            for string_file in string_files:
                xml_content = zf.read(string_file).decode('utf-8', errors='ignore')
                
                # Parsear XML básico
                name_pattern = r'<string\s+name="([^"]+)">([^<]+)</string>'
                matches = re.findall(name_pattern, xml_content)
                
                for name, value in matches:
                    strings[name] = value
        
        apk_file.seek(0)
        
    except Exception as e:
        strings['error'] = str(e)
    
    return strings


def analyze_gradle_files(gradle_file):
    """Analiza archivos build.gradle"""
    gradle_info = {
        'dependencies': [],
        'plugins': [],
        'min_sdk': '',
        'target_sdk': '',
        'version_name': '',
        'version_code': ''
    }
    
    try:
        content = gradle_file.read().decode('utf-8')
        
        # Buscar dependencias
        dep_pattern = r'implementation\s+["\'](.+)["\']'
        dependencies = re.findall(dep_pattern, content)
        gradle_info['dependencies'] = dependencies
        
        # Buscar plugins
        plugin_pattern = r'apply\s+plugin:\s+["\'](.+)["\']'
        plugins = re.findall(plugin_pattern, content)
        gradle_info['plugins'] = plugins
        
        # Buscar SDKs
        min_sdk_pattern = r'minSdkVersion\s+(\d+)'
        target_sdk_pattern = r'targetSdkVersion\s+(\d+)'
        
        min_sdk = re.search(min_sdk_pattern, content)
        if min_sdk:
            gradle_info['min_sdk'] = min_sdk.group(1)
        
        target_sdk = re.search(target_sdk_pattern, content)
        if target_sdk:
            gradle_info['target_sdk'] = target_sdk.group(1)
        
        gradle_file.seek(0)
        
    except Exception as e:
        gradle_info['error'] = str(e)
    
    return gradle_info


def detect_native_libs(apk_file):
    """Detecta librerías nativas (.so) en el APK"""
    native_libs = {}
    
    try:
        content = apk_file.read()
        
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            # Buscar archivos .so
            so_files = [f for f in zf.namelist() if f.endswith('.so')]
            
            # Organizar por arquitectura
            for so_file in so_files:
                parts = so_file.split('/')
                if len(parts) >= 3 and parts[0] == 'lib':
                    arch = parts[1]  # armeabi-v7a, arm64-v8a, x86, etc.
                    lib_name = parts[2]
                    
                    if arch not in native_libs:
                        native_libs[arch] = []
                    
                    native_libs[arch].append(lib_name)
        
        apk_file.seek(0)
        
    except Exception as e:
        native_libs['error'] = str(e)
    
    return native_libs

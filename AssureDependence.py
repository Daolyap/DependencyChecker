#!/usr/bin/env python3
"""
Enterprise Dependency Scanner
Identifies applications dependent on .NET Core, Java, SQL Databases, etc.
Excludes built-in .NET Framework.
"""

import os
import re
import json
import subprocess
import winreg
from pathlib import Path
from collections import defaultdict
import psutil
import xml.etree.ElementTree as ET

class DependencyScanner:
    def __init__(self):
        self.dependencies = defaultdict(list)
        self.running_processes = {}
        self.installed_frameworks = {}
        
    def scan_all(self):
        """Main scanning orchestrator"""
        print("🔍 Starting comprehensive dependency scan...")
        self.detect_frameworks()
        self.scan_installed_applications()
        self.scan_running_processes()
        return self.generate_report()
    
    def detect_frameworks(self):
        """Detect installed runtime frameworks (.NET Core, Java, SQL)"""
        frameworks = {}
        
        # Java detection
        java_versions = self.detect_java_installations()
        frameworks.update(java_versions)
        
        # .NET Core/5+ detection
        dotnet_versions = self.detect_dotnet_core()
        frameworks.update(dotnet_versions)
        
        # SQL Database detection
        sql_versions = self.detect_sql_databases()
        frameworks.update(sql_versions)
        
        self.installed_frameworks = frameworks
        print(f"📦 Found {len(frameworks)} framework installations (excluding .NET Framework)")
    
    def detect_java_installations(self):
        """Detect Java installations via registry."""
        java_installs = {}
        try:
            base_key = r"SOFTWARE\JavaSoft\Java Runtime Environment"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    version = winreg.EnumKey(key, i)
                    try:
                        with winreg.OpenKey(key, version) as version_key:
                            java_home, _ = winreg.QueryValueEx(version_key, "JavaHome")
                            java_installs[f"Java {version}"] = {
                                'version': version, 'path': java_home, 'type': 'java',
                                'eol_status': self.check_java_eol(version)
                            }
                    except FileNotFoundError: continue
        except Exception as e:
            print(f"- Info: Could not scan for installed Java versions: {e}")
        return java_installs
    
    def detect_dotnet_core(self):
        """Detect .NET Core/.NET 5+ installations via dotnet CLI."""
        dotnet_versions = {}
        try:
            result = subprocess.run(['dotnet', '--list-runtimes'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        match = re.match(r'([^\s]+)\s+([^\s]+)\s+\[(.*)\]', line)
                        if match:
                            runtime, version, path = match.groups()
                            key = f"{runtime} {version}"
                            dotnet_versions[key] = {
                                'version': version, 'runtime': runtime, 'path': path, 'type': 'dotnet_core',
                                'eol_status': self.check_dotnet_core_eol(version)
                            }
        except FileNotFoundError:
            print("- Info: dotnet CLI not found. .NET Core detection will be limited to runtime analysis.")
        return dotnet_versions

    def detect_sql_databases(self):
        """Detects installed SQL database server instances."""
        print("🔍 Scanning for SQL database installations...")
        sql_installs = {}
        sql_installs.update(self.detect_sql_server_instances())
        sql_installs.update(self.detect_mysql_instances())
        sql_installs.update(self.detect_postgresql_instances())
        return sql_installs

    def detect_sql_server_instances(self):
        """Detects Microsoft SQL Server instances via registry and services."""
        sql_server_installs = {}
        try:
            # Find instance names from the registry
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL") as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, inst_id, _ = winreg.EnumValue(key, i)
                    try:
                        # Get version from the instance-specific key
                        ver_key_path = fr"SOFTWARE\Microsoft\Microsoft SQL Server\{inst_id}\MSSQLServer\CurrentVersion"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ver_key_path) as ver_key:
                            version, _ = winreg.QueryValueEx(ver_key, "CurrentVersion")
                        
                        # Get path from the instance-specific key
                        path_key_path = fr"SOFTWARE\Microsoft\Microsoft SQL Server\{inst_id}\Setup"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path_key_path) as path_key:
                            path, _ = winreg.QueryValueEx(path_key, "SQLDataRoot")

                        display_name = f"Microsoft SQL Server {version.split('.')[0]} (Instance: {name})"
                        sql_server_installs[display_name] = {
                            'version': version, 'path': path, 'type': 'mssql',
                            'eol_status': self.check_mssql_eol(version)
                        }
                    except FileNotFoundError:
                        continue
        except Exception as e:
            print(f"- Info: Could not scan for MS SQL Server: {e}")
        return sql_server_installs

    def detect_mysql_instances(self):
        """Detects MySQL instances by checking Windows Services."""
        mysql_installs = {}
        try:
            for service in psutil.win_service_iter():
                if service.name().lower().startswith("mysql"):
                    try:
                        version_match = re.search(r"(\d+\.\d+\.\d+)", service.display_name() + service.binpath())
                        version = version_match.group(1) if version_match else "Unknown"
                        path = Path(service.binpath()).parent.parent
                        display_name = f"MySQL Server {version}"
                        mysql_installs[display_name] = {
                            'version': version, 'path': str(path), 'type': 'mysql',
                            'eol_status': self.check_mysql_eol(version)
                        }
                    except (psutil.AccessDenied, FileNotFoundError):
                        continue
        except Exception as e:
            print(f"- Info: Could not scan for MySQL services: {e}")
        return mysql_installs

    def detect_postgresql_instances(self):
        """Detects PostgreSQL instances by checking Windows Services."""
        postgres_installs = {}
        try:
            for service in psutil.win_service_iter():
                if service.name().lower().startswith("postgresql"):
                    try:
                        version_match = re.search(r"(\d+(\.\d+)?)", service.name() + service.display_name())
                        version = version_match.group(1) if version_match else "Unknown"
                        path = Path(service.binpath()).parent.parent
                        display_name = f"PostgreSQL {version}"
                        postgres_installs[display_name] = {
                            'version': version, 'path': str(path), 'type': 'postgresql',
                            'eol_status': self.check_postgresql_eol(version)
                        }
                    except (psutil.AccessDenied, FileNotFoundError):
                        continue
        except Exception as e:
            print(f"- Info: Could not scan for PostgreSQL services: {e}")
        return postgres_installs
    
    def scan_installed_applications(self):
        """Scan installed applications for framework dependencies"""
        print("🔍 Scanning installed applications for .NET Core and Java...")
        program_dirs = [Path("C:/Program Files"), Path("C:/Program Files (x86)"), Path("C:/ProgramData")]
        for prog_dir in program_dirs:
            if prog_dir.exists():
                self.scan_directory_for_dependencies(prog_dir)
        
    def scan_directory_for_dependencies(self, directory, max_depth=3):
        if max_depth <= 0: return
        try:
            for item in directory.iterdir():
                if item.is_file() and item.suffix.lower() == '.jar':
                    self.analyze_file_dependencies(item)
                elif item.is_dir() and not item.name.startswith('.'):
                    self.scan_directory_for_dependencies(item, max_depth - 1)
        except (PermissionError, OSError): pass
    
    def analyze_file_dependencies(self, file_path):
        """Analyze individual file for .NET Core or Java dependencies"""
        try:
            app_name = self.get_application_name(file_path)
            self.dependencies['java'].append({
                'app': app_name, 'file': str(file_path), 'framework': 'Java Runtime',
                'detection_method': 'static_analysis', 'confidence': 'high'
            })
        except Exception: pass
    
    def scan_running_processes(self):
        """Scan running processes for framework usage"""
        print("🔍 Scanning running processes...")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['exe']: self.analyze_running_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
    
    def analyze_running_process(self, proc):
        """Analyze individual running process for .NET Core and Java"""
        try:
            proc_info = proc.info
            exe_path = proc_info['exe']
            if not exe_path: return

            dotnet_version, dotnet_path = self.get_dotnet_core_version_from_process(proc)
            if dotnet_version:
                self.dependencies['dotnet_runtime'].append({
                    'app': proc_info['name'], 'pid': proc_info['pid'], 'file': exe_path,
                    'framework': f".NET Core Runtime {dotnet_version}", 'dependency_path': dotnet_path,
                    'detection_method': 'runtime_analysis', 'confidence': 'high', 'status': 'running'
                })

            if self.is_java_process(proc):
                java_version, java_path = self.detect_java_version_from_process(proc)
                self.dependencies['java_runtime'].append({
                    'app': proc_info['name'], 'pid': proc_info['pid'], 'file': exe_path,
                    'framework': f"Java Runtime {java_version}", 'dependency_path': java_path,
                    'detection_method': 'runtime_analysis', 'confidence': 'high', 'status': 'running'
                })
        except Exception: pass
    
    def get_dotnet_core_version_from_process(self, proc):
        """Returns the .NET Core version string and the path to coreclr.dll, or (None, None)."""
        try:
            for dll in proc.memory_maps():
                path_lower = dll.path.lower()
                core_match = re.search(r'\\dotnet\\shared\\(microsoft\.(?:netcore|aspnetcore)\.app)\\([^\\\\]+)\\coreclr\.dll', path_lower)
                if core_match:
                    version = f"{core_match.group(2)} ({core_match.group(1).split('.')[-2]})"
                    return version, dll.path
                if 'coreclr.dll' in path_lower and 'microsoft.net' not in path_lower:
                    version = f"Self-Contained ({proc.info.get('name', 'Unknown')})"
                    return version, dll.path
        except (psutil.AccessDenied, psutil.NoSuchProcess): pass
        return None, None

    def is_java_process(self, proc):
        try: return proc.info.get('name', '').lower() in ['java.exe', 'javaw.exe']
        except: return False
    
    def detect_java_version_from_process(self, proc):
        try:
            exe_path = proc.info['exe']
            if exe_path:
                result = subprocess.run([exe_path, '-version'], capture_output=True, text=True, stderr=subprocess.STDOUT, timeout=2)
                if result.returncode == 0:
                    version_match = re.search(r'version "([^"]+)"', result.stdout)
                    if version_match: return version_match.group(1), exe_path
        except Exception: pass
        return "Unknown", proc.info.get('exe', 'Unknown')

    def generate_report(self):
        return {
            'scan_summary': {
                'frameworks_found': len(self.installed_frameworks),
                'dependencies_found': sum(len(deps) for deps in self.dependencies.values()),
                'scan_timestamp': str(psutil.boot_time())
            },
            'installed_frameworks': self.installed_frameworks,
            'dependencies': dict(self.dependencies)
        }
    
    def get_application_name(self, file_path):
        try:
            if 'program files' in file_path.parts[1].lower(): return file_path.parts[2]
            if 'windowsapps' in file_path.parts[1].lower(): return file_path.parts[2].split('_')[0]
        except IndexError: pass
        return file_path.stem

    # --- EOL CHECKER METHODS ---
    def check_java_eol(self, v): 
        try: return 'EOL' if int(v.split('.')[1]) < 11 else 'Supported'
        except: return 'Unknown'

    def check_dotnet_core_eol(self, v):
        eol_versions = ['1.0', '1.1', '2.0', '2.1', '2.2', '3.0', '3.1', '5.0', '6.0' '7.0']
        return 'EOL' if any(v.startswith(p) for p in eol_versions) else 'Supported'
        
    def check_mssql_eol(self, v):
        try:
            major_version = int(v.split('.')[0])
            # 13=2016, 14=2017, 15=2019, 16=2022. Anything < 2016 is EOL.
            return 'EOL' if major_version < 13 else 'Supported'
        except: return 'Unknown'
        
    def check_mysql_eol(self, v):
        try:
            # MySQL versions before 8.0 are EOL.
            return 'EOL' if v.startswith('5.') else 'Supported'
        except: return 'Unknown'
        
    def check_postgresql_eol(self, v):
        try:
            major_version = int(v.split('.')[0])
            # PostgreSQL versions before 12 are generally EOL.
            return 'EOL' if major_version < 12 else 'Supported'
        except: return 'Unknown'

if __name__ == "__main__":
    scanner = DependencyScanner()
    report = scanner.scan_all()
    with open('dependency_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("\n📊 DEPENDENCY SCAN COMPLETE")
    print(f"Found {report['scan_summary']['dependencies_found']} dependencies on .NET Core, Java, SQL, etc.")
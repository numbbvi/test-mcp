#!/usr/bin/env python3
"""
NPM Analyzer for SBOM Generator
Analyzes NPM projects and extracts package information
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from .baseAnalyzer import BaseAnalyzer, ProjectType


class NpmAnalyzer(BaseAnalyzer):
    """NPM project analyzer for SBOM generation"""
    
    def __init__(self, project_path: str):
        """
        Initialize NPM analyzer
        
        Args:
            project_path: Path to the NPM project directory
        """
        super().__init__(project_path)
        
        if not self.is_npm():
            raise ValueError(f"Not an NPM project: {project_path}")
        
        self.package_json_path = self.project_path / "package.json"
        self.package_lock_path = self.project_path / "package-lock.json"
        
        # Load package.json
        self.package_data = self._load_package_json()
        
        # Ensure package-lock.json exists
        self._ensure_package_lock()
        
        # Load package-lock.json
        self.package_lock_data = self._load_package_lock()
        self._license_cache: Dict[str, Optional[str]] = {}
    
    def _load_package_json(self) -> Dict[str, Any]:
        """Load and parse package.json"""
        try:
            with open(self.package_json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load package.json: {e}")
    
    def _load_package_lock(self) -> Dict[str, Any]:
        """Load and parse package-lock.json"""
        try:
            with open(self.package_lock_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load package-lock.json: {e}")
    
    def _ensure_package_lock(self) -> None:
        """Ensure package-lock.json exists, run npm install if needed"""
        if not self.package_lock_path.exists():
            print("package-lock.json not found. Running npm install...")
            try:
                result = subprocess.run(
                    ["npm", "install"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                print("npm install completed successfully")
            except subprocess.CalledProcessError as e:
                if "link:" in e.stderr or "EUNSUPPORTEDPROTOCOL" in e.stderr:
                    print("Warning: npm install failed due to unsupported link: protocol dependencies.")
                    print("Attempting to generate package-lock.json by removing link: dependencies...")
                    try:
                        self._create_package_lock_without_link_deps()
                    except Exception as e2:
                        print(f"Warning: Could not generate package-lock.json: {e2}")
                        print("Continuing with package.json analysis only...")
                        self._create_empty_package_lock()
                else:
                    raise RuntimeError(f"npm install failed: {e.stderr}")
            except FileNotFoundError:
                raise RuntimeError("npm command not found. Please install Node.js and npm.")
    
    def _create_empty_package_lock(self) -> None:
        """Create an empty package-lock.json structure"""
        empty_lock = {
            "name": self.package_data.get("name", "unknown"),
            "version": self.package_data.get("version", "1.0.0"),
            "lockfileVersion": 3,
            "requires": True,
            "packages": {},
            "dependencies": {}
        }
        with open(self.package_lock_path, 'w', encoding='utf-8') as f:
            json.dump(empty_lock, f, indent=2)
    
    def _create_package_lock_without_link_deps(self) -> None:
        """Create package-lock.json by temporarily removing link: dependencies"""
        import shutil
        import tempfile
        
        modified_package = self.package_data.copy()
        
        if "devDependencies" in modified_package:
            modified_package["devDependencies"] = {
                k: v for k, v in modified_package["devDependencies"].items()
                if not (isinstance(v, str) and v.startswith("link:"))
            }
        
        backup_file = self.package_json_path.with_suffix('.json.backup')
        shutil.copy(self.package_json_path, backup_file)
        
        try:
            with open(self.package_json_path, 'w', encoding='utf-8') as f:
                json.dump(modified_package, f, indent=2)
            
            result = subprocess.run(
                ["npm", "install", "--package-lock-only"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            print("package-lock.json generated successfully (without link: dependencies)")
        finally:
            if backup_file.exists():
                shutil.copy(backup_file, self.package_json_path)
                backup_file.unlink()
    
    def _ensure_node_modules(self) -> None:
        node_modules = self.project_path / "node_modules"
        if node_modules.exists():
            return
        print("node_modules not found, running npm install --ignore-scripts...")
        try:
            subprocess.run(
                ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=self.project_path,
                check=True,
                capture_output=True,
                text=True
            )
            print("npm install completed successfully")
        except subprocess.CalledProcessError as e:
            print(f"Warning: npm install failed while preparing licenses: {e.stderr.strip() if e.stderr else e}")

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze NPM project and extract package information
        
        Returns:
            Dictionary containing analysis results
        """
        root_package = self._extract_root_package()
        
        self._ensure_node_modules()

        all_packages = self._extract_all_packages()
        self.all_packages = all_packages  
        
        # Build dependency graph
        dependencies = self._build_dependency_graph()
        
        # Identify direct dependencies
        direct_deps = self._identify_direct_dependencies()
        
        # Add main package dependencies to the graph
        main_name = root_package.get("name", "")
        main_version = root_package.get("version", "")
        main_key = f"{main_name}@{main_version}"
        dependencies[main_key] = direct_deps
        
        # Mark direct dependencies in packages
        for package in all_packages:
            package_name = package.get("name", "")
            package_version = package.get("version", "")
            package_key = f"{package_name}@{package_version}"
            
            # Ensure metadata exists
            if "metadata" not in package:
                package["metadata"] = {}
            
            if package_key in direct_deps:
                package["metadata"]["is_direct"] = True
            else:
                package["metadata"]["is_direct"] = False
        
        return {
            "root_package": root_package,
            "packages": all_packages,
            "all_packages": all_packages,
            "dependencies": dependencies,
            "direct_dependencies": direct_deps,
            "total_packages": len(all_packages),
            "direct_deps_count": len(direct_deps),
            "project_info": {
                "name": root_package.get("name", "unknown"),
                "version": root_package.get("version", "0.0.0")
            }
        }
    
    def _extract_root_package(self) -> Dict[str, Any]:
        """Extract root package information"""
        return {
            "name": self.package_data.get("name", "unknown"),
            "version": self.package_data.get("version", "0.0.0"),
            "description": self.package_data.get("description", ""),
            "author": self.package_data.get("author", ""),
            "license": self.package_data.get("license", ""),
            "homepage": self.package_data.get("homepage", ""),
            "repository": self.package_data.get("repository", ""),
            "bugs": self.package_data.get("bugs", ""),
            "keywords": self.package_data.get("keywords", []),
            "engines": self.package_data.get("engines", {}),
            "type": "application"  
        }
    
    def _extract_all_packages(self) -> List[Dict[str, Any]]:
        """Extract all packages from package-lock.json"""
        packages = []
        
        # Add root package
        root_package = self._extract_root_package()
        packages.append(root_package)
        
        # Extract packages from package-lock.json
        has_lockfile_packages = False
        if "packages" in self.package_lock_data and len(self.package_lock_data["packages"]) > 1:  # More than just root package
            for package_path, package_info in self.package_lock_data["packages"].items():
                if package_path == "":  
                    continue
                
                package = self._parse_package_info(package_path, package_info)
                if package:
                    packages.append(package)
                    has_lockfile_packages = True
        
        # If package-lock.json is empty or invalid, extract from package.json
        if not has_lockfile_packages:
            packages.extend(self._extract_packages_from_package_json())
        
        return packages
    
    def _extract_packages_from_package_json(self) -> List[Dict[str, Any]]:
        """Extract packages from package.json when package-lock.json is unavailable"""
        packages = []
        
        # Get all dependency types
        dep_types = ["dependencies", "devDependencies", "optionalDependencies"]
        
        for dep_type in dep_types:
            if dep_type in self.package_data:
                for dep_name, dep_version in self.package_data[dep_type].items():
                    # Skip link: protocol dependencies (workspace/local dependencies)
                    if isinstance(dep_version, str) and dep_version.startswith("link:"):
                        continue
                    
                    # Clean version range
                    clean_version = self._clean_version_range(dep_version)
                    
                    # Create package info
                    package = {
                        "name": dep_name,
                        "version": clean_version,
                        "type": "library",
                        "metadata": {
                            "description": "",
                            "dependency_type": dep_type,
                            "is_direct": True,
                            "dev": dep_type == "devDependencies",
                            "optional": dep_type == "optionalDependencies"
                        }
                    }
                    packages.append(package)
        
        return packages
    
    def _extract_declared_dependencies(self) -> List[Dict[str, Any]]:
        """Extract declared dependencies from package.json that might not be installed"""
        return []
    
    def _extract_package_lock_peer_dependencies(self) -> List[Dict[str, Any]]:
        """Extract peerDependencies from package-lock.json that might not be installed"""
        return []
    
    def _parse_package_info(self, package_path: str, package_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse individual package information"""
        if not package_info:
            return None
        
        # Extract name and version
        name = package_info.get("name", "")
        version = package_info.get("version", "")
        
        # For packages without name, try to extract from package_path
        if not name and package_path and package_path != "":
            # Extract package name from path (e.g., "node_modules/express" -> "express")
            # Handle scoped packages (e.g., "node_modules/@scope/package" -> "@scope/package")
            path_parts = package_path.split("/")
            if len(path_parts) > 1 and path_parts[-2] == "node_modules":
                name = path_parts[-1]
            elif len(path_parts) > 2 and path_parts[-3] == "node_modules" and path_parts[-2].startswith("@"):
                # Handle scoped packages: "node_modules/@scope/package" -> "@scope/package"
                name = f"{path_parts[-2]}/{path_parts[-1]}"
        
        if not name or not version:
            return None
        
        # Determine package type
        package_type = "library"
        if "bin" in package_info:
            package_type = "application"
        
        # Extract metadata
        metadata = {
            "description": package_info.get("description", ""),
            "author": package_info.get("author", ""),
            "license": package_info.get("license", ""),
            "homepage": package_info.get("homepage", ""),
            "repository": package_info.get("repository", ""),
            "bugs": package_info.get("bugs", ""),
            "keywords": package_info.get("keywords", []),
            "engines": package_info.get("engines", {}),
            "optional": package_info.get("optional", False),
            "dev": package_info.get("dev", False),
            "peer": package_info.get("peer", False),
            "bundled": package_info.get("bundled", False),
            "integrity": package_info.get("integrity", ""),
            "resolved": package_info.get("resolved", ""),
            "package_path": package_path
        }

        license_id = metadata.get("license") or self._resolve_package_license(package_path, name, version, package_info)
        if license_id:
            metadata["license"] = license_id

        return {
            "name": name,
            "version": version,
            "type": package_type,
            "package_path": package_path,  # Add package path for npm-specific info
            "metadata": metadata
        }
    
    def _resolve_package_license(self, package_path: str, package_name: str, version: str, package_info: Dict[str, Any]) -> Optional[str]:
        cache_key = f"{package_path}|{package_name}@{version}"
        if cache_key in self._license_cache:
            return self._license_cache[cache_key]

        license_field = package_info.get('license')
        license_id = self._normalize_license_value(license_field)
        if not license_id:
            license_id = self._extract_license_from_package_json(package_path)
        if not license_id:
            license_id = self._fetch_license_from_registry(package_name, version)

        self._license_cache[cache_key] = license_id
        return license_id

    def _fetch_license_from_registry(self, package_name: str, version: str) -> Optional[str]:
        if not package_name or not version:
            return None
        cache_key = f"registry|{package_name}@{version}"
        if cache_key in self._license_cache:
            return self._license_cache[cache_key]
        try:
            result = subprocess.run(
                ["npm", "view", f"{package_name}@{version}", "license", "--json"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            if not output:
                self._license_cache[cache_key] = None
                return None
            try:
                value = json.loads(output)
            except json.JSONDecodeError:
                value = output
            license_id = self._normalize_license_value(value)
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            print(f"Warning: npm view failed for {package_name}@{version}: {err}")
            license_id = None
        self._license_cache[cache_key] = license_id
        return license_id

    def _extract_license_from_package_json(self, package_path: str) -> Optional[str]:
        if not package_path:
            return None
        full_path = self.project_path / Path(package_path)
        if not full_path.exists():
            # handle paths missing node_modules prefix
            full_path = (self.project_path / 'node_modules' / Path(package_path)).resolve()
            if not full_path.exists():
                return None
        package_json_path = full_path / 'package.json'
        if not package_json_path.exists():
            return None
        try:
            with package_json_path.open('r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return None

        license_id = self._normalize_license_value(data.get('license'))
        if license_id:
            return license_id

        licenses_field = data.get('licenses')
        if isinstance(licenses_field, list):
            for entry in licenses_field:
                license_id = self._normalize_license_value(entry)
                if license_id:
                    return license_id
        elif isinstance(licenses_field, dict):
            license_id = self._normalize_license_value(licenses_field)
            if license_id:
                return license_id

        return None

    def _normalize_license_value(self, value: Any) -> Optional[str]:
        if isinstance(value, str):
            value = value.strip()
            return value if value else None
        if isinstance(value, dict):
            for key in ('type', 'name', 'id'):
                if key in value and isinstance(value[key], str) and value[key].strip():
                    return value[key].strip()
        if isinstance(value, list):
            for item in value:
                normalized = self._normalize_license_value(item)
                if normalized:
                    return normalized
        return None

    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """Build dependency graph from package-lock.json"""
        dependencies = {}
        
        if "packages" in self.package_lock_data:
            for package_path, package_info in self.package_lock_data["packages"].items():
                if package_path == "":  # Skip root package
                    continue
                
                # Extract package name (handle scoped packages)
                package_name = package_info.get("name", "")
                if not package_name:
                    # Extract from path for packages without name field
                    if package_path.startswith("node_modules/"):
                        path_parts = package_path.split("/")
                        if len(path_parts) > 1 and path_parts[-2] == "node_modules":
                            package_name = path_parts[-1]
                        elif len(path_parts) > 2 and path_parts[-3] == "node_modules" and path_parts[-2].startswith("@"):
                            package_name = f"{path_parts[-2]}/{path_parts[-1]}"
                
                if not package_name:
                    continue
                
                package_version = package_info.get("version", "")
                package_key = f"{package_name}@{package_version}"
                
                # Get dependencies for this package
                package_deps = []
                
                # Handle regular dependencies
                if "dependencies" in package_info:
                    for dep_name, dep_info in package_info["dependencies"].items():
                        # Find the actual installed version of this dependency
                        actual_version = self._find_actual_version(dep_name)
                        if actual_version:
                            package_deps.append(f"{dep_name}@{actual_version}")
                
                
                # Handle optionalDependencies
                if "optionalDependencies" in package_info:
                    for opt_name, opt_version in package_info["optionalDependencies"].items():
                        # Find the actual installed version of this optionalDependency
                        actual_version = self._find_actual_version(opt_name)
                        if actual_version:
                            package_deps.append(f"{opt_name}@{actual_version}")
                            # Mark as optionalDependency in metadata
                            for pkg in self.all_packages:
                                if pkg.get("name") == opt_name and pkg.get("version") == actual_version:
                                    if "metadata" not in pkg:
                                        pkg["metadata"] = {}
                                    pkg["metadata"]["dependency_type"] = "optionalDependencies"
                                    pkg["metadata"]["is_optional"] = True
                
                if package_deps:
                    dependencies[package_key] = package_deps
        
        return dependencies
    
    def _identify_direct_dependencies(self) -> List[str]:
        """Identify direct dependencies from package.json"""
        direct_deps = []
        
        dep_types = [
            "dependencies",
            "devDependencies", 
            "optionalDependencies"
        ]
        
        for dep_type in dep_types:
            if dep_type in self.package_data:
                for dep_name, dep_version in self.package_data[dep_type].items():
                    # For optionalDependencies, check if it's actually installed
                    if dep_type == "optionalDependencies":
                        actual_version = self._find_actual_version(dep_name)
                        if actual_version:
                            direct_deps.append(f"{dep_name}@{actual_version}")
                    else:
                        # Remove version range prefixes (^, ~, >=, etc.)
                        clean_version = self._clean_version_range(dep_version)
                        direct_deps.append(f"{dep_name}@{clean_version}")
                    
                    # Store metadata for SBOM generation (will be handled in analyze method)
                    # Note: Metadata storage is handled in the analyze method where all_packages is available
        
        return direct_deps
    
    def _clean_version_range(self, version: str) -> str:
        """Clean version range to get exact version"""
        if not version:
            return version
        
        # Remove common version range prefixes
        version = version.lstrip('^~>=<')
        
        # If it's a range like ">=1.0.0 <2.0.0", take the first part
        if ' ' in version:
            version = version.split(' ')[0]
        
        return version
    
    def _find_actual_version(self, package_name: str) -> str:
        """Find the actual installed version of a package"""
        if "packages" not in self.package_lock_data:
            return ""
        
        # Look for the package in node_modules
        for path, info in self.package_lock_data["packages"].items():
            # Exact match
            if path == f"node_modules/{package_name}":
                return info.get("version", "")
            # Scoped package match (e.g., @types/express)
            elif path.startswith(f"node_modules/{package_name}/"):
                return info.get("version", "")
            # Handle scoped packages differently
            elif package_name.startswith("@") and path == f"node_modules/{package_name}":
                return info.get("version", "")
        
        return ""
    
    def get_dependency_types(self) -> Dict[str, List[str]]:
        """Get dependencies categorized by type"""
        dep_types = {
            "dependencies": [],
            "devDependencies": [],
            "peerDependencies": [],
            "optionalDependencies": []
        }
        
        for dep_type in dep_types.keys():
            if dep_type in self.package_data:
                for dep_name, dep_version in self.package_data[dep_type].items():
                    dep_types[dep_type].append(f"{dep_name}@{dep_version}")
        
        return dep_types
    
    def get_package_summary(self) -> Dict[str, Any]:
        """Get summary of package analysis"""
        analysis = self.analyze()
        
        return {
            "project_name": analysis["root_package"]["name"],
            "project_version": analysis["root_package"]["version"],
            "total_packages": analysis["total_packages"],
            "direct_dependencies": analysis["direct_deps_count"],
            "dependency_types": self.get_dependency_types(),
            "has_dev_dependencies": len(self.package_data.get("devDependencies", {})) > 0,
            "has_peer_dependencies": len(self.package_data.get("peerDependencies", {})) > 0,
            "has_optional_dependencies": len(self.package_data.get("optionalDependencies", {})) > 0
        }

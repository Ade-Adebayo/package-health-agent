from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from typing import List, Dict, Optional, Any
from datetime import datetime
import requests
import logging
from models.a2a import JSONRPCRequest, JSONRPCResponse
from models.schemas import (
    PackageDependency,
    PythonDependenciesRequest,
    NpmDependenciesRequest,
    PackageHealthResponse,
    OverallHealthResponse
)
from a2a_handler import A2AHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initializing the api
app = FastAPI(
    title="Package Health Monitor Agent (A2A)",
    description="An A2A Protocol Agent that monitors package health and security",
    version="1.0.0"
)

# Package checking class
class PackageChecker:
    """Class to check package health"""
    
    async def analyze_python(self, packages: List[str]) -> Dict[str, Any]:
        """Analyze Python packages"""
        parsed_packages = []
        for pkg_str in packages:
            pkg_str = pkg_str.strip()
            if not pkg_str or pkg_str.startswith('#'):
                continue
            
            for op in ['==', '>=', '<=', '>', '<', '~=']:
                if op in pkg_str:
                    name, version = pkg_str.split(op, 1)
                    parsed_packages.append(PackageDependency(name=name.strip(), version=version.strip()))
                    break
            else:
                parsed_packages.append(PackageDependency(name=pkg_str, version=None))
        
        if not parsed_packages:
            return {}
        
        results = []
        outdated_count = 0
        vulnerable_count = 0
        deprecated_count = 0
        
        for pkg in parsed_packages:
            pypi_info = check_pypi_package(pkg.name, pkg.version)
            vulnerabilities = check_vulnerabilities_osv(pkg.name, "python")
            
            is_outdated = pypi_info['is_outdated']
            has_vulns = len(vulnerabilities) > 0
            is_deprecated = pypi_info.get('deprecated', False)
            
            if is_outdated:
                outdated_count += 1
            if has_vulns:
                vulnerable_count += 1
            if is_deprecated:
                deprecated_count += 1
            
            health_score = calculate_health_score(is_outdated, len(vulnerabilities), is_deprecated)
            recommendation = get_recommendation(health_score, is_outdated, len(vulnerabilities), is_deprecated)
            
            results.append({
                "name": pkg.name,
                "current_version": pkg.version,
                "latest_version": pypi_info['latest_version'],
                "is_outdated": is_outdated,
                "has_vulnerabilities": has_vulns,
                "vulnerability_count": len(vulnerabilities),
                "is_deprecated": is_deprecated,
                "health_score": health_score,
                "recommendation": recommendation,
                "vulnerabilities": vulnerabilities
            })
        
        overall_score = sum(r["health_score"] for r in results) // len(results) if results else 0
        
        return {
            "total_packages": len(results),
            "outdated_count": outdated_count,
            "vulnerable_count": vulnerable_count,
            "deprecated_count": deprecated_count,
            "overall_health_score": overall_score,
            "packages": results
        }
    
    async def analyze_npm(self, dependencies: Dict[str, str]) -> Dict[str, Any]:
        """Analyze npm packages"""
        if not dependencies:
            return {}
        
        packages = []
        for name, version in dependencies.items():
            clean_version = version.lstrip('^~>=<')
            packages.append(PackageDependency(name=name, version=clean_version))
        
        results = []
        outdated_count = 0
        vulnerable_count = 0
        deprecated_count = 0
        
        for pkg in packages:
            npm_info = check_npm_package(pkg.name, pkg.version)
            vulnerabilities = check_vulnerabilities_osv(pkg.name, "npm")
            
            is_outdated = npm_info['is_outdated']
            has_vulns = len(vulnerabilities) > 0
            is_deprecated = npm_info.get('deprecated', False)
            
            if is_outdated:
                outdated_count += 1
            if has_vulns:
                vulnerable_count += 1
            if is_deprecated:
                deprecated_count += 1
            
            health_score = calculate_health_score(is_outdated, len(vulnerabilities), is_deprecated)
            recommendation = get_recommendation(health_score, is_outdated, len(vulnerabilities), is_deprecated)
            
            results.append({
                "name": pkg.name,
                "current_version": pkg.version,
                "latest_version": npm_info['latest_version'],
                "is_outdated": is_outdated,
                "has_vulnerabilities": has_vulns,
                "vulnerability_count": len(vulnerabilities),
                "is_deprecated": is_deprecated,
                "health_score": health_score,
                "recommendation": recommendation,
                "vulnerabilities": vulnerabilities
            })
        
        overall_score = sum(r["health_score"] for r in results) // len(results) if results else 0
        
        return {
            "total_packages": len(results),
            "outdated_count": outdated_count,
            "vulnerable_count": vulnerable_count,
            "deprecated_count": deprecated_count,
            "overall_health_score": overall_score,
            "packages": results
        }

# Helper functions (from original main.py)
def check_pypi_package(package_name: str, current_version: Optional[str]) -> Dict:
    """Check package on PyPI"""
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            latest_version = data['info']['version']
            is_outdated = current_version and current_version != latest_version
            
            return {
                'latest_version': latest_version,
                'is_outdated': is_outdated,
                'deprecated': False
            }
    except Exception as e:
        print(f"Error checking PyPI for {package_name}: {e}")
    
    return {'latest_version': None, 'is_outdated': False, 'deprecated': False}

def check_npm_package(package_name: str, current_version: Optional[str]) -> Dict:
    """Check package on npm registry"""
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            latest_version = data['dist-tags']['latest']
            is_outdated = current_version and current_version != latest_version
            
            return {
                'latest_version': latest_version,
                'is_outdated': is_outdated,
                'deprecated': False
            }
    except Exception as e:
        print(f"Error checking npm for {package_name}: {e}")
    
    return {'latest_version': None, 'is_outdated': False, 'deprecated': False}

def check_vulnerabilities_osv(package_name: str, ecosystem: str) -> List[Dict]:
    """Check vulnerabilities using OSV API"""
    vulnerabilities = []
    
    try:
        url = "https://api.osv.dev/v1/query"
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI" if ecosystem == "python" else "npm"
            }
        }
        
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulns', [])
            
            for vuln in vulns:
                vulnerabilities.append({
                    'id': vuln.get('id'),
                    'summary': vuln.get('summary', 'No summary available'),
                    'severity': vuln.get('severity', [{}])[0].get('type', 'UNKNOWN') if vuln.get('severity') else 'UNKNOWN',
                    'published': vuln.get('published', '')
                })
    except Exception as e:
        print(f"Error checking vulnerabilities for {package_name}: {e}")
    
    return vulnerabilities

def calculate_health_score(is_outdated: bool, vuln_count: int, is_deprecated: bool) -> int:
    """Calculate health score (0-100)"""
    score = 100
    
    if is_outdated:
        score -= 20
    if vuln_count > 0:
        score -= min(50, vuln_count * 15)
    if is_deprecated:
        score -= 30
    
    return max(0, score)

def get_recommendation(health_score: int, is_outdated: bool, vuln_count: int, is_deprecated: bool) -> str:
    """Get recommendation based on health metrics"""
    if health_score >= 80:
        return "Package is healthy!"
    elif is_deprecated:
        return "Package is deprecated. Consider finding an alternative."
    elif vuln_count > 0:
        return f"Update immediately! {vuln_count} security vulnerability/ies found."
    elif is_outdated:
        return "Update to the latest version when possible."
    else:
        return "Review package health metrics."

# Initialize package checker and A2A handler
package_checker = PackageChecker()
a2a_handler = A2AHandler(package_checker)

# A2A Protocol Endpoint
@app.post("/a2a", response_model=None)
async def a2a_endpoint(request: JSONRPCRequest):
    """
    A2A Protocol endpoint for Telex integration
    
    This endpoint handles JSON-RPC 2.0 requests following the A2A protocol.
    """
    logger.info(f"A2A endpoint called - method: {request.method}")
    response = await a2a_handler.handle_message(request)
    logger.info(f"A2A response generated - bytes: {len(str(response.model_dump()))}")
    return JSONResponse(content=response.model_dump())

# Standard API endpoints (keep for backward compatibility)
@app.get("/")
async def root():
    """Welcome endpoint"""
    return {
        "message": "Package Health Monitor Agent (A2A Protocol)",
        "version": "1.0.0",
        "protocol": "A2A (Agent-to-Agent)",
        "endpoints": {
            "/a2a": "A2A Protocol endpoint (POST - for Telex integration)",
            "/health": "Check API health",
            "/analyze/python": "Analyze Python packages (POST)",
            "/analyze/npm": "Analyze npm packages (POST)"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/analyze/python", response_model=OverallHealthResponse)
async def analyze_python_dependencies(request: PythonDependenciesRequest):
    """Analyze Python dependencies"""
    result = await package_checker.analyze_python(request.packages)
    
    if not result:
        raise HTTPException(status_code=400, detail="No valid packages found")
    
    return OverallHealthResponse(**result)

@app.post("/analyze/npm", response_model=OverallHealthResponse)
async def analyze_npm_dependencies(request: NpmDependenciesRequest):
    """Analyze npm dependencies"""
    all_deps = {**request.dependencies, **(request.devDependencies or {})}
    result = await package_checker.analyze_npm(all_deps)
    
    if not result:
        raise HTTPException(status_code=400, detail="No valid packages found")
    
    return OverallHealthResponse(**result)

@app.post("/check-package", response_model=PackageHealthResponse)
async def check_single_package(package: PackageDependency, ecosystem: str):
    """
    Check a single package health
    
    Args:
        package: PackageDependency with name and version
        ecosystem: "python" or "npm"
    """
    if ecosystem not in ["python", "npm"]:
        raise HTTPException(status_code=400, detail="Ecosystem must be 'python' or 'npm'")
    
    if ecosystem == "python":
        pkg_info = check_pypi_package(package.name, package.version)
    else:
        pkg_info = check_npm_package(package.name, package.version)
    
    vulnerabilities = check_vulnerabilities_osv(package.name, ecosystem)
    
    is_outdated = pkg_info.get('is_outdated', False)
    has_vulns = len(vulnerabilities) > 0
    is_deprecated = pkg_info.get('deprecated', False)
    
    health_score = calculate_health_score(is_outdated, len(vulnerabilities), is_deprecated)
    recommendation = get_recommendation(health_score, is_outdated, len(vulnerabilities), is_deprecated)
    
    return PackageHealthResponse(
        name=package.name,
        current_version=package.version,
        latest_version=pkg_info.get('latest_version'),
        is_outdated=is_outdated,
        has_vulnerabilities=has_vulns,
        vulnerability_count=len(vulnerabilities),
        is_deprecated=is_deprecated,
        health_score=health_score,
        recommendation=recommendation,
        vulnerabilities=vulnerabilities
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

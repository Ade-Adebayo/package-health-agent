from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import requests
import re
from datetime import datetime
import json

app = FastAPI(
    title="Package Version Health Monitor Agent",
    description="An A2A Protocol Agent that monitors package dependencies for security vulnerabilities and outdated versions",
    version="1.0.0"
)

# Models
class PackageDependency(BaseModel):
    name: str
    version: Optional[str] = None

class PythonDependenciesRequest(BaseModel):
    """Request model for Python dependencies - mimics requirements.txt structure"""
    packages: List[str]  # e.g., ["flask==2.0.1", "requests>=2.25.0", "numpy"]

class NpmDependenciesRequest(BaseModel):
    """Request model for npm dependencies - mimics package.json structure"""
    dependencies: Optional[Dict[str, str]] = {}
    devDependencies: Optional[Dict[str, str]] = {}

class PackageHealthResponse(BaseModel):
    name: str
    current_version: Optional[str]
    latest_version: Optional[str]
    is_outdated: bool
    has_vulnerabilities: bool
    vulnerability_count: int
    is_deprecated: bool
    health_score: int
    recommendation: str
    vulnerabilities: List[Dict] = []

class OverallHealthResponse(BaseModel):
    total_packages: int
    outdated_count: int
    vulnerable_count: int
    deprecated_count: int
    overall_health_score: int
    packages: List[PackageHealthResponse]

# Helper Functions
def parse_requirements_txt(content: str) -> List[PackageDependency]:
    """Parse requirements.txt content"""
    packages = []
    lines = content.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Handle various formats: package==1.0.0, package>=1.0.0, package
        match = re.match(r'^([a-zA-Z0-9_-]+)([>=<~!]*)([\d.]*)', line)
        if match:
            name = match.group(1)
            version = match.group(3) if match.group(3) else None
            packages.append(PackageDependency(name=name, version=version))
    
    return packages

def parse_package_json(content: str) -> List[PackageDependency]:
    """Parse package.json content"""
    packages = []
    try:
        data = json.loads(content)
        dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        
        for name, version in dependencies.items():
            # Remove version prefixes like ^, ~, >=
            clean_version = re.sub(r'^[^\d]*', '', version)
            packages.append(PackageDependency(name=name, version=clean_version))
    except json.JSONDecodeError:
        pass
    
    return packages

def check_pypi_package(package_name: str, current_version: Optional[str]) -> Dict:
    """Check Python package on PyPI"""
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            latest_version = data['info']['version']
            
            return {
                'latest_version': latest_version,
                'is_outdated': current_version != latest_version if current_version else False,
                'releases': list(data.get('releases', {}).keys())
            }
    except Exception as e:
        print(f"Error checking PyPI for {package_name}: {e}")
    
    return {'latest_version': None, 'is_outdated': False, 'releases': []}

def check_npm_package(package_name: str, current_version: Optional[str]) -> Dict:
    """Check npm package on npm registry"""
    try:
        response = requests.get(f"https://registry.npmjs.org/{package_name}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            latest_version = data.get('dist-tags', {}).get('latest')
            
            return {
                'latest_version': latest_version,
                'is_outdated': current_version != latest_version if current_version and latest_version else False,
                'deprecated': data.get('deprecated', False)
            }
    except Exception as e:
        print(f"Error checking npm for {package_name}: {e}")
    
    return {'latest_version': None, 'is_outdated': False, 'deprecated': False}

def check_vulnerabilities_osv(package_name: str, ecosystem: str) -> List[Dict]:
    """Check vulnerabilities using OSV (Open Source Vulnerabilities) API"""
    vulnerabilities = []
    
    try:
        # OSV API endpoint
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
        score -= min(vuln_count * 15, 50)  # Max -50 for vulnerabilities
    if is_deprecated:
        score -= 30
    
    return max(score, 0)

def get_recommendation(health_score: int, is_outdated: bool, vuln_count: int, is_deprecated: bool) -> str:
    """Generate recommendation based on package health"""
    if is_deprecated:
        return "⚠️ CRITICAL: Package is deprecated. Find an alternative immediately."
    elif vuln_count > 0:
        return f"🚨 URGENT: {vuln_count} vulnerabilities found. Update immediately."
    elif is_outdated:
        return "⚡ Update recommended to latest version."
    else:
        return "✅ Package is healthy and up-to-date."

# API Endpoints
@app.get("/")
async def root():
    """Welcome endpoint"""
    return {
        "message": "Welcome to Package Version Health Monitor Agent",
        "version": "1.0.0",
        "endpoints": {
            "/health": "Check API health",
            "/analyze/python": "Analyze Python packages (POST with requirements.txt content)",
            "/analyze/npm": "Analyze npm packages (POST with package.json content)",
            "/check-package": "Check a single package (POST)"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/analyze/python", response_model=OverallHealthResponse)
async def analyze_python_dependencies(request: PythonDependenciesRequest):
    """
    Analyze Python dependencies from a list of package strings
    
    Example request body:
    {
        "packages": [
            "flask==2.0.1",
            "requests>=2.25.0",
            "numpy"
        ]
    }
    """
    packages = []
    for pkg_str in request.packages:
        # Parse each package string (e.g., "flask==2.0.1" or "requests>=2.25.0")
        pkg_str = pkg_str.strip()
        if not pkg_str or pkg_str.startswith('#'):
            continue
        
        # Extract package name and version
        for op in ['==', '>=', '<=', '>', '<', '~=']:
            if op in pkg_str:
                name, version = pkg_str.split(op, 1)
                packages.append(PackageDependency(name=name.strip(), version=version.strip()))
                break
        else:
            # No version specified
            packages.append(PackageDependency(name=pkg_str, version=None))
    
    if not packages:
        raise HTTPException(status_code=400, detail="No valid packages found in the provided content")
    
    results = []
    outdated_count = 0
    vulnerable_count = 0
    deprecated_count = 0
    
    for pkg in packages:
        # Check PyPI
        pypi_info = check_pypi_package(pkg.name, pkg.version)
        
        # Check vulnerabilities
        vulnerabilities = check_vulnerabilities_osv(pkg.name, "python")
        
        is_outdated = pypi_info['is_outdated']
        has_vulns = len(vulnerabilities) > 0
        is_deprecated = False  # PyPI doesn't have a clear deprecated flag
        
        health_score = calculate_health_score(is_outdated, len(vulnerabilities), is_deprecated)
        recommendation = get_recommendation(health_score, is_outdated, len(vulnerabilities), is_deprecated)
        
        if is_outdated:
            outdated_count += 1
        if has_vulns:
            vulnerable_count += 1
        if is_deprecated:
            deprecated_count += 1
        
        results.append(PackageHealthResponse(
            name=pkg.name,
            current_version=pkg.version,
            latest_version=pypi_info['latest_version'],
            is_outdated=is_outdated,
            has_vulnerabilities=has_vulns,
            vulnerability_count=len(vulnerabilities),
            is_deprecated=is_deprecated,
            health_score=health_score,
            recommendation=recommendation,
            vulnerabilities=vulnerabilities
        ))
    
    # Calculate overall health score
    overall_score = sum(r.health_score for r in results) // len(results) if results else 0
    
    return OverallHealthResponse(
        total_packages=len(results),
        outdated_count=outdated_count,
        vulnerable_count=vulnerable_count,
        deprecated_count=deprecated_count,
        overall_health_score=overall_score,
        packages=results
    )

@app.post("/analyze/npm", response_model=OverallHealthResponse)
async def analyze_npm_dependencies(request: NpmDependenciesRequest):
    """
    Analyze npm dependencies from package.json structure
    
    Example request body:
    {
        "dependencies": {
            "express": "^4.17.1",
            "axios": "^0.21.1"
        },
        "devDependencies": {
            "jest": "^27.0.0"
        }
    }
    """
    packages = []
    
    # Combine dependencies and devDependencies
    all_deps = {**request.dependencies, **(request.devDependencies or {})}
    
    for name, version in all_deps.items():
        # Clean version (remove ^, ~, etc.)
        clean_version = version.lstrip('^~>=<')
        packages.append(PackageDependency(name=name, version=clean_version))
    
    if not packages:
        raise HTTPException(status_code=400, detail="No valid packages found in the provided content")
    
    results = []
    outdated_count = 0
    vulnerable_count = 0
    deprecated_count = 0
    
    for pkg in packages:
        # Check npm registry
        npm_info = check_npm_package(pkg.name, pkg.version)
        
        # Check vulnerabilities
        vulnerabilities = check_vulnerabilities_osv(pkg.name, "npm")
        
        is_outdated = npm_info['is_outdated']
        has_vulns = len(vulnerabilities) > 0
        is_deprecated = npm_info.get('deprecated', False)
        
        health_score = calculate_health_score(is_outdated, len(vulnerabilities), is_deprecated)
        recommendation = get_recommendation(health_score, is_outdated, len(vulnerabilities), is_deprecated)
        
        if is_outdated:
            outdated_count += 1
        if has_vulns:
            vulnerable_count += 1
        if is_deprecated:
            deprecated_count += 1
        
        results.append(PackageHealthResponse(
            name=pkg.name,
            current_version=pkg.version,
            latest_version=npm_info['latest_version'],
            is_outdated=is_outdated,
            has_vulnerabilities=has_vulns,
            vulnerability_count=len(vulnerabilities),
            is_deprecated=is_deprecated,
            health_score=health_score,
            recommendation=recommendation,
            vulnerabilities=vulnerabilities
        ))
    
    # Calculate overall health score
    overall_score = sum(r.health_score for r in results) // len(results) if results else 0
    
    return OverallHealthResponse(
        total_packages=len(results),
        outdated_count=outdated_count,
        vulnerable_count=vulnerable_count,
        deprecated_count=deprecated_count,
        overall_health_score=overall_score,
        packages=results
    )

@app.post("/check-package")
async def check_single_package(package: PackageDependency, ecosystem: str):
    """
    Check a single package health
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

# Package Version Health Monitor Agent

An A2A (Agent-to-Agent) Protocol AI Agent built with Python and FastAPI that monitors package dependencies for security vulnerabilities, outdated versions, pythonand deprecated packages.

## Features

- ✅ Parse `requirements.txt` (Python) and `package.json` (npm) files
- ✅ Check latest versions from PyPI and npm registries
- ✅ Identify security vulnerabilities using OSV (Open Source Vulnerabilities) database
- ✅ Detect deprecated packages
- ✅ Calculate health scores for each dependency
- ✅ Provide actionable recommendations
- ✅ RESTful API endpoints for easy integration

## Installation

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the server:

```bash
python main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### 1. Root Endpoint

```
GET /
```

Returns API information and available endpoints.

### 2. Health Check

```
GET /health
```

Check if the API is running.

### 3. Analyze Python Dependencies

```
POST /analyze/python
Content-Type: application/json
```

**Request Body:**
```json
{
  "packages": [
    "flask==2.0.1",
    "requests>=2.25.0",
    "numpy==1.19.0"
  ]
}
```

**Example with curl:**
```bash
curl -X POST "http://localhost:8000/analyze/python" \
  -H "Content-Type: application/json" \
  -d '{
    "packages": ["flask==2.0.1", "requests==2.25.0", "numpy==1.19.0"]
  }'
```

**Example with PowerShell:**
```powershell
$body = @{
    packages = @("flask==2.0.1", "requests==2.25.0", "numpy==1.19.0")
} | ConvertTo-Json

Invoke-WebRequest -Uri http://localhost:8000/analyze/python -Method POST -Body $body -ContentType "application/json"
```

### 4. Analyze npm Dependencies

```
POST /analyze/npm
Content-Type: application/json
```

**Request Body:**
```json
{
  "dependencies": {
    "express": "^4.17.1",
    "axios": "^0.21.1"
  },
  "devDependencies": {
    "jest": "^27.0.0"
  }
}
```

**Example with curl:**
```bash
curl -X POST "http://localhost:8000/analyze/npm" \
  -H "Content-Type: application/json" \
  -d '{
    "dependencies": {"express": "^4.17.1", "axios": "^0.21.1"},
    "devDependencies": {"jest": "^27.0.0"}
  }'
```

**Example with PowerShell:**
```powershell
$body = @{
    dependencies = @{
        express = "^4.17.1"
        axios = "^0.21.1"
    }
    devDependencies = @{
        jest = "^27.0.0"
    }
} | ConvertTo-Json

Invoke-WebRequest -Uri http://localhost:8000/analyze/npm -Method POST -Body $body -ContentType "application/json"
```

### 5. Check Single Package

```
POST /check-package?ecosystem=python
Content-Type: application/json

{
  "name": "flask",
  "version": "2.0.1"
}
```

## Response Format

```json
{
  "total_packages": 5,
  "outdated_count": 3,
  "vulnerable_count": 2,
  "deprecated_count": 0,
  "overall_health_score": 65,
  "packages": [
    {
      "name": "flask",
      "current_version": "2.0.1",
      "latest_version": "3.0.0",
      "is_outdated": true,
      "has_vulnerabilities": false,
      "vulnerability_count": 0,
      "is_deprecated": false,
      "health_score": 80,
      "recommendation": "⚡ Update recommended to latest version.",
      "vulnerabilities": []
    }
  ]
}
```

## Health Score Calculation

- **100**: Perfect health - up-to-date, no vulnerabilities
- **80**: Outdated version (-20 points)
- **50-0**: Has vulnerabilities (-15 points per vulnerability, max -50)
- **70**: Deprecated package (-30 points)

## Testing

Sample files are included:

- `sample_requirements.txt` - Python dependencies
- `sample_package.json` - npm dependencies

Test with PowerShell:

```powershell
# Test Python dependencies
$content = Get-Content sample_requirements.txt -Raw
Invoke-WebRequest -Uri http://localhost:8000/analyze/python -Method POST -Body (ConvertTo-Json $content) -ContentType "application/json"

# Test npm dependencies
$content = Get-Content sample_package.json -Raw
Invoke-WebRequest -Uri http://localhost:8000/analyze/npm -Method POST -Body (ConvertTo-Json $content) -ContentType "application/json"
```

## Architecture

- **FastAPI**: Modern, fast web framework for building APIs
- **OSV API**: Open Source Vulnerabilities database for security checks
- **PyPI API**: Python Package Index for version checking
- **npm Registry API**: npm package registry for JavaScript packages

## Use Cases

1. **CI/CD Integration**: Add to your pipeline to block deployments with vulnerable dependencies
2. **Weekly Reports**: Schedule automated dependency health reports
3. **Developer Tools**: Integrate into IDEs or development workflows
4. **Security Audits**: Quick security assessment of project dependencies

## License

MIT License

# Package Health Monitor Agent

An **A2A (Agent-to-Agent) Protocol** AI Agent built with Python and FastAPI that monitors package dependencies for security vulnerabilities, outdated versions, and deprecated packages. Designed for Telex integration with natural language processing capabilities.

## Features

- **A2A Protocol Support** - Native Telex integration with conversational interface
- **Multi-Language Support** - Analyze Python (PyPI) and JavaScript/Node.js (npm) packages
- **Security Scanning** - Check for vulnerabilities using OSV (Open Source Vulnerabilities) database
- **Health Scoring** - Calculate health scores (0-100) for each dependency
- **Smart Recommendations** - Get actionable advice for package updates
- **Natural Language** - Ask questions like "Check flask==2.0.1, requests==2.25.0"
- **RESTful API** - Traditional REST endpoints for direct integration

## Quick Start

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/MyITjournal/package-health-agent.git
cd package-health-agent
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Run the server:**

````bash
# Package Health Monitor Agent

A production-ready **A2A (Agent-to-Agent) Protocol** AI Agent built with Python and FastAPI that monitors package dependencies for security vulnerabilities, outdated versions, and deprecated packages. Features enterprise-grade error handling, strict type validation, and seamless Telex integration.

## Features

- ** Enterprise A2A Protocol** - Full JSON-RPC 2.0 compliance with comprehensive error handling
- ** Strict Type Safety** - Pydantic models with Literal types for protocol enforcement
- ** Multi-Language Support** - Analyze Python (PyPI) and JavaScript/Node.js (npm) packages
- ** Security Scanning** - Real-time vulnerability checking via OSV database
- ** Health Scoring** - Calculate health scores (0-100) with actionable insights
- ** Natural Language** - Conversational interface: "Check my requirements.txt"
- ** File Upload Support** - Direct upload of requirements.txt and package.json
- ** Production Ready** - Deployed on Heroku with proper logging and monitoring
- ** RESTful API** - Traditional REST endpoints for direct integration

## Architecture

### A2A Protocol Implementation

This agent implements the **A2A Protocol** following best practices:

- **Strict Literal Types** - `Literal["text", "data", "file"]` for `kind` validation
- **JSON-RPC 2.0 Compliant** - Full error code support (-32700 to -32603)
- **Manual Request Parsing** - Validates before Pydantic parsing for better error handling
- **ConfigDict(extra='allow')** - Forward compatibility while maintaining strictness
- **Proper Error Responses** - Detailed error messages with request ID tracking

### Technology Stack

- **FastAPI 0.115.5** - Modern async web framework
- **Pydantic 2.10.3** - Data validation with strict typing
- **Uvicorn 0.32.1** - ASGI server for production
- **Requests 2.32.3** - HTTP client for external APIs
- **Python 3.13** - Latest Python with improved performance

## Quick Start

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/MyITjournal/package-health-agent.git
cd package-health-agent
````

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Run the server:**

```bash
python main_a2a.py
```

Or using uvicorn:

```bash
uvicorn main_a2a:app --reload --host 0.0.0.0 --port 8000
```

4. **Access the API:**

- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health
- **A2A Endpoint:** http://localhost:8000/a2a

## Live Deployment

**Production URL:** `https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/`

**Interactive Docs:** `https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/docs`

**Status:** Active (v13+)

## API Endpoints

### 1. A2A Protocol Endpoint (Primary)

```
POST /a2a
Content-Type: application/json
```

**Enterprise-grade A2A endpoint with full JSON-RPC 2.0 support**

#### Supported Methods:

- `message/send` - Single message interaction
- `execute` - Multi-message conversation with context

#### Error Codes:

- `-32700` - Parse error (Invalid JSON)
- `-32600` - Invalid Request (Missing jsonrpc or id)
- `-32601` - Method not found
- `-32602` - Invalid params (Pydantic validation failed)
- `-32603` - Internal error

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [
        {
          "kind": "text",
          "text": "Check flask==2.0.1, requests==2.25.0"
        }
      ]
    },
    "configuration": {
      "blocking": true
    }
  }
}
```

**File Upload Support:**

```json
{
  "jsonrpc": "2.0",
  "id": "req-456",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [
        {
          "kind": "file",
          "data": "<base64-encoded-requirements.txt>"
        }
      ]
    }
  }
}
```

**Natural Language Commands:**

- "help" - Show available commands
- "Check flask==2.0.1, requests>=2.25.0" - Analyze Python packages
- "Analyze npm: express@4.17.1, axios@0.21.1" - Analyze npm packages
- Upload requirements.txt or package.json directly

### 2. Root Endpoint

```
GET /
```

Returns API information, version, and available endpoints.

### 3. Health Check

```
GET /health
```

Check if the API is running.

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-11-03T14:30:00.000000"
}
```

### 4. Analyze Python Dependencies

```
POST /analyze/python
Content-Type: application/json
```

**Request Body:**

```json
{
  "packages": ["flask==2.0.1", "requests>=2.25.0", "numpy==1.19.0"]
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

### 5. Analyze npm Dependencies

```
POST /analyze/npm
Content-Type: application/json
```

````

Or using uvicorn:

```bash
uvicorn main_a2a:app --reload --host 0.0.0.0 --port 8000
````

4. **Access the API:**

- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health
- **A2A Endpoint:** http://localhost:8000/a2a

## Live Deployment

**Production URL:** `https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/`

**Interactive Docs:** `https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/docs`

## API Endpoints

### 1. A2A Protocol Endpoint (Telex Integration)

```
POST /a2a
Content-Type: application/json
```

**For Telex/A2A clients** - Supports conversational package health checks.

**Example Request:**

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [
        {
          "kind": "text",
          "text": "Check flask==2.0.1, requests==2.25.0"
        }
      ]
    }
  }
}
```

**Natural Language Commands:**

- "help" - Show available commands
- "Check flask==2.0.1, requests>=2.25.0" - Analyze Python packages
- "Analyze npm: express@4.17.1, axios@0.21.1" - Analyze npm packages

### 2. Root Endpoint

```
GET /
```

Returns API information, version, and available endpoints.

### 3. Health Check

```
GET /health
```

Check if the API is running.

### 4. Analyze Python Dependencies

```
POST /analyze/python
Content-Type: application/json
```

**Request Body:**

```json
{
  "packages": ["flask==2.0.1", "requests>=2.25.0", "numpy==1.19.0"]
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

### 5. Analyze npm Dependencies

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

### 6. Check Single Package

```
POST /check-package?ecosystem=python
Content-Type: application/json

{
  "name": "flask",
  "version": "2.0.1"
}
```

## Response Format

**Successful Analysis:**

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
      "recommendation": " Update recommended to latest version.",
      "vulnerabilities": []
    }
  ]
}
```

## Health Score Calculation

The health score ranges from **0-100** based on these factors:

- **100**: Perfect health - up-to-date, no vulnerabilities
- **80**: Outdated version (-20 points)
- **50-0**: Has vulnerabilities (-15 points per vulnerability, max -50)
- **70**: Deprecated package (-30 points)

## Testing

Sample test files are included in the repository:

- `sample_requirements.txt` - Example Python dependencies
- `sample_package.json` - Example npm dependencies
- `test_a2a.py` - A2A protocol test script

**Run A2A Tests:**

```bash
python test_a2a.py
```

**Test with PowerShell:**

```powershell
# Test Python package analysis
$body = @{
    packages = @("flask==2.0.1", "requests==2.25.0", "numpy==1.19.0")
} | ConvertTo-Json

Invoke-WebRequest -Uri http://localhost:8000/analyze/python -Method POST -Body $body -ContentType "application/json"

# Test npm package analysis
$body = @{
    dependencies = @{
        express = "^4.17.1"
        axios = "^0.21.1"
    }
} | ConvertTo-Json

Invoke-WebRequest -Uri http://localhost:8000/analyze/npm -Method POST -Body $body -ContentType "application/json"
```

## Architecture

**Tech Stack:**

- **FastAPI** - Modern, fast web framework for building APIs
- **Pydantic** - Data validation using Python type annotations
- **A2A Protocol** - Agent-to-Agent communication standard
- **OSV API** - Open Source Vulnerabilities database for security checks
- **PyPI API** - Python Package Index for version checking
- **npm Registry API** - npm package registry for JavaScript packages

**Project Structure:**

```
package-health-agent/
├── main_a2a.py           # Main FastAPI application with A2A support
├── a2a_handler.py        # A2A protocol message handler
├── models/
│   ├── __init__.py
│   ├── a2a.py           # A2A protocol models
│   └── schemas.py       # API request/response models
├── test_a2a.py          # A2A endpoint tests
├── pyproject.toml       # Project metadata and dependencies
├── requirements.txt     # Dependencies (for Heroku)
├── Procfile            # Heroku deployment config
└── README.md           # This file
```

## Use Cases

1. **Telex Integration** - Use as a conversational agent in Telex workspace
2. **CI/CD Integration** - Add to your pipeline to block deployments with vulnerable dependencies
3. **Weekly Reports** - Schedule automated dependency health reports
4. **Developer Tools** - Integrate into IDEs or development workflows
5. **Security Audits** - Quick security assessment of project dependencies

## Deployment

### Deploy to Heroku

1. **Create Heroku app:**

```bash
heroku create your-app-name
```

2. **Set Python version:**

```bash
echo "3.13" > .python-version
```

3. **Deploy:**

```bash
git push heroku main
```

4. **Verify:**

```bash
heroku logs --tail
```

### Environment Variables

No environment variables required for basic operation. All APIs used are public and free.

## Telex Integration

To register this agent on Telex, use this configuration:

```json
{
  "name": "Package Health Monitor",
  "description": "Monitors package dependencies for security and health issues",
  "url": "https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/a2a",
  "protocol": "A2A",
  "version": "1.0.0"
}
```

**Example Telex Commands:**

- "help" - Show what the agent can do
- "Check flask==2.0.1, requests==2.25.0" - Analyze Python packages
- "Analyze npm: express@4.17.1" - Check npm packages

## Recent Improvements

### v13+ (Latest)

- ** Enterprise A2A Protocol Implementation**
  - Strict Literal types for protocol enforcement (`kind`, `role`, `method`, `state`)
  - Manual Request parsing before Pydantic validation (prevents 422 errors)
  - Full JSON-RPC 2.0 compliance with error codes (-32700 to -32603)
  - Forward compatibility via `ConfigDict(extra='allow')`
- ** Code Quality Enhancements**

  - Replaced all `print()` statements with proper `logger` usage
  - Moved imports to module top level for better organization
  - Improved exception handling with detailed error logging
  - Added comprehensive error context for debugging

- ** Repository Cleanup**

  - Created professional `.gitignore` for Python/FastAPI projects
  - Removed `__pycache__` directories from git tracking
  - Eliminated code redundancies and inline imports
  - Clean git history with meaningful commits

- ** Documentation**
  - Enhanced README with Architecture section
  - Added detailed JSON-RPC 2.0 error code documentation
  - File upload support documentation
  - Technology stack and features overview

### Architecture Highlights

- **Pattern**: Follows chess agent A2A implementation best practices
- **Type Safety**: Strict Literal types catch protocol violations early
- **Error Handling**: Comprehensive JSON-RPC 2.0 error codes for debugging
- **Flexibility**: `extra='allow'` enables future protocol extensions without breaking changes
- **Logging**: Production-grade logging at INFO/ERROR/EXCEPTION levels

## License

MIT License

## Author

**Adeyoola Adebayo**  
GitHub: [@MyITjournal](https://github.com/MyITjournal)

## Acknowledgments

- FastAPI for the excellent web framework
- OSV for the vulnerabilities database
- Telex for A2A protocol specification
- Chess agent implementation for A2A protocol best practices

---

**Live API:** https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/  
**Documentation:** https://packagehealthmonitoragent-2367cacc569a.herokuapp.com/docs

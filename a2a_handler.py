from models.a2a import (
    A2AMessage, MessagePart, TaskResult, TaskStatus, 
    Artifact, JSONRPCRequest, JSONRPCResponse
)
from typing import List, Dict, Any
from uuid import uuid4
import json
import re
import logging

logger = logging.getLogger(__name__)

class A2AHandler:
    """Handler for A2A protocol messages"""
    
    def __init__(self, package_checker):
        """
        Initialize A2A handler with package checking functions
        
        Args:
            package_checker: Object with methods to check packages
        """
        self.package_checker = package_checker
        self.conversation_history: Dict[str, List[A2AMessage]] = {}
    
    async def handle_message(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """
        Handle incoming A2A message request
        
        Args:
            request: JSONRPCRequest object
            
        Returns:
            JSONRPCResponse object
        """
        try:
            logger.info(f"A2A request - method: {request.method}, id: {request.id}")
            if hasattr(request, 'params'):
                logger.info(f"Request params type: {type(request.params)}")
            
            if request.method == "message/send":
                return await self._handle_message_send(request)
            elif request.method == "execute":
                return await self._handle_execute(request)
            else:
                logger.warning(f"Unknown method: {request.method}")
                return self._error_response(
                    request.id,
                    -32601,
                    f"Method not found: {request.method}"
                )
        except AttributeError as e:
            return self._error_response(
                getattr(request, 'id', 'unknown'),
                -32602,
                f"Invalid params: {str(e)}"
            )
        except Exception as e:
            return self._error_response(
                getattr(request, 'id', 'unknown'),
                -32603,
                f"Internal error: {str(e)}"
            )
    
    async def _handle_message_send(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Handle message/send method"""
        # Parse params if it's a dict
        if isinstance(request.params, dict):
            from models.a2a import MessageParams
            params = MessageParams(**request.params)
        else:
            params = request.params
            
        user_message = params.message
        
        # Extract user's text from message parts
        user_text = self._extract_text_from_message(user_message)
        logger.info(f"Received message with {len(user_message.parts)} parts")
        logger.info(f"Extracted text (first 200 chars): {user_text[:200]}")
        
        # Store in conversation history
        context_id = user_message.taskId or str(uuid4())
        if context_id not in self.conversation_history:
            self.conversation_history[context_id] = []
        self.conversation_history[context_id].append(user_message)
        
        # Process the message and generate response
        response_text, artifacts = await self._process_user_message(user_text)
        logger.info(f"Generated response (first 200 chars): {response_text[:200]}")
        
        # Create agent response message
        agent_message = A2AMessage(
            role="agent",
            parts=[MessagePart(kind="text", text=response_text)],
            taskId=context_id
        )
        
        self.conversation_history[context_id].append(agent_message)
        
        # Create task result
        task_result = TaskResult(
            id=user_message.taskId or str(uuid4()),
            contextId=context_id,
            status=TaskStatus(
                state="completed",
                message=agent_message
            ),
            artifacts=artifacts,
            history=self.conversation_history[context_id]
        )
        
        return JSONRPCResponse(
            id=request.id,
            result=task_result
        )
    
    async def _handle_execute(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Handle execute method"""
        # Parse params if it's a dict
        if isinstance(request.params, dict):
            from models.a2a import ExecuteParams
            params = ExecuteParams(**request.params)
        else:
            params = request.params
            
        context_id = params.contextId or str(uuid4())
        
        # Store messages in history
        if context_id not in self.conversation_history:
            self.conversation_history[context_id] = []
        
        self.conversation_history[context_id].extend(params.messages)
        
        # Get the last user message
        user_messages = [msg for msg in params.messages if msg.role == "user"]
        if not user_messages:
            return self._error_response(
                request.id,
                -32602,
                "No user message found in execute request"
            )
        
        user_text = self._extract_text_from_message(user_messages[-1])
        
        # Process the message
        response_text, artifacts = await self._process_user_message(user_text)
        
        # Create agent response
        agent_message = A2AMessage(
            role="agent",
            parts=[MessagePart(kind="text", text=response_text)],
            taskId=params.taskId
        )
        
        self.conversation_history[context_id].append(agent_message)
        
        task_result = TaskResult(
            id=params.taskId or str(uuid4()),
            contextId=context_id,
            status=TaskStatus(
                state="completed",
                message=agent_message
            ),
            artifacts=artifacts,
            history=self.conversation_history[context_id]
        )
        
        return JSONRPCResponse(
            id=request.id,
            result=task_result
        )
    
    async def _process_user_message(self, user_text: str) -> tuple[str, List[Artifact]]:
        """
        Process user message and generate response
        
        Args:
            user_text: User's message text
            
        Returns:
            Tuple of (response_text, artifacts)
        """
        user_text_lower = user_text.lower()
        
        # Check if user is asking for help
        if any(word in user_text_lower for word in ["help", "what can you do", "commands"]):
            return self._get_help_message(), []
        
        # Check if user wants to analyze Python packages
        if "python" in user_text_lower or "pip" in user_text_lower or "requirements" in user_text_lower:
            packages = self._extract_python_packages(user_text)
            if packages:
                result = await self.package_checker.analyze_python(packages)
                return self._format_analysis_result(result, "Python"), [self._create_artifact(result)]
            else:
                return "Please provide Python packages to analyze. Example: `flask==2.0.1, requests>=2.25.0`", []
        
        # Check if user wants to analyze npm packages
        if "npm" in user_text_lower or "node" in user_text_lower or "javascript" in user_text_lower:
            packages = self._extract_npm_packages(user_text)
            if packages:
                result = await self.package_checker.analyze_npm(packages)
                return self._format_analysis_result(result, "npm"), [self._create_artifact(result)]
            else:
                return "Please provide npm packages to analyze. Example: `express@4.17.1, axios@0.21.1`", []
        
        # Default response - try to extract packages from text
        python_packages = self._extract_python_packages(user_text)
        npm_packages = self._extract_npm_packages(user_text)
        
        if python_packages:
            result = await self.package_checker.analyze_python(python_packages)
            return self._format_analysis_result(result, "Python"), [self._create_artifact(result)]
        elif npm_packages:
            result = await self.package_checker.analyze_npm(npm_packages)
            return self._format_analysis_result(result, "npm"), [self._create_artifact(result)]
        else:
            return self._get_help_message(), []
    
    def _extract_text_from_message(self, message: A2AMessage) -> str:
        """Extract text content and file data from message parts"""
        content_parts = []
        
        for part in message.parts:
            if part.kind == "text" and part.text:
                content_parts.append(part.text)
            elif part.kind == "file" and hasattr(part, 'data') and part.data:
                # Handle file upload - decode base64 or direct text
                try:
                    import base64
                    # Try to decode as base64
                    file_content = base64.b64decode(part.data).decode('utf-8')
                    content_parts.append(file_content)
                except:
                    # If not base64, treat as plain text
                    content_parts.append(str(part.data))
            elif part.kind == "data" and hasattr(part, 'data') and part.data:
                # Handle data parts
                if isinstance(part.data, str):
                    content_parts.append(part.data)
                elif isinstance(part.data, dict):
                    content_parts.append(json.dumps(part.data))
        
        return " ".join(content_parts)
    
    def _extract_python_packages(self, text: str) -> List[str]:
        """Extract Python package specifications from text"""
        packages = []
        
        # Pattern for packages like: flask==2.0.1, requests>=2.25.0
        pattern = r'\b([a-zA-Z0-9_-]+)\s*([=<>~!]+)\s*([0-9.]+)\b'
        matches = re.findall(pattern, text)
        
        for match in matches:
            pkg_name, operator, version = match
            packages.append(f"{pkg_name}{operator}{version}")
        
        # Also look for simple package names
        words = text.split()
        for word in words:
            word = word.strip(',')
            # Check if it looks like a package (contains == or >= etc)
            if any(op in word for op in ['==', '>=', '<=', '>', '<', '~=']):
                if word not in packages:
                    packages.append(word)
        
        return packages
    
    def _extract_npm_packages(self, text: str) -> Dict[str, str]:
        """Extract npm package specifications from text"""
        dependencies = {}
        
        # Pattern for packages like: express@4.17.1, axios@0.21.1
        pattern = r'\b([a-zA-Z0-9_-]+)@([0-9.^~]+)\b'
        matches = re.findall(pattern, text)
        
        for match in matches:
            pkg_name, version = match
            dependencies[pkg_name] = version
        
        return dependencies
    
    def _format_analysis_result(self, result: Dict[str, Any], ecosystem: str) -> str:
        """Format package analysis result as readable text"""
        if not result:
            return f"No {ecosystem} packages were analyzed."
        
        total = result.get("total_packages", 0)
        outdated = result.get("outdated_count", 0)
        vulnerable = result.get("vulnerable_count", 0)
        score = result.get("overall_health_score", 0)
        
        # Create health emoji
        if score >= 80:
            health_emoji = "✅"
        elif score >= 60:
            health_emoji = "⚠️"
        else:
            health_emoji = "❌"
        
        response = f"## {ecosystem} Package Health Report {health_emoji}\n\n"
        response += f"**Overall Health Score:** {score}/100\n"
        response += f"**Total Packages:** {total}\n"
        response += f"**Outdated:** {outdated}\n"
        response += f"**With Vulnerabilities:** {vulnerable}\n\n"
        
        # Add details for each package
        packages = result.get("packages", [])
        if packages:
            response += "### Package Details:\n\n"
            for pkg in packages:
                name = pkg.get("name", "unknown")
                current = pkg.get("current_version", "N/A")
                latest = pkg.get("latest_version", "N/A")
                pkg_score = pkg.get("health_score", 0)
                vuln_count = pkg.get("vulnerability_count", 0)
                
                if pkg_score >= 80:
                    status = "✅"
                elif pkg_score >= 60:
                    status = "⚠️"
                else:
                    status = "❌"
                
                response += f"{status} **{name}** ({current})\n"
                response += f"   - Latest: {latest}\n"
                response += f"   - Health: {pkg_score}/100\n"
                
                if vuln_count > 0:
                    response += f"   - ⚠️ {vuln_count} vulnerability/ies found\n"
                
                recommendation = pkg.get("recommendation", "")
                if recommendation:
                    response += f"   - 💡 {recommendation}\n"
                
                response += "\n"
        
        return response
    
    def _create_artifact(self, data: Dict[str, Any]) -> Artifact:
        """Create an artifact from analysis data"""
        return Artifact(
            name="package-health-report.json",
            parts=[MessagePart(kind="data", data=data)]
        )
    
    def _get_help_message(self) -> str:
        """Return help message"""
        return """
## Package Health Monitor Agent 📦

I can help you check the health of your Python and npm packages!

### Commands:

**Analyze Python packages:**
- "Check flask==2.0.1, requests>=2.25.0"
- "Analyze Python packages: numpy==1.19.0, pandas"

**Analyze npm packages:**
- "Check express@4.17.1, axios@0.21.1"
- "Analyze npm packages: react@17.0.0, lodash@4.17.20"

I'll check for:
✅ Outdated versions
✅ Security vulnerabilities (CVEs)
✅ Deprecated packages
✅ Overall health score

Just send me a list of packages and I'll analyze them for you!
"""
    
    def _error_response(self, request_id: str, code: int, message: str) -> JSONRPCResponse:
        """Create an error response"""
        return JSONRPCResponse(
            id=request_id,
            error={
                "code": code,
                "message": message
            }
        )

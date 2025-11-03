from pydantic import BaseModel, Field, ConfigDict
from typing import Literal, Optional, List, Dict, Any, Union
from datetime import datetime
from uuid import uuid4

class MessagePart(BaseModel):
    """A2A Protocol message part - can be text, data, or file"""
    model_config = ConfigDict(extra='allow')
    
    kind: Literal["text", "data", "file"]
    text: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    file_url: Optional[str] = None

class A2AMessage(BaseModel):
    """A2A Protocol message"""
    model_config = ConfigDict(extra='allow')
    
    kind: Literal["message"] = "message"
    role: Literal["user", "agent", "system"]
    parts: List[MessagePart]
    messageId: Optional[str] = Field(default_factory=lambda: str(uuid4()))
    taskId: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class PushNotificationConfig(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    url: str
    token: Optional[str] = None
    authentication: Optional[Dict[str, Any]] = None

class MessageConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    blocking: bool = True
    acceptedOutputModes: Optional[List[str]] = ["text/plain", "image/png", "image/svg+xml"]
    pushNotificationConfig: Optional[PushNotificationConfig] = None

class MessageParams(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    message: A2AMessage
    configuration: Optional[MessageConfiguration] = Field(default_factory=MessageConfiguration)

class ExecuteParams(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    contextId: Optional[str] = None
    taskId: Optional[str] = None
    messages: List[A2AMessage]

class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 Request for A2A Protocol"""
    model_config = ConfigDict(extra='allow')
    
    jsonrpc: Literal["2.0"] = "2.0"
    id: str
    method: Literal["message/send", "execute"]
    params: Union[MessageParams, ExecuteParams]

class TaskStatus(BaseModel):
    """Task status in A2A Protocol"""
    model_config = ConfigDict(extra='allow')
    
    state: Literal["working", "completed", "input-required", "failed"]
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    message: Optional[A2AMessage] = None

class Artifact(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    artifactId: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    parts: List[MessagePart]

class TaskResult(BaseModel):
    """Task result in A2A Protocol"""
    model_config = ConfigDict(extra='allow')
    
    id: str
    contextId: str
    status: TaskStatus
    artifacts: List[Artifact] = []
    history: List[A2AMessage] = []
    kind: Literal["task"] = "task"

class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 Response"""
    model_config = ConfigDict(extra='allow')
    
    jsonrpc: Literal["2.0"] = "2.0"
    id: str
    result: Optional[TaskResult] = None
    error: Optional[Dict[str, Any]] = None

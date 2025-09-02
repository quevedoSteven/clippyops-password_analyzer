from dataclasses import dataclass
from typing import Dict, Optional
import json

@dataclass
class BreachResult:
    breached: bool
    count: int
    error: Optional[str]
    hash_prefix: Optional[str]
    timestamp: Optional[float] = None
    cache_hit: bool = False
    risk_assessment: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return {
            'breached': self.breached,
            'count': self.count,
            'error': self.error,
            'hash_prefix': self.hash_prefix,
            'timestamp': self.timestamp,
            'cache_hit': self.cache_hit,
            'risk_assessment': self.risk_assessment
        }
    
    @classmethod
    def from_dict(cls, data: Dict):
        return cls(**data)
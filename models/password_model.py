from dataclasses import dataclass
from typing import Dict, List, Optional
import json

@dataclass
class PasswordAnalysis:
    password: str
    length: int
    score: int
    strength_level: str
    entropy: float
    character_sets: Dict[str, int]
    patterns: List[str]
    common_password: bool
    recommendations: List[str]
    zxcvbn_score: Optional[int] = None
    zxcvbn_feedback: Optional[Dict] = None
    zxcvbn_guesses: Optional[int] = None
    analysis_time: Optional[float] = None
    risk_level: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'password': self.password,
            'length': self.length,
            'score': self.score,
            'strength_level': self.strength_level,
            'entropy': self.entropy,
            'character_sets': self.character_sets,
            'patterns': self.patterns,
            'common_password': self.common_password,
            'recommendations': self.recommendations,
            'zxcvbn_score': self.zxcvbn_score,
            'zxcvbn_feedback': self.zxcvbn_feedback,
            'zxcvbn_guesses': self.zxcvbn_guesses,
            'analysis_time': self.analysis_time,
            'risk_level': self.risk_level
        }
    
    @classmethod
    def from_dict(cls, data: Dict):
        return cls(**data)
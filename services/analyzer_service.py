import re
import math
import time
from typing import Dict, List
from models.password_model import PasswordAnalysis
from utils.security_utils import SecurityUtils

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

class PasswordAnalyzerService:
    def __init__(self):
        self.common_patterns = [
            r'(.)\1{2,}',
            r'(012|123|234|345|456|567|678|789|890)',
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            r'(qwert|asdfg|zxcvb)',
        ]
        
        self.weak_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'qwerty123', '111111', 'password1', 'qwertyuiop'
        }
        
        self.security_utils = SecurityUtils()
    
    def analyze_password(self, password: str) -> PasswordAnalysis:
        start_time = time.time()
        
        if not password:
            return self._create_empty_analysis()
        
        analysis_data = {
            'password': password,
            'length': len(password),
            'character_sets': self._analyze_character_sets(password),
            'patterns': self._detect_patterns(password),
            'entropy': self._calculate_entropy(password),
            'common_password': password.lower() in self.weak_passwords,
            'recommendations': []
        }
        
        if ZXCVBN_AVAILABLE:
            try:
                zxcvbn_result = zxcvbn(password)
                analysis_data['zxcvbn_score'] = zxcvbn_result['score']
                analysis_data['zxcvbn_feedback'] = zxcvbn_result['feedback']
                analysis_data['zxcvbn_guesses'] = zxcvbn_result['guesses']
            except Exception:
                pass
        
        score = self._calculate_base_score(analysis_data)
        score = self._apply_pattern_penalties(analysis_data, score)
        
        if analysis_data['common_password']:
            score = max(0, score - 30)
            analysis_data['recommendations'].append("CRITICAL: Commonly compromised password detected")
        
        analysis_data['recommendations'].extend(self._generate_recommendations(analysis_data))
        analysis_data['score'] = max(0, min(100, score))
        analysis_data['strength_level'] = self._get_strength_level(analysis_data['score'])
        analysis_data['risk_level'] = self._assess_risk_level(analysis_data)
        analysis_data['analysis_time'] = round(time.time() - start_time, 3)
        
        return PasswordAnalysis(**analysis_data)
    
    def _create_empty_analysis(self) -> PasswordAnalysis:
        return PasswordAnalysis(
            password='',
            length=0,
            score=0,
            strength_level='CRITICAL',
            entropy=0,
            character_sets={'lowercase': 0, 'uppercase': 0, 'digits': 0, 'special': 0},
            patterns=[],
            common_password=False,
            recommendations=['NO PASSWORD PROVIDED'],
            risk_level='CRITICAL',
            analysis_time=0.0
        )
    
    def _analyze_character_sets(self, password: str) -> Dict[str, int]:
        return {
            'lowercase': len(re.findall(r'[a-z]', password)),
            'uppercase': len(re.findall(r'[A-Z]', password)),
            'digits': len(re.findall(r'[0-9]', password)),
            'special': len(re.findall(r'[^a-zA-Z0-9]', password))
        }
    
    def _detect_patterns(self, password: str) -> List[str]:
        patterns_found = []
        
        if re.search(r'(.)\1{2,}', password):
            patterns_found.append("REPETITIVE_CHARACTERS")
        
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password.lower()):
            patterns_found.append("SEQUENTIAL_NUMBERS")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            patterns_found.append("SEQUENTIAL_LETTERS")
        
        if re.search(r'(qwert|asdfg|zxcvb)', password.lower()):
            patterns_found.append("KEYBOARD_PATTERNS")
        
        return patterns_found
    
    def _calculate_entropy(self, password: str) -> float:
        if not password:
            return 0
        
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
            return round(entropy, 2)
        return 0
    
    def _calculate_base_score(self, analysis: Dict) -> int:
        score = 0
        char_sets = analysis['character_sets']
        
        length = analysis['length']
        if length >= 16:
            score += 45
        elif length >= 12:
            score += 40
        elif length >= 8:
            score += 30
        elif length >= 6:
            score += 20
        elif length >= 4:
            score += 10
        else:
            score += 5
        
        diversity_score = 0
        if char_sets['lowercase'] > 0:
            diversity_score += 10
        if char_sets['uppercase'] > 0:
            diversity_score += 10
        if char_sets['digits'] > 0:
            diversity_score += 10
        if char_sets['special'] > 0:
            diversity_score += 10
        
        score += diversity_score
        
        entropy = analysis['entropy']
        if entropy >= 70:
            score += 25
        elif entropy >= 60:
            score += 20
        elif entropy >= 50:
            score += 15
        elif entropy >= 40:
            score += 10
        elif entropy >= 30:
            score += 5
        
        return score
    
    def _apply_pattern_penalties(self, analysis: Dict, score: int) -> int:
        patterns = analysis['patterns']
        penalty = len(patterns) * 8
        return max(0, score - penalty)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        recommendations = []
        
        if analysis['length'] < 12:
            recommendations.append("ENHANCE: Minimum 12 characters required")
        
        char_sets = analysis['character_sets']
        if char_sets['uppercase'] == 0:
            recommendations.append("ENHANCE: Include uppercase letters")
        if char_sets['digits'] == 0:
            recommendations.append("ENHANCE: Include numeric characters")
        if char_sets['special'] == 0:
            recommendations.append("ENHANCE: Include special characters")
        
        if analysis['patterns']:
            recommendations.append("CRITICAL: Eliminate predictable patterns")
        
        if analysis['entropy'] < 45:
            recommendations.append("ENHANCE: Increase password randomness")
        
        if not recommendations and analysis['score'] >= 85:
            recommendations.append("SECURE: Password meets military-grade standards")
        
        return recommendations
    
    def _get_strength_level(self, score: int) -> str:
        if score >= 90:
            return "CLASSIFIED"
        elif score >= 75:
            return "RESTRICTED"
        elif score >= 60:
            return "CONFIDENTIAL"
        elif score >= 40:
            return "UNCLASSIFIED"
        elif score >= 20:
            return "COMPROMISED"
        else:
            return "CRITICAL"
    
    def _assess_risk_level(self, analysis: Dict) -> str:
        if analysis['common_password'] or analysis['score'] < 20:
            return "HIGH"
        elif analysis['score'] < 40:
            return "MEDIUM"
        elif analysis['score'] < 70:
            return "LOW"
        else:
            return "MINIMAL"
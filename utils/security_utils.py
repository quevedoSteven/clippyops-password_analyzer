import re
import secrets
import string
from typing import List, Dict

class SecurityUtils:
    def __init__(self):
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def generate_secure_password(self, length: int = 16) -> str:
        if length < 12:
            length = 12
        
        alphabet = string.ascii_letters + string.digits + self.special_chars
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    def validate_password_strength(self, password: str) -> Dict[str, bool]:
        return {
            'length_ok': len(password) >= 12,
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'no_common_patterns': not self._has_common_patterns(password)
        }
    
    def _has_common_patterns(self, password: str) -> bool:
        patterns = [
            r'(.)\1{2,}',
            r'(012|123|234|345|456|567|678|789|890)',
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            r'(qwert|asdfg|zxcvb)'
        ]
        
        for pattern in patterns:
            if re.search(pattern, password.lower()):
                return True
        return False
    
    def sanitize_input(self, input_str: str) -> str:
        if not input_str:
            return ""
        return input_str.strip()[:128]
    
    def calculate_password_complexity(self, password: str) -> float:
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size > 0 and len(password) > 0:
            return len(password) * charset_size
        return 0
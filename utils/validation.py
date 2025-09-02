import re
from typing import Tuple, Optional

class InputValidator:
    @staticmethod
    def validate_password_input(password: str) -> Tuple[bool, Optional[str]]:
        if not password:
            return False, "PASSWORD_REQUIRED"
        
        if len(password) > 128:
            return False, "PASSWORD_TOO_LONG"
        
        if len(password) < 4:
            return False, "PASSWORD_TOO_SHORT"
        
        return True, None
    
    @staticmethod
    def validate_analysis_request(data: dict) -> Tuple[bool, Optional[str]]:
        if not isinstance(data, dict):
            return False, "INVALID_REQUEST_FORMAT"
        
        password = data.get('password')
        if not password:
            return False, "PASSWORD_REQUIRED"
        
        return InputValidator.validate_password_input(password)
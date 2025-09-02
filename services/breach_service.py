import requests
import hashlib
import time
import json
import os
from typing import Dict, Optional
from models.breach_model import BreachResult
from config import Config

class BreachCheckerService:
    def __init__(self):
        self.api_url = Config.BREACH_API_URL
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MilitaryPasswordAnalyzer/2.0',
            'Accept': 'text/plain'
        })
        self.cache_file = 'data/breach_cache.json'
        self._ensure_cache_directory()
    
    def _ensure_cache_directory(self):
        os.makedirs('data', exist_ok=True)
        if not os.path.exists(self.cache_file):
            with open(self.cache_file, 'w') as f:
                json.dump({}, f)
    
    def check_password_breach(self, password: str) -> BreachResult:
        if not password:
            return BreachResult(
                breached=False,
                count=0,
                error=None,
                hash_prefix=None,
                timestamp=time.time(),
                cache_hit=False
            )
        
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            cached_result = self._check_cache(prefix, suffix)
            if cached_result:
                return BreachResult(
                    breached=cached_result['breached'],
                    count=cached_result['count'],
                    error=None,
                    hash_prefix=prefix,
                    timestamp=time.time(),
                    cache_hit=True,
                    risk_assessment=cached_result.get('risk_assessment')
                )
            
            time.sleep(Config.API_RATE_LIMIT)
            
            breach_count = self._query_breach_api(prefix, suffix)
            risk_assessment = self._assess_breach_risk(breach_count)
            
            result = {
                'breached': breach_count > 0,
                'count': breach_count,
                'hash_prefix': prefix,
                'timestamp': time.time(),
                'risk_assessment': risk_assessment
            }
            
            self._update_cache(prefix, suffix, result)
            
            return BreachResult(
                breached=result['breached'],
                count=result['count'],
                error=None,
                hash_prefix=result['hash_prefix'],
                timestamp=result['timestamp'],
                cache_hit=False,
                risk_assessment=result['risk_assessment']
            )
            
        except Exception as e:
            return BreachResult(
                breached=False,
                count=0,
                error=str(e),
                hash_prefix=None,
                timestamp=time.time(),
                cache_hit=False
            )
    
    def _check_cache(self, prefix: str, suffix: str) -> Optional[Dict]:
        try:
            with open(self.cache_file, 'r') as f:
                cache = json.load(f)
            
            cache_key = f"{prefix}:{suffix}"
            if cache_key in cache:
                cached_data = cache[cache_key]
                if time.time() - cached_data.get('timestamp', 0) < Config.CACHE_TIMEOUT:
                    return cached_data
                else:
                    del cache[cache_key]
                    with open(self.cache_file, 'w') as f:
                        json.dump(cache, f)
        except Exception:
            pass
        return None
    
    def _update_cache(self, prefix: str, suffix: str, result: Dict):
        try:
            with open(self.cache_file, 'r') as f:
                cache = json.load(f)
            
            cache_key = f"{prefix}:{suffix}"
            cache[cache_key] = result
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache, f)
        except Exception:
            pass
    
    def _query_breach_api(self, prefix: str, suffix: str) -> int:
        try:
            response = self.session.get(f"{self.api_url}{prefix}")
            
            if response.status_code == 200:
                for line in response.text.splitlines():
                    hash_part, count = line.split(':')
                    if hash_part == suffix:
                        return int(count)
                return 0
            elif response.status_code == 404:
                return 0
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException:
            raise Exception("API communication failure")
        except ValueError:
            raise Exception("API response parsing error")
    
    def _assess_breach_risk(self, breach_count: int) -> Dict:
        if breach_count >= 1000:
            risk_level = "CRITICAL"
            description = "EXTREMELY COMPROMISED - Found in 1000+ breaches"
        elif breach_count >= 100:
            risk_level = "HIGH"
            description = "SEVERELY COMPROMISED - Found in 100+ breaches"
        elif breach_count >= 10:
            risk_level = "MEDIUM"
            description = "COMPROMISED - Found in multiple breaches"
        elif breach_count > 0:
            risk_level = "LOW"
            description = "MINIMALLY COMPROMISED - Found in 1 breach"
        else:
            risk_level = "NONE"
            description = "CLEAN - Not found in known breaches"
        
        return {
            'level': risk_level,
            'description': description,
            'exposure_count': breach_count
        }
    
    def get_security_intelligence(self) -> Dict:
        return {
            "protocol": "K-ANONYMITY",
            "classification": "CONFIDENTIAL",
            "privacy_compliance": "YES",
            "data_protection": "SHA-1 HASH TRUNCATION",
            "verification_method": "REAL-TIME API INTEGRATION",
            "threat_intelligence": "GLOBAL BREACH DATABASE"
        }
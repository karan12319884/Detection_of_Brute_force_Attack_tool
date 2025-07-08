import time
from datetime import datetime, timedelta
from collections import defaultdict

class BruteForceDetector:
    def __init__(self, max_attempts=5, time_window=60, ban_time=300):
        self.max_attempts = max_attempts
        self.time_window = time_window
        self.ban_time = ban_time
        self.attempts = defaultdict(list)
        self.banned_ips = {}
        
    def log_attempt(self, ip_address, success):
        current_time = time.time()
        
        self._clean_old_attempts(ip_address, current_time)
        
        if ip_address in self.banned_ips:
            if current_time > self.banned_ips[ip_address]:
                del self.banned_ips[ip_address]
            else:
                return False
        
        if not success:
            self.attempts[ip_address].append(current_time)
            
            if len(self.attempts[ip_address]) >= self.max_attempts:
                self._handle_brute_force(ip_address, current_time)
                return False
        else:
            if ip_address in self.attempts:
                del self.attempts[ip_address]
                
        return True
    
    def _clean_old_attempts(self, ip_address, current_time):
        if ip_address in self.attempts:
            self.attempts[ip_address] = [
                t for t in self.attempts[ip_address] 
                if current_time - t < self.time_window
            ]
            if not self.attempts[ip_address]:
                del self.attempts[ip_address]
    
    def _handle_brute_force(self, ip_address, current_time):
        ban_until = current_time + self.ban_time
        self.banned_ips[ip_address] = ban_until
        print(f"[ALERT] Brute-force detected from {ip_address}. Banned until {datetime.fromtimestamp(ban_until)}")
        
    def is_banned(self, ip_address):
        current_time = time.time()
        if ip_address in self.banned_ips:
            if current_time <= self.banned_ips[ip_address]:
                return True
            del self.banned_ips[ip_address]
        return False

if __name__ == "__main__":
    detector = BruteForceDetector(max_attempts=3, time_window=60, ban_time=300)
    
    test_ip = "192.168.1.100"
    
    print("Testing normal behavior:")
    for i in range(2):
        print(f"Attempt {i+1}:", detector.log_attempt(test_ip, False))
    
    print("\nTesting brute-force detection:")
    for i in range(5):
        allowed = detector.log_attempt(test_ip, False)
        print(f"Attempt {i+1}:", allowed)
        if not allowed:
            break
    
    print("\nChecking ban status:")
    print("Is banned:", detector.is_banned(test_ip))
    print("Trying banned IP:", detector.log_attempt(test_ip, False))
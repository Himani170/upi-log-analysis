"""
================================================================================
UPI FRAUD DETECTOR - Core Detection Logic
================================================================================
This file contains the main logic for detecting fraudulent UPI IDs.

Purpose:
- Analyze UPI IDs for suspicious patterns
- Check against known scam keywords
- Verify bank handle legitimacy
- Calculate risk score

Author: UPI Fraud Detection Team
================================================================================
"""

import re
from datetime import datetime


class UPIRiskChecker:
    """
    ============================================================================
    CLASS: UPIRiskChecker
    ============================================================================
    Purpose: This is the main class that checks if a UPI ID is safe or risky.
    
    How it works:
    1. Takes a UPI ID as input (e.g., "john@oksbi")
    2. Checks it against multiple fraud detection methods
    3. Returns a risk score and verdict
    
    Methods in this class:
    - __init__() - SetupTrusted bank handles and scam keywords
    - analyze_upi_id() - Main function that analyzes the UPI ID
    - _is_valid_format() - Check if UPI ID format is valid
    - _check_fraud_keywords() - Look for scam keywords in the ID
    - _check_suspicious_patterns() - Find suspicious patterns
    - _check_domain_age() - (Optional) Check how old the UPI handle is
    ============================================================================
    """
    
    def __init__(self):
        """
        ============================================================================
        METHOD: __init__ (Constructor)
        ============================================================================
        Purpose: Initialize the checker with trusted banks and scam keywords
        
        What we setup here:
        1. trusted_handles = Bank handles that we know are legitimate
        2. fraud_keywords = Words that scammers commonly use
        3. suspicious_patterns = Regular expressions for suspicious patterns
        ============================================================================
        """
        
        # =========================================================================
        # SECTION 1: TRUSTED BANK HANDLES
        # =========================================================================
        # These are legitimate UPI handles from real banks in India.
        # If a UPI ID uses one of these, it's more trustworthy.
        # 
        # Examples:
        # - @oksbi = State Bank of India
        # - @ybl = Yes Bank
        # - @okhdfcbank = HDFC Bank
        # =========================================================================
        
        self.trusted_handles = {
            # Major Private Banks
            '@oksbi',          # State Bank of India
            '@ybl',            # Yes Bank
            '@okhdfcbank',     # HDFC Bank
            '@okicici',        # ICICI Bank
            '@okaxis',         # Axis Bank
            '@okkotak',        # Kotak Mahindra
            '@okidbi',         # IDBI Bank
            '@okyesbank',      # Yes Bank (alternative)
            '@okucobank',      # UCO Bank
            '@okbarodamanipal', # Bank of Baroda
            '@okfederal',      # Federal Bank
            '@okindus',        # IndusInd Bank
            
            # Public Sector Banks
            '@pnb',            # Punjab National Bank
            '@sbi',            # SBI (alternative)
            '@hdfcbank',       # HDFC (alternative)
            '@icici',          # ICICI (alternative)
            '@axisbank',       # Axis (alternative)
            '@kotak',          # Kotak (alternative)
            '@yesbank',        # Yes Bank (alternative)
            '@idbi',           # IDBI (alternative)
            '@uco',            # UCO Bank
            '@punjabnational', # PNB
            '@indusind',       # IndusInd
            '@federal',        # Federal Bank
            '@baroda',         # Bank of Baroda
            '@canara',         # Canara Bank
            '@unionbank',      # Union Bank of India
            
            # Payment Apps (UPI Enabled)
            '@paytm',          # Paytm
            '@phonepe',        # PhonePe
            '@gpay',           # Google Pay
            '@amazonpay',      # Amazon Pay
            '@mobikwik',       # MobiKwik
            '@airtel',         # Airtel Payments Bank
            '@jio',            # Jio Pay
        }
        
        # =========================================================================
        # SECTION 2: FRAUD KEYWORDS
        # =========================================================================
        # These are words that scammers commonly use in their UPI IDs to trick
        # people. If any of these words appear in a UPI ID, it's a red flag.
        #
        # Categories:
        # - Money/Greed (earn, cash, prize, win)
        # - Government (sarkari, govt, yojana)
        # - Urgency (verify, urgent, kyc)
        # - Banking (bank, account, otp)
        # - Jobs (job, work, parttime)
        # =========================================================================
        
        self.fraud_keywords = [
            # 🎰 Money/Greed Keywords - Scammers promise easy money
            'earn', 'money', 'cash', 'rupees', 'income',
            'win', 'winner', 'winning', 'lottery', 'prize', 'gift', 'reward',
            'bonus', 'free', 'freebie', 'giveaway', 'promo', 'discount', 'offer',
            'million', 'crore', 'lakh', 'rupees', 'double', 'doublemoney',
            'profit', 'investment', 'return', 'returns', 'interest',
            
            # 🏛️ Government Keywords - Scammers pretend to be from government
            'sarkari', 'govt', 'government', 'gov', 'govt',
            'yojana', 'scheme', 'scheme', 'subsidy', 'benefits',
            'aadhaar', 'pan', 'nrc', 'citizen', 'official', 'authority',
            
            # ⚠️ Urgency Keywords - Scammers create fake urgency
            'urgent', 'verify', 'verification', 'confirm', 'confirmation',
            'kyc', 'kycupdate', 'kycverified', 'update', 'updated',
            'link', 'click', 'tap', 'active', 'activate', 'unlock',
            'expire', 'expiring', 'deadline', 'lastday', 'limited',
            
            # 🏦 Banking Keywords - Scammers impersonate banks
            'bank', 'banking', 'account', 'accountverify', 'accountupdate',
            'password', 'pin', 'mpin', 'otp', 'otpregister',
            'details', 'detail', 'info', 'information', 'balance',
            'blocked', 'freeze', 'frozen', 'suspended', 'deactivate',
            
            # 💼 Job Keywords - Fake job offers
            'job', 'jobs', 'work', 'workfromhome', 'parttime', 'parttimejob',
            'homebased', 'onlinejob', 'earnfromhome', 'salary',
            
            # 📞 Customer Support Keywords - Fake helplines
            'help', 'helpdesk', 'support', 'customer', 'service', 'care',
            'contact', 'call', 'helpline', 'tollfree', 'customer care',
            
            # 🔧 Tech Keywords - Fake tech support
            'tech', 'techsupport', 'technical', 'server', 'system',
            'update', 'maintenance', 'maintain',
            
            # 🎯 Scam Action Keywords
            'claim', 'claimnow', 'claimprize', 'apply', 'applynow',
            'register', 'registration', 'signup', 'signin',
            
            # 👤 Personal Info Keywords
            'name', 'mobile', 'number', 'email', 'address',
            
            # 🚨 Emergency Keywords
            'police', 'court', 'legal', 'notice', 'summon', 'warrant',
            
            # 💰 Payment Keywords
            'payment', 'pay', 'send', 'transfer', 'transaction',
            'refund', 'return', 'moneyback', 'cashback',
            
            # 🎲 Lucky/Draw Keywords
            'lucky', 'draw', 'result', 'selected', 'luckywinner',
            'contest', 'competition', 'raffle',
            
            # 📱 App Keywords
            'app', 'application', 'download', 'install',
        ]
        
        # =========================================================================
        # SECTION 3: SUSPICIOUS PATTERNS
        # =========================================================================
        # These are regex patterns that match suspicious behaviors in UPI IDs.
        # Regular Expressions (regex) are patterns that match specific text.
        # =========================================================================
        
        self.suspicious_patterns = [
            r'\d{5,}',        # 5 or more consecutive digits (e.g., 123456789)
            r'[a-z]{15,}',    # Very long username (15+ letters)
            r'tech\d+',       # tech123, techsupport999
            r'care\d+',       # care123, carehelp456
            r'support\d+',    # support12345
            r'help\d+',       # help999
            r'govt\d+',       # govt12345
            r'bank\d+',       # bankupdate123
            r'\d{3,}[a-z]+',  # Numbers followed by text (e.g., 123abc)
            r'[a-z]+\d{3,}',  # Text followed by numbers (e.g., abc12345)
            r'(.)\1{3,}',     # Same character repeated 3+ times (aaaa, 1111)
        ]
    
    # ============================================================================
    # MAIN METHOD: analyze_upi_id()
    # ============================================================================
    # This is the main function that checks a UPI ID and returns the result
    # ============================================================================
    
    def analyze_upi_id(self, upi_id):
        """
        ============================================================================
        METHOD: analyze_upi_id()
        ============================================================================
        Purpose: The main function that analyzes a UPI ID for fraud
        
        Input: upi_id (string) - e.g., "john.doe@oksbi"
        
        Output: Dictionary containing:
        - upi_id: The original UPI ID
        - risk_level: "SAFE", "SUSPICIOUS", or "DANGEROUS"
        - risk_score: 0-100 (higher = more risky)
        - reasons: List of reasons for the risk level
        - bank_handle: The @bank part
        - is_trusted_bank: True/False
        - warnings: Additional warnings
        
        How it works:
        1. Validates the format of UPI ID
        2. Extracts username and bank handle
        3. Checks against all fraud detection methods
        4. Calculates final risk score
        5. Returns verdict
        ============================================================================
        """
        
        # Clean the input - remove extra spaces and convert to lowercase
        upi_id = upi_id.strip().lower()
        
        # Initialize result dictionary with default values
        result = {
            "upi_id": upi_id,
            "risk_level": "SAFE",
            "risk_score": 0,
            "reasons": [],
            "warnings": [],
            "bank_handle": None,
            "is_trusted_bank": False,
            "username": None
        }
        
        # Step 1: Validate UPI ID format
        # A valid UPI ID should look like: username@bank
        # Example: john.doe@oksbi
        if not self._is_valid_format(upi_id):
            result["risk_level"] = "DANGEROUS"
            result["risk_score"] = 100
            result["reasons"].append("Invalid UPI ID format - must be username@bank")
            return result
        
        # Step 2: Extract username and handle
        # Split "john.doe@oksbi" into "john.doe" and "@oksbi"
        parts = upi_id.split('@')
        
        # Make sure there are exactly 2 parts (username and bank handle)
        if len(parts) != 2:
            result["risk_level"] = "DANGEROUS"
            result["reasons"].append("UPI ID must have exactly one @ symbol")
            return result
        
        username, handle = parts[0], '@' + parts[1]
        result["username"] = username
        result["bank_handle"] = handle
        
        # Step 3: Check if bank handle is trusted
        # If it's a known bank, reduce risk score
        if handle in self.trusted_handles:
            result["is_trusted_bank"] = True
            result["risk_score"] -= 10  # Reduce risk by 10 points
        
        # Step 4: Check for fraud keywords in username
        # Scammers use words like "earn", "win", "prize" to trick people
        keyword_found = self._check_fraud_keywords(username)
        if keyword_found:
            result["risk_score"] += 40  # Add 40 points to risk
            result["reasons"].append(f"Fraud keyword found: '{keyword_found}'")
        
        # Step 5: Check for suspicious patterns
        # Look for patterns like long numbers, repeated characters, etc.
        if self._check_suspicious_patterns(username):
            result["risk_score"] += 25
            result["reasons"].append("Suspicious pattern detected in username")
        
        # Step 6: Check username length
        # Scammers often use very long usernames to appear official
        if len(username) > 15:
            result["risk_score"] += 20
            result["reasons"].append(f"Unusually long username ({len(username)} characters)")
        
        # Step 7: Check for too many numbers
        # Having 5+ consecutive numbers is suspicious
        if re.search(r'\d{5,}', username):
            result["risk_score"] += 15
            result["reasons"].append("Too many consecutive numbers in ID")
        
        # Step 8: Check for all lowercase (very long string)
        # Legitimate UPI IDs usually have a reasonable length
        if len(username) > 20:
            result["risk_score"] += 15
            result["reasons"].append("Extremely long username - likely automated")
        
        # Step 9: Determine final risk level based on score
        # 0-29 = SAFE, 30-59 = SUSPICIOUS, 60+ = DANGEROUS
        if result["risk_score"] >= 60:
            result["risk_level"] = "DANGEROUS"
        elif result["risk_score"] >= 30:
            result["risk_level"] = "SUSPICIOUS"
        else:
            result["risk_level"] = "SAFE"
            # Only add this message if no other reasons found
            if not result["reasons"]:
                result["reasons"].append("No suspicious indicators found")
        
        # Step 10: Add warnings
        if result["is_trusted_bank"]:
            result["warnings"].append("✓ Bank handle is from a recognized bank")
        
        if result["risk_level"] == "SAFE":
            result["warnings"].append("✓ Still verify the recipient name in your payment app")
        
        return result
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _is_valid_format(self, upi_id):
        """
        ============================================================================
        METHOD: _is_valid_format()
        ============================================================================
        Purpose: Check if UPI ID has a valid format
        
        Valid format: letters, numbers, dots, hyphens, underscores 
                     followed by @ followed by letters, numbers, dots, hyphens
        
        Example valid: john.doe@oksbi, user123@paytm
        Example invalid: @@@@, user@@bank, no-at-sign
        ============================================================================
        """
        # Regex pattern explanation:
        # ^[a-zA-Z0-9._-]+  = Start with letters/numbers/dots/underscores/hyphens
        # @                 = Must have @ symbol
        # [a-zA-Z0-9.-]+$   = End with letters/numbers/dots/hyphens
        pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$'
        return bool(re.match(pattern, upi_id))
    
    def _check_fraud_keywords(self, username):
        """
        ============================================================================
        METHOD: _check_fraud_keywords()
        ============================================================================
        Purpose: Check if username contains any fraud keywords
        
        Input: username (string) - e.g., "earn.money.free"
        
        Output: The keyword found (string) or None
        ============================================================================
        """
        # Convert username to lowercase for comparison
        username_lower = username.lower()
        
        # Loop through each fraud keyword
        for keyword in self.fraud_keywords:
            # If keyword is found in username, return it
            if keyword in username_lower:
                return keyword
        
        # No keyword found
        return None
    
    def _check_suspicious_patterns(self, username):
        """
        ============================================================================
        METHOD: _check_suspicious_patterns()
        ============================================================================
        Purpose: Check if username matches any suspicious regex patterns
        
        Input: username (string)
        
        Output: True if suspicious pattern found, False otherwise
        ============================================================================
        """
        # Convert to lowercase
        username_lower = username.lower()
        
        # Check each suspicious pattern
        for pattern in self.suspicious_patterns:
            # re.search looks for the pattern anywhere in the string
            if re.search(pattern, username_lower):
                return True
        
        # No suspicious pattern found
        return False


# ============================================================================
# CLASS: FraudDetector (Legacy - for existing functionality)
# ============================================================================
# This class is kept for backward compatibility with existing code
# ============================================================================

class FraudDetector:
    """
    ============================================================================
    CLASS: FraudDetector (Legacy)
    ============================================================================
    Purpose: This was the original fraud detector class.
    Kept for backward compatibility with existing code.
    
    If you have existing transaction checking logic, keep it here.
    ============================================================================
    """
    
    def __init__(self):
        """Initialize the fraud detector"""
        self.suspicious_keywords = [
            'urgent', 'verify', 'otp', 'refund', 'win', 'prize'
        ]
    
    def check_transaction(self, transaction):
        """
        Method to check a transaction for fraud
        (Your existing implementation goes here)
        """
        # Your existing transaction checking logic
        pass
    
    def detect_fraud(self, data):
        """
        Method to detect fraud in data
        (Your existing implementation goes here)
        """
        # Your existing fraud detection logic
        pass


# ============================================================================
# TEST CODE - Runs only when you run this file directly
# ============================================================================

if __name__ == "__main__":
    """
    ============================================================================
    TEST SECTION
    ============================================================================
    This code runs when you execute: python fraud_detector.py
    
    It tests the UPIRiskChecker with various UPI IDs to show how it works.
    ============================================================================
    """
    
    # Create an instance of the checker
    checker = UPIRiskChecker()
    
    # Test cases with different risk levels
    test_cases = [
        # Safe UPI IDs (Trusted banks, normal usernames)
        ("john.doe@ybl", "Should be SAFE - normal name, trusted bank"),
        ("raj.kumar@oksbi", "Should be SAFE - normal name, SBI"),
        ("priya.sharma@okhdfcbank", "Should be SAFE - normal name, HDFC"),
        ("user123@paytm", "Should be SAFE - normal user, Paytm"),
        
        # Dangerous UPI IDs (Fraud keywords)
        ("earn.money.free@paytm", "Should be DANGEROUS - multiple fraud keywords"),
        ("lottery.winner.now@upi", "Should be DANGEROUS - lottery scam"),
        ("prize.claim.now@gpay", "Should be DANGEROUS - prize scam"),
        ("sarkari.yojana.help@oksbi", "Should be DANGEROUS - govt scam"),
        
        # Suspicious UPI IDs (Some red flags)
        ("verify.kyc.update@okaxis", "Should be SUSPICIOUS - KYC scam"),
        ("tech.support.123@oksbi", "Should be SUSPICIOUS - tech support scam"),
        ("helpdesk.care@paytm", "Should be SUSPICIOUS - fake support"),
        
        # More Dangerous Cases
        ("job.earn.money@upi", "Should be DANGEROUS - job scam"),
        ("free.gift.lucky@okhdfcbank", "Should be DANGEROUS - gift scam"),
        ("bank.verify.account@okaxis", "Should be DANGEROUS - bank scam"),
        
        # Edge Cases
        ("8967123456@oksbi", "Should be SUSPICIOUS - phone number as username"),
        ("verylongusername@paytm", "Should be SUSPICIOUS - very long username"),
    ]
    
    # Print test results
    print("=" * 80)
    print("🛡️ UPI FRAUD DETECTOR - TEST RESULTS")
    print("=" * 80)
    print()
    
    for upi_id, expected in test_cases:
        result = checker.analyze_upi_id(upi_id)
        
        # Color coding for output
        if result["risk_level"] == "SAFE":
            emoji = "✅"
        elif result["risk_level"] == "SUSPICIOUS":
            emoji = "⚠️"
        else:
            emoji = "🚨"
        
        print(f"{emoji} UPI ID: {upi_id}")
        print(f"   Level: {result['risk_level']} | Score: {result['risk_score']}/100")
        print(f"   Bank: {result['bank_handle']} | Trusted: {result['is_trusted_bank']}")
        if result["reasons"]:
            print(f"   Reasons: {', '.join(result['reasons'])}")
        print(f"   Expected: {expected}")
        print("-" * 80)
    
    print()
    print("✅ Tests completed!")
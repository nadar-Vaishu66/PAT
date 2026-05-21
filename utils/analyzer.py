"""
PAT - Password Analyzer
Core analysis logic for password strength, entropy, crack time, patterns.
"""

import re
import math
import string


# Common password patterns to detect
COMMON_PASSWORDS = {
    'password', 'password1', '123456', '123456789', 'qwerty', 'abc123',
    'monkey', 'master', 'dragon', 'letmein', 'sunshine', 'princess',
    'welcome', 'shadow', 'superman', 'michael', 'football', 'iloveyou',
    'passw0rd', 'admin', 'login', 'hello', 'charlie', 'donald', 'qwerty123',
    '111111', '12345678', '1234567', '1234567890', 'baseball', 'trustno1',
    'batman', 'access', 'jesus', 'ninja', 'mustang', 'jessica', 'ashley',
    'bailey', 'starwars', 'pass', 'test', 'temp', 'changeme', 'secret'
}

KEYBOARD_PATTERNS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn',
    'qweasdzxc', '1234567890', '0987654321', 'poiuytrewq',
    'lkjhgfdsa', '!@#$%^&*()', 'qazwsx', 'edcrfv', 'tgbyhn'
]

LEET_MAP = {'@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '$': 's', '!': 'i'}


def calculate_charset_size(password):
    """Calculate the effective character set size used in the password."""
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password):
        charset += 32
    if re.search(r'[^\x00-\x7F]', password):  # non-ASCII
        charset += 64
    return max(charset, 1)


def calculate_entropy(password):
    """Calculate Shannon entropy and brute-force entropy."""
    if not password:
        return 0.0
    
    charset_size = calculate_charset_size(password)
    brute_force_entropy = len(password) * math.log2(charset_size)
    
    # Also calculate Shannon entropy based on character frequency
    from collections import Counter
    freq = Counter(password)
    length = len(password)
    shannon = -sum((count / length) * math.log2(count / length) for count in freq.values())
    shannon_total = shannon * length
    
    # Use the lower of the two for a conservative estimate
    return round(min(brute_force_entropy, shannon_total * 1.5 + brute_force_entropy * 0.5) if shannon_total > 0 else brute_force_entropy, 2)


def get_entropy_rating(entropy):
    """Convert entropy bits to a human-readable security rating."""
    if entropy < 28:
        return "Very Weak", 0
    elif entropy < 36:
        return "Weak", 1
    elif entropy < 60:
        return "Reasonable", 2
    elif entropy < 80:
        return "Strong", 3
    elif entropy < 128:
        return "Very Strong", 4
    else:
        return "Exceptional", 5


def estimate_crack_time(password):
    """Estimate time to crack using different attack methods."""
    charset_size = calculate_charset_size(password)
    combinations = charset_size ** len(password)
    
    # Average case is half of all combinations
    avg_combinations = combinations / 2
    
    # Attack speeds (guesses per second)
    speeds = {
        'casual': 1_000,           # Online attack, throttled
        'gpu': 10_000_000_000,     # Modern GPU (10 billion/s)
        'botnet': 100_000_000_000  # Distributed botnet
    }
    
    results = {}
    for attack_type, speed in speeds.items():
        seconds = avg_combinations / speed
        results[attack_type] = format_time(seconds)
    
    return results


def format_time(seconds):
    """Format seconds into human-readable time."""
    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 2592000:
        return f"{int(seconds / 86400)} days"
    elif seconds < 31536000:
        return f"{int(seconds / 2592000)} months"
    elif seconds < 3153600000:
        return f"{int(seconds / 31536000)} years"
    elif seconds < 3.154e12:
        return f"{int(seconds / 3153600000)} millennia"
    else:
        return "longer than the age of the universe"


def detect_patterns(password):
    """Detect various patterns in the password."""
    patterns = []
    lower = password.lower()
    
    # Check for keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            patterns.append({
                'type': 'keyboard',
                'description': f'Keyboard walk detected: "{pattern}"',
                'severity': 'high'
            })
            break
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        match = re.search(r'(.)\1{2,}', password)
        patterns.append({
            'type': 'repeat',
            'description': f'Repeated characters: "{match.group()}"',
            'severity': 'medium'
        })
    
    # Check for sequential numbers
    if re.search(r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)', password):
        patterns.append({
            'type': 'sequential',
            'description': 'Sequential number pattern detected',
            'severity': 'medium'
        })
    
    # Check for sequential letters
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', lower):
        patterns.append({
            'type': 'sequential_alpha',
            'description': 'Sequential letter pattern detected',
            'severity': 'medium'
        })
    
    # Check for year patterns
    if re.search(r'(19|20)\d{2}', password):
        patterns.append({
            'type': 'year',
            'description': 'Year pattern detected (common in passwords)',
            'severity': 'low'
        })
    
    # Check for date patterns
    if re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password):
        patterns.append({
            'type': 'date',
            'description': 'Date pattern detected',
            'severity': 'low'
        })
    
    # Check for leet speak
    deleet = ''.join(LEET_MAP.get(c, c) for c in lower)
    if deleet != lower:
        patterns.append({
            'type': 'leet',
            'description': 'L33t speak substitution detected (hackers know this trick)',
            'severity': 'low'
        })
    
    # Check for common password
    if lower in COMMON_PASSWORDS:
        patterns.append({
            'type': 'common',
            'description': 'This is one of the most commonly used passwords',
            'severity': 'critical'
        })
    
    # Check if password is all numbers
    if password.isdigit():
        patterns.append({
            'type': 'numeric_only',
            'description': 'Password contains only digits',
            'severity': 'high'
        })
    
    # Check if password is all lowercase
    if password.isalpha() and password == password.lower():
        patterns.append({
            'type': 'alpha_only',
            'description': 'Password contains only lowercase letters',
            'severity': 'medium'
        })
    
    # Check for repeated word patterns
    if re.search(r'(\w{3,})\1', lower):
        patterns.append({
            'type': 'word_repeat',
            'description': 'Repeated word/phrase detected',
            'severity': 'medium'
        })
    
    return patterns


def score_password(password):
    """Calculate a security score from 0-100 with breakdown."""
    if not password:
        return {'total': 0, 'breakdown': {}}
    
    breakdown = {}
    
    # === LENGTH SCORE (0-25) ===
    length = len(password)
    if length < 6:
        breakdown['length'] = {'score': 0, 'max': 25, 'label': 'Too Short', 'note': f'{length} chars — minimum 8 recommended'}
    elif length < 8:
        breakdown['length'] = {'score': 5, 'max': 25, 'label': 'Short', 'note': f'{length} chars — use at least 12'}
    elif length < 10:
        breakdown['length'] = {'score': 12, 'max': 25, 'label': 'Acceptable', 'note': f'{length} chars'}
    elif length < 12:
        breakdown['length'] = {'score': 17, 'max': 25, 'label': 'Good', 'note': f'{length} chars'}
    elif length < 16:
        breakdown['length'] = {'score': 22, 'max': 25, 'label': 'Strong', 'note': f'{length} chars'}
    else:
        breakdown['length'] = {'score': 25, 'max': 25, 'label': 'Excellent', 'note': f'{length} chars'}
    
    # === COMPLEXITY SCORE (0-25) ===
    complexity = 0
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password))
    
    complexity += 5 if has_lower else 0
    complexity += 7 if has_upper else 0
    complexity += 7 if has_digit else 0
    complexity += 11 if has_special else 0
    
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    label_map = {0: 'None', 1: 'Minimal', 2: 'Low', 3: 'Moderate', 4: 'Full Mix'}
    breakdown['complexity'] = {
        'score': min(complexity, 25),
        'max': 25,
        'label': label_map[char_types],
        'note': f'{char_types}/4 character types used'
    }
    
    # === UNIQUENESS SCORE (0-20) ===
    unique_chars = len(set(password))
    unique_ratio = unique_chars / len(password)
    uniqueness_score = int(unique_ratio * 20)
    breakdown['uniqueness'] = {
        'score': uniqueness_score,
        'max': 20,
        'label': 'Low' if unique_ratio < 0.5 else ('Moderate' if unique_ratio < 0.75 else 'High'),
        'note': f'{unique_chars} unique chars out of {len(password)}'
    }
    
    # === PREDICTABILITY SCORE (0-20) ===
    patterns = detect_patterns(password)
    severity_deductions = {'critical': 20, 'high': 15, 'medium': 8, 'low': 3}
    deduction = sum(severity_deductions.get(p['severity'], 0) for p in patterns)
    predictability_score = max(0, 20 - deduction)
    breakdown['predictability'] = {
        'score': predictability_score,
        'max': 20,
        'label': 'Predictable' if predictability_score < 8 else ('Moderate' if predictability_score < 15 else 'Unpredictable'),
        'note': f'{len(patterns)} patterns detected'
    }
    
    # === ENTROPY SCORE (0-10) ===
    entropy = calculate_entropy(password)
    if entropy < 30:
        entropy_score = 0
    elif entropy < 50:
        entropy_score = 3
    elif entropy < 70:
        entropy_score = 6
    elif entropy < 90:
        entropy_score = 8
    else:
        entropy_score = 10
    breakdown['entropy'] = {
        'score': entropy_score,
        'max': 10,
        'label': f'{entropy} bits',
        'note': 'Higher is better'
    }
    
    total = sum(v['score'] for v in breakdown.values())
    return {'total': min(total, 100), 'breakdown': breakdown}


def get_strength_label(score):
    """Get strength label from score."""
    if score < 20:
        return 'CRITICAL', '#ff0000'
    elif score < 40:
        return 'WEAK', '#ff4444'
    elif score < 60:
        return 'MODERATE', '#ffaa00'
    elif score < 80:
        return 'STRONG', '#44ff44'
    else:
        return 'VERY STRONG', '#00ff88'


def generate_heatmap(password):
    """Generate character-level heatmap data showing weak spots."""
    heatmap = []
    lower = password.lower()
    
    for i, char in enumerate(password):
        heat = 'normal'  # green
        reason = ''
        
        # Check for keyboard pattern involvement
        for pattern in KEYBOARD_PATTERNS:
            if i < len(lower) - 1:
                chunk = lower[i:i+3]
                if len(chunk) == 3 and chunk in pattern:
                    heat = 'hot'
                    reason = 'Keyboard pattern'
                    break
        
        # Check digit
        if char.isdigit():
            # Check if part of sequential run
            if i > 0 and i < len(password) - 1:
                if password[i-1].isdigit() and password[i+1].isdigit():
                    heat = 'warm'
                    reason = 'Sequential digit'
        
        # Repeated character
        if i > 0 and password[i] == password[i-1]:
            heat = 'warm'
            reason = 'Repeated character'
        
        # Leet speak
        if char in LEET_MAP:
            heat = 'warm'
            reason = 'Leet substitution'
        
        heatmap.append({'char': char, 'heat': heat, 'reason': reason})
    
    return heatmap


def generate_feedback(password, score, patterns):
    """Generate human-friendly feedback messages."""
    feedback = []
    
    length = len(password)
    
    if length == 0:
        return []
    
    if length < 8:
        feedback.append({
            'type': 'error',
            'message': f'Your password is too short ({length} chars). Hackers can crack it instantly.',
            'icon': '⚠'
        })
    elif length < 12:
        feedback.append({
            'type': 'warning',
            'message': 'Longer passwords are exponentially harder to crack. Aim for 14+ characters.',
            'icon': '→'
        })
    
    if not re.search(r'[A-Z]', password):
        feedback.append({
            'type': 'warning',
            'message': 'Adding uppercase letters will significantly increase your password strength.',
            'icon': '→'
        })
    
    if not re.search(r'[0-9]', password):
        feedback.append({
            'type': 'warning',
            'message': 'Including numbers makes your password harder to guess.',
            'icon': '→'
        })
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password):
        feedback.append({
            'type': 'warning',
            'message': 'Adding symbols (!@#$) will greatly improve security — few brute-force tools start with symbols.',
            'icon': '→'
        })
    
    for pattern in patterns:
        if pattern['severity'] == 'critical':
            feedback.append({
                'type': 'error',
                'message': 'This is one of the most commonly tried passwords. Change it immediately.',
                'icon': '✗'
            })
        elif pattern['type'] == 'keyboard':
            feedback.append({
                'type': 'error',
                'message': 'Your password uses a keyboard walk pattern. Hackers try these first.',
                'icon': '✗'
            })
        elif pattern['type'] == 'year':
            feedback.append({
                'type': 'warning',
                'message': 'Avoid using years — birthdays and anniversaries are among the first things attackers try.',
                'icon': '→'
            })
        elif pattern['type'] == 'leet':
            feedback.append({
                'type': 'info',
                'message': 'L33t speak substitutions (like @ for a) are well-known to attackers and add minimal security.',
                'icon': 'ℹ'
            })
        elif pattern['type'] == 'repeat':
            feedback.append({
                'type': 'warning',
                'message': 'Repeated characters reduce your password\'s complexity significantly.',
                'icon': '→'
            })
    
    if score['total'] >= 80:
        feedback.append({
            'type': 'success',
            'message': 'Excellent password. Store it in a password manager to keep it secure.',
            'icon': '✓'
        })
    elif score['total'] >= 60:
        feedback.append({
            'type': 'success',
            'message': 'Good password. Consider making it longer for even better protection.',
            'icon': '✓'
        })
    
    return feedback


def analyze_password(password):
    """Main analysis function — returns complete analysis object."""
    if not password:
        return {}
    
    entropy = calculate_entropy(password)
    entropy_rating, entropy_level = get_entropy_rating(entropy)
    patterns = detect_patterns(password)
    score = score_password(password)
    strength_label, strength_color = get_strength_label(score['total'])
    crack_times = estimate_crack_time(password)
    heatmap = generate_heatmap(password)
    feedback = generate_feedback(password, score, patterns)
    
    return {
        'password_length': len(password),
        'entropy': {
            'bits': entropy,
            'rating': entropy_rating,
            'level': entropy_level
        },
        'score': score,
        'strength': {
            'label': strength_label,
            'color': strength_color
        },
        'crack_times': crack_times,
        'patterns': patterns,
        'heatmap': heatmap,
        'feedback': feedback,
        'char_analysis': {
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password)),
            'unique_chars': len(set(password)),
            'charset_size': calculate_charset_size(password)
        }
    }
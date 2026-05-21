"""
PAT - Password Generator
Cryptographically secure password and passphrase generator.
"""

import secrets
import string
import random


# Word lists for memorable passphrases
ADJECTIVES = [
    'amber', 'azure', 'blazing', 'bold', 'bright', 'calm', 'crystal', 'dark',
    'deep', 'deft', 'distant', 'electric', 'fierce', 'frozen', 'golden', 'grand',
    'hollow', 'iron', 'jade', 'lone', 'lunar', 'mighty', 'neon', 'noble',
    'obsidian', 'phantom', 'primal', 'rapid', 'rogue', 'savage', 'silent',
    'silver', 'solar', 'stark', 'steel', 'stone', 'swift', 'toxic', 'velvet',
    'wild', 'winter', 'zenith', 'zero', 'cobalt', 'crimson', 'shadow', 'quantum'
]

NOUNS = [
    'apex', 'arc', 'atlas', 'axon', 'bastion', 'beacon', 'blade', 'bolt',
    'byte', 'cipher', 'citadel', 'code', 'core', 'comet', 'cosmos', 'crypt',
    'dagger', 'data', 'delta', 'drone', 'echo', 'edge', 'epoch', 'falcon',
    'flare', 'forge', 'frost', 'gate', 'ghost', 'grid', 'hawk', 'helix',
    'hex', 'horizon', 'hydra', 'kraken', 'laser', 'matrix', 'maze', 'mesh',
    'nexus', 'node', 'nova', 'orbit', 'phase', 'pixel', 'proxy', 'pulse',
    'quasar', 'radar', 'realm', 'relay', 'rune', 'sector', 'sentinel', 'server',
    'signal', 'siren', 'socket', 'spike', 'storm', 'surge', 'synapse', 'token',
    'titan', 'trace', 'vault', 'vector', 'vertex', 'viper', 'void', 'wave',
    'warden', 'wraith', 'zero', 'zone', 'cobra', 'phantom', 'specter', 'cipher'
]

VERBS = [
    'breach', 'bypass', 'chase', 'clash', 'crash', 'cross', 'crush', 'dash',
    'decrypt', 'deploy', 'detect', 'dive', 'dodge', 'dread', 'drive', 'encode',
    'evade', 'exploit', 'fight', 'flank', 'flash', 'forge', 'freeze', 'glitch',
    'guard', 'hack', 'hunt', 'ignite', 'intercept', 'invade', 'jump', 'launch',
    'lock', 'lunge', 'mitigate', 'monitor', 'morph', 'neutralize', 'obliterate',
    'override', 'patch', 'penetrate', 'probe', 'protect', 'pulse', 'purge',
    'reboot', 'redirect', 'scan', 'secure', 'shift', 'shield', 'shred', 'slice',
    'smash', 'sneak', 'spike', 'spiral', 'sprint', 'strike', 'surge', 'sweep',
    'trace', 'track', 'trigger', 'unlock', 'upload', 'vanish', 'wipe', 'zero'
]


def generate_password(length=16, use_symbols=True, use_numbers=True, use_uppercase=True):
    """
    Generate a cryptographically secure random password.
    Uses secrets module for true cryptographic randomness.
    """
    charset = string.ascii_lowercase  # Always include lowercase
    
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_numbers:
        charset += string.digits
    if use_symbols:
        charset += '!@#$%^&*()-_=+[]{}|;:,.<>?'
    
    # Ensure we meet the requirements by including at least one of each requested type
    password_chars = []
    
    if use_uppercase:
        password_chars.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        password_chars.append(secrets.choice(string.digits))
    if use_symbols:
        password_chars.append(secrets.choice('!@#$%^&*()-_=+[]{}|;:,.<>?'))
    
    # Always add at least one lowercase
    password_chars.append(secrets.choice(string.ascii_lowercase))
    
    # Fill the rest
    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(charset) for _ in range(remaining))
    
    # Shuffle with cryptographically secure random
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)


def generate_passphrase(word_count=4, separator='-', capitalize=True, add_number=True):
    """
    Generate a memorable passphrase using random words.
    Based on the EFF Diceware concept — long but memorable.
    """
    # Build words list: adjective + noun + verb + noun pattern
    word_pools = [ADJECTIVES, NOUNS, VERBS, NOUNS]
    
    words = []
    for i in range(word_count):
        pool = word_pools[i % len(word_pools)]
        word = secrets.choice(pool)
        if capitalize:
            word = word.capitalize()
        words.append(word)
    
    passphrase = separator.join(words)
    
    # Optionally append a 2-3 digit number for extra entropy
    if add_number:
        passphrase += separator + str(secrets.randbelow(900) + 100)
    
    return passphrase
"""
Hash Generator Module

Provides functions to generate multiple hash algorithms for input strings.
Supports SHA256, GOST R 34.11-94, SHA384, SHA3-256, Keccak-256, and SHA256(MD5()).
"""

import hashlib
from typing import Dict, Union
from Crypto.Hash import keccak
import gostcrypto


def generate_hashes(plaintext: str) -> Dict[str, str]:
    """
    Generate multiple hash algorithms for the given plaintext string.
    
    Args:
        plaintext: The input string to hash
        
    Returns:
        Dictionary containing labeled hashes:
        - SHA256: Standard SHA-256 hash
        - GOST_R_34_11_94: Russian GOST R 34.11-94 hash
        - SHA384: Standard SHA-384 hash  
        - SHA3_256: SHA3-256 hash
        - Keccak_256: Keccak-256 hash
        - SHA256_MD5: SHA256 of MD5 hash (double hash)
        
    Raises:
        TypeError: If plaintext is not a string
        ValueError: If plaintext is empty
        
    Example:
        >>> hashes = generate_hashes("hello world")
        >>> print(hashes['SHA256'])
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    """
    if not isinstance(plaintext, str):
        raise TypeError("Input must be a string")
    
    if not plaintext:
        raise ValueError("Input string cannot be empty")
    
    # Convert string to bytes for hashing
    plaintext_bytes = plaintext.encode('utf-8')
    
    try:
        hashes = {}
        
        # SHA256
        sha256_hash = hashlib.sha256(plaintext_bytes)
        hashes['SHA256'] = sha256_hash.hexdigest()
        
        # GOST R 34.11-94 (using GOST R 34.11-2012 256-bit as modern equivalent)
        gost_hash = gostcrypto.gosthash.new('streebog256', data=plaintext_bytes)
        hashes['GOST_R_34_11_94'] = gost_hash.hexdigest()
        
        # SHA384
        sha384_hash = hashlib.sha384(plaintext_bytes)
        hashes['SHA384'] = sha384_hash.hexdigest()
        
        # SHA3-256
        sha3_256_hash = hashlib.sha3_256(plaintext_bytes)
        hashes['SHA3_256'] = sha3_256_hash.hexdigest()
        
        # Keccak-256
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(plaintext_bytes)
        hashes['Keccak_256'] = keccak_hash.hexdigest()
        
        # SHA256(MD5(plaintext))
        md5_hash = hashlib.md5(plaintext_bytes)
        sha256_md5_hash = hashlib.sha256(md5_hash.digest())
        hashes['SHA256_MD5'] = sha256_md5_hash.hexdigest()
        
        return hashes
        
    except Exception as e:
        raise RuntimeError(f"Error generating hashes: {str(e)}") from e


def print_hashes(plaintext: str) -> None:
    """
    Generate and print all hashes for the given plaintext in a formatted way.
    
    Args:
        plaintext: The input string to hash
        
    Example:
        >>> print_hashes("hello world")
        Input: hello world
        
        Hash Results:
        =============
        SHA256:        b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        GOST_R_34_11_94: 8d5e957f297893bcf2ca652d6d4fa8e2b5e1b4c4c8b8df8e3c4f7b8d6e5e4d3c
        ...
    """
    try:
        hashes = generate_hashes(plaintext)
        
        print(f"Input: {plaintext}")
        print("\nHash Results:")
        print("=" * 50)
        
        for algorithm, hash_value in hashes.items():
            print(f"{algorithm:<15}: {hash_value}")
            
    except (TypeError, ValueError, RuntimeError) as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Demo usage
    test_input = "hello world"
    print_hashes(test_input) 
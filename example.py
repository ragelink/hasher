#!/usr/bin/env python3
"""
Example usage of the hash generator functions.

This script demonstrates how to use the hasher module to generate
multiple cryptographic hashes from input strings.
"""

from hasher import generate_hashes, print_hashes


def main():
    """Demonstrate hash generation with various examples."""
    
    print("Hash Generator Example")
    print("=" * 50)
    
    # Example 1: Basic usage with formatted output
    print("\n1. Basic Usage:")
    print_hashes("hello world")
    
    # Example 2: Programmatic access to individual hashes
    print("\n2. Programmatic Access:")
    plaintext = "password123"
    hashes = generate_hashes(plaintext)
    
    print(f"Input: {plaintext}")
    print(f"SHA256:     {hashes['SHA256']}")
    print(f"Keccak-256: {hashes['Keccak_256']}")
    print(f"SHA256(MD5): {hashes['SHA256_MD5']}")
    
    # Example 3: Unicode string handling
    print("\n3. Unicode String:")
    unicode_text = "Hello 世界! 🌍"
    print_hashes(unicode_text)
    
    # Example 4: Comparing different inputs
    print("\n4. Different Inputs Produce Different Hashes:")
    input1 = "test1"
    input2 = "test2"
    
    hashes1 = generate_hashes(input1)
    hashes2 = generate_hashes(input2)
    
    print(f"'{input1}' SHA256: {hashes1['SHA256']}")
    print(f"'{input2}' SHA256: {hashes2['SHA256']}")
    print(f"Hashes are different: {hashes1['SHA256'] != hashes2['SHA256']}")
    
    # Example 5: Error handling demonstration
    print("\n5. Error Handling:")
    try:
        generate_hashes("")  # This will raise ValueError
    except ValueError as e:
        print(f"Caught expected error: {e}")
    
    try:
        generate_hashes(123)  # This will raise TypeError
    except TypeError as e:
        print(f"Caught expected error: {e}")


if __name__ == "__main__":
    main() 
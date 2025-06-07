"""
Unit tests for the hasher module.

Tests cover all hash algorithms, error handling, and edge cases.
"""

import pytest
from hasher import generate_hashes, print_hashes
import hashlib
from io import StringIO
import sys


class TestGenerateHashes:
    """Test cases for the generate_hashes function."""
    
    def test_generate_hashes_basic_functionality(self):
        """Test that all hash algorithms are generated for basic input."""
        plaintext = "hello world"
        result = generate_hashes(plaintext)
        
        # Check that all expected hash types are present
        expected_keys = {
            'SHA256', 'GOST_R_34_11_94', 'SHA384', 
            'SHA3_256', 'Keccak_256', 'SHA256_MD5'
        }
        assert set(result.keys()) == expected_keys
        
        # Check that all values are non-empty strings
        for algorithm, hash_value in result.items():
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
            assert hash_value.isalnum()  # Should be hexadecimal
    
    def test_sha256_correctness(self):
        """Test SHA256 hash correctness against known values."""
        plaintext = "hello world"
        result = generate_hashes(plaintext)
        
        # Verify against manually calculated SHA256
        expected_sha256 = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        assert result['SHA256'] == expected_sha256
    
    def test_sha384_correctness(self):
        """Test SHA384 hash correctness against known values."""
        plaintext = "test"
        result = generate_hashes(plaintext)
        
        # Verify against manually calculated SHA384
        expected_sha384 = hashlib.sha384(plaintext.encode('utf-8')).hexdigest()
        assert result['SHA384'] == expected_sha384
    
    def test_sha3_256_correctness(self):
        """Test SHA3-256 hash correctness against known values."""
        plaintext = "abc"
        result = generate_hashes(plaintext)
        
        # Verify against manually calculated SHA3-256
        expected_sha3_256 = hashlib.sha3_256(plaintext.encode('utf-8')).hexdigest()
        assert result['SHA3_256'] == expected_sha3_256
    
    def test_sha256_md5_correctness(self):
        """Test SHA256(MD5()) hash correctness."""
        plaintext = "password123"
        result = generate_hashes(plaintext)
        
        # Manually calculate SHA256(MD5())
        md5_hash = hashlib.md5(plaintext.encode('utf-8'))
        expected_sha256_md5 = hashlib.sha256(md5_hash.digest()).hexdigest()
        assert result['SHA256_MD5'] == expected_sha256_md5
    
    def test_empty_string_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Input string cannot be empty"):
            generate_hashes("")
    
    def test_non_string_input_error(self):
        """Test that non-string input raises TypeError."""
        with pytest.raises(TypeError, match="Input must be a string"):
            generate_hashes(123)
        
        with pytest.raises(TypeError, match="Input must be a string"):
            generate_hashes(None)
        
        with pytest.raises(TypeError, match="Input must be a string"):
            generate_hashes(['hello'])
    
    def test_unicode_string_handling(self):
        """Test that Unicode strings are handled correctly."""
        unicode_text = "Hello 世界! 🌍"
        result = generate_hashes(unicode_text)
        
        # Should not raise exceptions and should produce valid hashes
        assert len(result) == 6
        for hash_value in result.values():
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
    
    def test_long_string_handling(self):
        """Test handling of very long strings."""
        long_text = "a" * 10000
        result = generate_hashes(long_text)
        
        # Should handle long strings without issues
        assert len(result) == 6
        for hash_value in result.values():
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
    
    def test_special_characters(self):
        """Test handling of strings with special characters."""
        special_text = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        result = generate_hashes(special_text)
        
        assert len(result) == 6
        for hash_value in result.values():
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
    
    def test_hash_consistency(self):
        """Test that same input produces same hash consistently."""
        plaintext = "consistency_test"
        
        result1 = generate_hashes(plaintext)
        result2 = generate_hashes(plaintext)
        
        assert result1 == result2
    
    def test_different_inputs_different_hashes(self):
        """Test that different inputs produce different hashes."""
        text1 = "input1"
        text2 = "input2"
        
        result1 = generate_hashes(text1)
        result2 = generate_hashes(text2)
        
        # All hashes should be different
        for algorithm in result1.keys():
            assert result1[algorithm] != result2[algorithm]


class TestPrintHashes:
    """Test cases for the print_hashes function."""
    
    def test_print_hashes_output_format(self, capsys):
        """Test that print_hashes produces correctly formatted output."""
        plaintext = "test"
        print_hashes(plaintext)
        
        captured = capsys.readouterr()
        output = captured.out
        
        # Check that output contains expected elements
        assert "Input: test" in output
        assert "Hash Results:" in output
        assert "SHA256" in output
        assert "GOST_R_34_11_94" in output
        assert "SHA384" in output
        assert "SHA3_256" in output
        assert "Keccak_256" in output
        assert "SHA256_MD5" in output
    
    def test_print_hashes_error_handling(self, capsys):
        """Test error handling in print_hashes."""
        # Test with invalid input
        print_hashes("")
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "Error:" in output
        assert "cannot be empty" in output


class TestHashLengths:
    """Test that hash lengths are correct for each algorithm."""
    
    def test_hash_lengths(self):
        """Test that each hash algorithm produces correct length output."""
        plaintext = "length_test"
        result = generate_hashes(plaintext)
        
        # SHA256: 64 hex characters (32 bytes * 2)
        assert len(result['SHA256']) == 64
        
        # SHA384: 96 hex characters (48 bytes * 2)
        assert len(result['SHA384']) == 96
        
        # SHA3-256: 64 hex characters (32 bytes * 2)
        assert len(result['SHA3_256']) == 64
        
        # Keccak-256: 64 hex characters (32 bytes * 2)
        assert len(result['Keccak_256']) == 64
        
        # SHA256(MD5): 64 hex characters (32 bytes * 2)
        assert len(result['SHA256_MD5']) == 64
        
        # GOST: 64 hex characters (32 bytes * 2)
        assert len(result['GOST_R_34_11_94']) == 64


class TestAcceptanceCriteria:
    """Acceptance tests based on user requirements."""
    
    def test_all_required_algorithms_present(self):
        """
        Acceptance Criteria: Function must support all specified algorithms:
        - SHA256
        - GOST R 34.11-94  
        - SHA384
        - SHA3-256
        - Keccak-256
        - sha256(md5($plaintext))
        """
        plaintext = "acceptance_test"
        result = generate_hashes(plaintext)
        
        required_algorithms = {
            'SHA256', 'GOST_R_34_11_94', 'SHA384',
            'SHA3_256', 'Keccak_256', 'SHA256_MD5'
        }
        
        assert set(result.keys()) == required_algorithms
    
    def test_labeled_output(self):
        """
        Acceptance Criteria: Hashes must be labeled.
        """
        plaintext = "labeled_test"
        result = generate_hashes(plaintext)
        
        # Result should be a dictionary with string keys (labels)
        assert isinstance(result, dict)
        for key in result.keys():
            assert isinstance(key, str)
            assert len(key) > 0
    
    def test_string_input_string_output(self):
        """
        Acceptance Criteria: Function receives string, produces string hashes.
        """
        plaintext = "string_test"
        result = generate_hashes(plaintext)
        
        # All hash values should be strings
        for hash_value in result.values():
            assert isinstance(hash_value, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 
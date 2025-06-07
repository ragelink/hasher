#!/usr/bin/env python3
"""
Command Line Interface for Hash Generator

Provides CLI access to generate multiple cryptographic hashes from input strings.
Supports command line arguments, stdin input, and flexible output formatting.
"""

import argparse
import sys
from typing import List, Optional
from hasher import generate_hashes, print_hashes


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description='Generate multiple cryptographic hashes from input text',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "hello world"                    # Hash a string
  %(prog)s --stdin                          # Read from stdin
  %(prog)s "test" --algorithms SHA256,SHA384 # Only specific algorithms
  %(prog)s "test" --format json             # JSON output format
  echo "hello" | %(prog)s --stdin           # Pipe input
  
Supported algorithms:
  SHA256, GOST_R_34_11_94, SHA384, SHA3_256, Keccak_256, SHA256_MD5
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument(
        'text',
        nargs='?',
        help='Text to hash'
    )
    input_group.add_argument(
        '--stdin',
        action='store_true',
        help='Read input from stdin'
    )
    
    # Algorithm selection
    parser.add_argument(
        '--algorithms', '-a',
        type=str,
        help='Comma-separated list of algorithms to use (default: all)',
        default=None
    )
    
    # Output formatting
    parser.add_argument(
        '--format', '-f',
        choices=['table', 'json', 'simple'],
        default='table',
        help='Output format (default: table)'
    )
    
    # Quiet mode
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Only output hash values (one per line)'
    )
    
    # Show algorithms
    parser.add_argument(
        '--list-algorithms',
        action='store_true',
        help='List available algorithms and exit'
    )
    
    return parser


def filter_algorithms(hashes: dict, algorithms: Optional[str]) -> dict:
    """Filter hash results based on specified algorithms."""
    if algorithms is None:
        return hashes
    
    requested = [alg.strip() for alg in algorithms.split(',')]
    filtered = {}
    
    for alg in requested:
        if alg in hashes:
            filtered[alg] = hashes[alg]
        else:
            available = ', '.join(hashes.keys())
            sys.stderr.write(f"Warning: Algorithm '{alg}' not available. "
                           f"Available: {available}\n")
    
    return filtered


def format_output(hashes: dict, format_type: str, input_text: str, quiet: bool) -> str:
    """Format the hash output according to the specified format."""
    if quiet:
        return '\n'.join(hashes.values())
    
    if format_type == 'json':
        import json
        output_data = {
            'input': input_text,
            'hashes': hashes
        }
        return json.dumps(output_data, indent=2)
    
    elif format_type == 'simple':
        lines = [f"Input: {input_text}", ""]
        for algorithm, hash_value in hashes.items():
            lines.append(f"{algorithm}: {hash_value}")
        return '\n'.join(lines)
    
    else:  # table format (default)
        lines = [f"Input: {input_text}", "", "Hash Results:"]
        lines.append("=" * 70)
        
        for algorithm, hash_value in hashes.items():
            lines.append(f"{algorithm:<15}: {hash_value}")
        
        return '\n'.join(lines)


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle --list-algorithms
    if args.list_algorithms:
        sample_hashes = generate_hashes("test")
        print("Available algorithms:")
        for alg in sample_hashes.keys():
            print(f"  {alg}")
        return
    
    # Check if input is provided
    if not args.text and not args.stdin:
        sys.stderr.write("Error: Must provide either text argument or --stdin\n")
        parser.print_help()
        sys.exit(1)
    
    # Get input text
    if args.stdin:
        try:
            input_text = sys.stdin.read().strip()
            if not input_text:
                sys.stderr.write("Error: No input provided via stdin\n")
                sys.exit(1)
        except KeyboardInterrupt:
            sys.stderr.write("\nOperation cancelled\n")
            sys.exit(1)
    else:
        input_text = args.text
        if not input_text:
            sys.stderr.write("Error: No input text provided\n")
            sys.exit(1)
    
    # Generate hashes
    try:
        all_hashes = generate_hashes(input_text)
        filtered_hashes = filter_algorithms(all_hashes, args.algorithms)
        
        if not filtered_hashes:
            sys.stderr.write("Error: No valid algorithms specified\n")
            sys.exit(1)
        
        # Format and output results
        output = format_output(filtered_hashes, args.format, input_text, args.quiet)
        print(output)
        
    except (ValueError, TypeError, RuntimeError) as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\nOperation cancelled\n")
        sys.exit(1)


if __name__ == "__main__":
    main() 
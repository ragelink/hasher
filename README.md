# Hash Generator

A Python library abstraction that generates multiple cryptographic hashes from input strings using various algorithms.

## Supported Hash Algorithms

- **SHA256**: Standard SHA-256 hash
- **GOST R 34.11-94**: Russian cryptographic standard (using GOST R 34.11-2012 256-bit)
- **SHA384**: Standard SHA-384 hash
- **SHA3-256**: SHA3-256 hash
- **Keccak-256**: Keccak-256 hash (Ethereum-style)
- **SHA256(MD5)**: Double hash - SHA256 of MD5 hash

## Installation

### Prerequisites
- Python 3.8+
- Virtual environment (recommended)

### Setup

1. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # or
   venv\Scripts\activate     # On Windows
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```python
from hasher import generate_hashes, print_hashes

# Generate all hashes for a string
hashes = generate_hashes("hello world")

# Print results in formatted output
print_hashes("hello world")
```

### Programmatic Usage

```python
from hasher import generate_hashes

# Get hash dictionary
plaintext = "my secret password"
hashes = generate_hashes(plaintext)

# Access individual hashes
sha256_hash = hashes['SHA256']
gost_hash = hashes['GOST_R_34_11_94']
keccak_hash = hashes['Keccak_256']

print(f"SHA256: {sha256_hash}")
print(f"GOST: {gost_hash}")
print(f"Keccak-256: {keccak_hash}")
```

### Command Line Usage

The package includes a comprehensive CLI interface:

```bash
# Basic usage
python cli.py "hello world"

# Use specific algorithms only
python cli.py "test" --algorithms SHA256,Keccak_256

# JSON output format
python cli.py "secret" --format json

# Read from stdin
echo "hello" | python cli.py --stdin

# Quiet mode (only hash values)
python cli.py "test" --quiet

# List available algorithms
python cli.py --list-algorithms

# Simple format
python cli.py "test" --format simple
```

#### CLI Options

- `text`: Text to hash (positional argument)
- `--stdin`: Read input from stdin
- `--algorithms, -a`: Comma-separated list of algorithms to use
- `--format, -f`: Output format (table, json, simple)
- `--quiet, -q`: Only output hash values
- `--list-algorithms`: List available algorithms and exit
- `--help, -h`: Show help message

## Function Reference

### `generate_hashes(plaintext: str) -> Dict[str, str]`

Generate multiple hash algorithms for the given plaintext string.

**Parameters:**
- `plaintext` (str): The input string to hash

**Returns:**
- Dictionary containing labeled hashes with keys:
  - `SHA256`: Standard SHA-256 hash
  - `GOST_R_34_11_94`: Russian GOST R 34.11-94 hash
  - `SHA384`: Standard SHA-384 hash
  - `SHA3_256`: SHA3-256 hash
  - `Keccak_256`: Keccak-256 hash
  - `SHA256_MD5`: SHA256 of MD5 hash

**Raises:**
- `TypeError`: If plaintext is not a string
- `ValueError`: If plaintext is empty
- `RuntimeError`: If hash generation fails

### `print_hashes(plaintext: str) -> None`

Generate and print all hashes in a formatted way.

**Parameters:**
- `plaintext` (str): The input string to hash

## Testing

Run the test suite:

```bash
# Run all tests
pytest test_hasher.py -v

# Run with coverage
pytest test_hasher.py --cov=hasher --cov-report=html
```

## Development

### Code Standards
- Follows PEP 8 style guide
- Comprehensive docstrings
- Type hints throughout
- Comprehensive error handling
- 100% test coverage

### Project Structure
```
hasher/
├── hasher.py           # Main hash generation module
├── cli.py              # Command line interface
├── example.py          # Usage examples
├── test_hasher.py      # Comprehensive test suite
├── requirements.txt    # Project dependencies
├── .gitignore          # Git ignore rules
├── LICENSE             # MIT License
└── README.md          # This file
```

## Dependencies

- `pycryptodome==3.19.0`: For Keccak-256 hashing
- `pygost==5.10`: For GOST R 34.11-94 hashing
- `pytest==7.4.3`: For testing
- `pytest-cov==4.1.0`: For test coverage

## Security Considerations

- All hash functions use UTF-8 encoding for consistent results
- Input validation prevents common attack vectors
- Comprehensive error handling prevents information leakage
- Uses well-established cryptographic libraries

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Use responsibly for legitimate cryptographic purposes.

## Contributing

1. Ensure all tests pass
2. Maintain 100% test coverage
3. Follow PEP 8 style guidelines
4. Add tests for new features
5. Update documentation accordingly 

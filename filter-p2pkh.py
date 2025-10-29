#!/usr/bin/env python3
"""
Bitcoin Address Filter - Legacy P2PKH Extractor

Description:
	This script filters Bitcoin addresses to extract only Legacy P2PKH addresses
	(Pay-to-Public-Key-Hash) that start with '1'. It processes large files
	efficiently by streaming line-by-line instead of loading entire file into memory.

Purpose:
	Prepare address database for bitcoin-wallet-bruteforce-offline.go by removing
	incompatible address types (SegWit, Taproot, P2SH) that the brute force
	program doesn't generate.

Address Types:
	✓ Legacy P2PKH (starts with '1') - KEPT
	✗ P2SH (starts with '3') - FILTERED OUT
	✗ SegWit P2WPKH (starts with 'bc1q') - FILTERED OUT
	✗ Taproot P2TR (starts with 'bc1p') - FILTERED OUT

Performance:
	- Processes ~1M addresses per second
	- Memory usage: constant (line-by-line processing)
	- Can handle files of any size (tested with 27M+ addresses)

Cross-platform:
	Works on macOS, Linux, and Windows without modifications.

Author: David Zita
License: MIT
"""

import sys       # System-specific parameters and functions
import argparse  # Command-line argument parsing
import os        # Operating system interface (file operations)

def is_p2pkh_address(address):
    """
    Validate if a Bitcoin address is Legacy P2PKH format.
    
    Parameters:
        address (str): Bitcoin address to check
    
    Returns:
        bool: True if address is valid P2PKH, False otherwise
    
    Validation Criteria:
        1. Starts with '1' (Bitcoin mainnet P2PKH version byte 0x00)
        2. Length between 26-35 characters (typical P2PKH range)
        3. Contains only Base58 characters (Bitcoin's encoding alphabet)
    
    Base58 Alphabet:
        123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        (excludes: 0, O, I, l to avoid visual confusion)
    
    Examples:
        Valid P2PKH:
            - 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (Genesis block address)
            - 112PkhMPGH8xrdpHuKUhueQ2rwJ7uTqzAD
        
        Invalid (filtered out):
            - 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy (P2SH - starts with '3')
            - bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh (SegWit - starts with 'bc1q')
            - bc1p5d7rjq7g6rdk... (Taproot - starts with 'bc1p')
    
    Performance:
        This is a lightweight validation (not full checksum verification).
        Full validation would require:
        - Base58 decoding
        - Checksum verification (double SHA256)
        - Network byte validation
        
        For filtering purposes, this quick check is sufficient and much faster.
    """
    # Remove leading/trailing whitespace
    addr = address.strip()
    
    # Reject empty strings
    if not addr:
        return False
    
    # Check P2PKH criteria:
    # - First character must be '1' (mainnet P2PKH)
    # - Length must be in valid range (26-35 characters typical)
    if addr[0] == '1' and 26 <= len(addr) <= 35:
        # Verify all characters are valid Base58 (no 0, O, I, l)
        # Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        if all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in addr):
            return True
    
    return False

def filter_p2pkh(input_file, output_file):
    """
    Filter P2PKH addresses from input file and write to output file.
    
    Parameters:
        input_file (str): Path to input file containing Bitcoin addresses (one per line)
        output_file (str): Path to output file for filtered P2PKH addresses
    
    Algorithm:
        1. Open input and output files simultaneously
        2. Read input line-by-line (streaming, not loading into memory)
        3. Validate each address using is_p2pkh_address()
        4. Write valid P2PKH addresses to output file
        5. Display progress every 1 million lines
        6. Print final statistics
    
    Memory Efficiency:
        - Streaming approach: Only one line in memory at a time
        - Can handle files of any size (tested with 27M+ lines)
        - Memory usage: constant (~few MB) regardless of file size
        - Alternative approach (load all into memory) would require:
          * 27M addresses × ~50 bytes = ~1.35 GB RAM
    
    Cross-platform File Handling:
        Input (newline=''):
            - Python auto-detects line endings (Unix \\n, Windows \\r\\n, Mac \\r)
            - Universal newline mode ensures compatibility
        
        Output (newline='\\n'):
            - Forces Unix-style line endings (\\n)
            - Consistent output format on all platforms
            - Compatible with Go program expectations
    
    Encoding:
        - UTF-8: Universal text encoding (Bitcoin addresses are ASCII subset)
        - errors='ignore': Skip any malformed UTF-8 sequences (rare in address lists)
    
    Progress Reporting:
        - Updates every 1M lines to stderr (doesn't interfere with output)
        - Allows user to monitor progress on large files
        - Flush ensures immediate display (not buffered)
    
    Performance:
        - Processes ~1M addresses per second (CPU-dependent)
        - 27M addresses completed in ~30-40 seconds
        - Bottleneck: I/O and string validation, not CPU
    
    Error Handling:
        Handled by caller (try-except block wraps this function)
    """
    # Initialize counters
    total_lines = 0     # Total lines read from input
    p2pkh_count = 0     # Number of valid P2PKH addresses found
    
    try:
        # Open both files simultaneously using context managers
        # Both files will be automatically closed when block exits
        
        # INPUT FILE (read mode):
        # - encoding='utf-8': Standard text encoding
        # - errors='ignore': Skip invalid UTF-8 bytes (continue processing)
        # - newline='': Universal newline mode (handles \\n, \\r\\n, \\r)
        
        # OUTPUT FILE (write mode):
        # - encoding='utf-8': Match input encoding
        # - newline='\\n': Force Unix line endings (cross-platform consistency)
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore', newline='') as infile, \
             open(output_file, 'w', encoding='utf-8', newline='\n') as outfile:
            
            # Process file line-by-line (streaming)
            # enumerate() provides line numbers starting from 1
            for line_num, line in enumerate(infile, 1):
                total_lines += 1
                
                # Progress indicator: Print update every 1 million lines
                # Output to stderr to separate from main output
                # flush=True ensures immediate display (not buffered)
                if line_num % 1000000 == 0:
                    print(f"Processed {line_num:,} lines, found {p2pkh_count:,} P2PKH addresses...", 
                          file=sys.stderr, flush=True)
                
                # Validate address
                if is_p2pkh_address(line):
                    # Write valid address to output file
                    # strip() removes leading/trailing whitespace
                    # Add newline for proper formatting
                    outfile.write(line.strip() + '\n')
                    p2pkh_count += 1
            
            # Print completion summary
            print(f"\n✓ Filtering complete!", file=sys.stderr)
            print(f"  Total lines processed: {total_lines:,}", file=sys.stderr)
            print(f"  P2PKH addresses found: {p2pkh_count:,}", file=sys.stderr)
            print(f"  Output saved to: {output_file}", file=sys.stderr)
            
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied. Cannot read '{input_file}' or write to '{output_file}'.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error: OS error - {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    """
    Main entry point for the Bitcoin address filter script.
    
    Workflow:
        1. Parse command-line arguments
        2. Validate input file existence
        3. Normalize file paths (cross-platform)
        4. Execute filtering operation
        5. Display results
    
    Command-line Interface:
        Required:
            input_file: Path to file containing Bitcoin addresses
        
        Optional:
            -o, --output: Path to output file (default: attack-addresses-p2pkh.txt)
    
    Exit Codes:
        0: Success
        1: Error (file not found, permission denied, etc.)
    
    Usage Examples:
        macOS/Linux:
            python3 filter-p2pkh.py addresses.txt
            python3 filter-p2pkh.py addresses.txt -o filtered.txt
            ./filter-p2pkh.py addresses.txt
        
        Windows:
            python filter-p2pkh.py addresses.txt
            py filter-p2pkh.py addresses.txt -o filtered.txt
    """
    # ========================================================================
    # ARGUMENT PARSER SETUP
    # ========================================================================
    
    # Create argument parser with detailed help text
    parser = argparse.ArgumentParser(
        description='Filter Legacy P2PKH Bitcoin addresses (starting with "1") from a file.',
        epilog='Cross-platform: Works on macOS, Linux, and Windows.\n'
               '\n'
               'Examples:\n'
               '  python filter-p2pkh.py addresses.txt\n'
               '  python filter-p2pkh.py addresses.txt -o output.txt\n'
               '  python3 filter-p2pkh.py addresses.txt\n'
               '  py filter-p2pkh.py addresses.txt (Windows)\n'
               '\n'
               'Use Case:\n'
               '  Prepare address database for bitcoin-wallet-bruteforce-offline.go\n'
               '  by removing incompatible address types (SegWit, Taproot, P2SH).',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required argument: input file path
    parser.add_argument('input_file', 
                       help='Input file with Bitcoin addresses (one per line)')
    
    # Optional argument: output file path
    parser.add_argument('-o', '--output', 
                       default='attack-addresses-p2pkh.txt',
                       help='Output file for filtered addresses (default: attack-addresses-p2pkh.txt)')
    
    # Parse command-line arguments
    args = parser.parse_args()
    
    # ========================================================================
    # PATH NORMALIZATION (Cross-platform compatibility)
    # ========================================================================
    
    # Normalize paths to handle different OS path separators
    # Windows: C:\path\to\file.txt (backslashes)
    # Unix/Mac: /path/to/file.txt (forward slashes)
    # os.path.normpath() converts to OS-appropriate format
    input_file = os.path.normpath(args.input_file)
    output_file = os.path.normpath(args.output)
    
    # ========================================================================
    # INPUT VALIDATION
    # ========================================================================
    
    # Check if input file exists before starting processing
    # Fail fast to avoid wasting time on non-existent file
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    # ========================================================================
    # STATUS INFORMATION
    # ========================================================================
    
    # Display what the script is about to do
    print(f"Filtering P2PKH addresses from '{input_file}'...", file=sys.stderr)
    print(f"Output will be saved to '{output_file}'...\n", file=sys.stderr)
    
    # ========================================================================
    # EXECUTE FILTERING
    # ========================================================================
    
    # Call main filtering function
    # Exceptions are handled within filter_p2pkh() function
    filter_p2pkh(input_file, output_file)

if __name__ == '__main__':
    main()


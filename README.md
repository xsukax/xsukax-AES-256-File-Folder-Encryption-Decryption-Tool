# **xsukax AES-256 File & Folder Encryptor & Decryptor**

## **General Description**

### **What is xsukax AES-256 File & Folder Encryptor & Decryptor**

xsukax AES-256 File & Folder Encryptor & Decryptor is a comprehensive Python application that provides military-grade encryption for both individual files and entire folder structures. Available in both GUI and CLI modes, this tool makes advanced cryptography accessible to users of all technical levels while offering maximum performance through TAR archiving.

![](https://raw.githubusercontent.com/xsukax/xsukax-AES-256-File-Folder-Encryptor-Decryptor/refs/heads/main/screenshot.png)

### **Core Functionality**

The application offers four distinct operation modes:

1. **📄🔒 File Encryption**: Transform any file into a secure `.enc` file with streaming encryption
2. **📄🔓 File Decryption**: Restore encrypted files to their original format with perfect filename preservation
3. **📁🔒 Folder Encryption**: Archive folders using TAR (no compression) and encrypt into a single secure file
4. **📁🔓 Folder Decryption**: Extract encrypted folders while maintaining complete directory structure

### **Key Features**

- **Dual Interface**: Full-featured GUI and powerful CLI with smart auto-detection
- **TAR Archiving**: Fast folder processing without compression overhead (30-50% faster than ZIP)
- **Enterprise-Grade Security**: AES-256-CBC encryption with PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Interactive Password Entry**: Secure password prompts that never appear in command history
- **Auto-Generated Output Names**: Smart naming system - no need to specify output paths
- **Dynamic Chunk Sizing**: Automatically optimizes processing based on file size (64KB to 1MB chunks)
- **Multi-Stage Progress Tracking**: Smooth, accurate progress bars with separate stages for archiving/encryption
- **Real-Time Performance Metrics**: Live speed monitoring in MB/s during operations
- **Password Strength Checker**: Built-in analyzer with visual feedback and suggestions
- **Safe Cancellation**: Ability to safely cancel operations with proper cleanup
- **Cross-Platform**: Works on Windows, macOS, and Linux systems

### **Version 4.0 Improvements**

- **TAR Instead of ZIP**: No compression overhead - encryption provides the security
- **Interactive Passwords Only**: Removed file-based passwords for better security
- **Simplified CLI**: Short flags (`-e` for encrypt, `-d` for decrypt)
- **Smart Auto-Detection**: Automatically determines file vs folder operations
- **Better PowerShell Support**: Proper handling of paths with spaces
- **Performance Boost**: 30-50% faster folder operations with TAR

## **Installation**

### **Requirements**

- Python 3.7 or higher (3.9+ recommended)
- Single external dependency: `cryptography`

### **Quick Install**

```bash
# Install the required package
pip install cryptography

# Download the script
git clone https://github.com/xsukax/xsukax-AES-256-File-Folder-Encryptor-Decryptor
cd xsukax-AES-256-File-Folder-Encryptor-Decryptor

# Run the application
python xsukax-enc-dec.py  # Opens GUI
python xsukax-enc-dec.py -h  # Shows CLI help
```

### **Linux Additional Setup**

```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora/RHEL/CentOS
sudo dnf install python3-tkinter
```

## **Usage Instructions**

### **GUI Mode**

Simply run the script without arguments to open the graphical interface:

```bash
python xsukax-enc-dec.py
```

**GUI Features:**
- Visual file/folder selection with browse dialogs
- Real-time password strength indicator with color coding
- Live progress bars with stage indicators
- Detailed operation logs with performance metrics
- Show/hide password toggle
- Automatic output path generation

### **CLI Mode**

The CLI provides powerful command-line functionality with interactive password prompts:

#### **Basic Syntax**

```bash
python xsukax-enc-dec.py [-e | -d] input [-o output] [options]
```

#### **CLI Options**

| Option | Description |
|--------|-------------|
| `-e, --encrypt` | Encrypt the input file or folder |
| `-d, --decrypt` | Decrypt the input file or folder |
| `-o, --output` | Specify output path (optional - auto-generated if omitted) |
| `--file` | Explicitly specify input is a file |
| `--folder` | Explicitly specify input is a folder |
| `-f, --force` | Overwrite output without prompting |
| `-q, --quiet` | Minimal output - suppress progress and logs |
| `--check-strength` | Check password strength during encryption |
| `-h, --help` | Show help message with examples |

#### **CLI Examples**

**Simple File Operations (Auto-Generated Output):**

```bash
# Encrypt a file (creates file.txt.enc)
python xsukax-enc-dec.py -e file.txt
Enter password: [hidden]
Confirm password: [hidden]

# Decrypt a file (creates file.txt)
python xsukax-enc-dec.py -d file.txt.enc
Enter password: [hidden]

# Encrypt with password strength check
python xsukax-enc-dec.py -e document.pdf --check-strength
Enter password: [hidden]
Confirm password: [hidden]
Password strength: Weak
Suggestions: Add special characters, 12+ characters recommended
Continue anyway? (y/N): 
```

**Folder Operations:**

```bash
# Encrypt a folder (creates MyFolder.enc using TAR)
python xsukax-enc-dec.py -e MyFolder
Enter password: [hidden]
Confirm password: [hidden]

# Decrypt a folder (extracts to MyFolder/)
python xsukax-enc-dec.py -d MyFolder.enc
Enter password: [hidden]

# Encrypt folder with spaces (PowerShell/Windows)
python xsukax-enc-dec.py -e "My Documents"
Enter password: [hidden]
Confirm password: [hidden]
```

**Advanced Usage:**

```bash
# Specify custom output
python xsukax-enc-dec.py -e sensitive.doc -o backup.enc
Enter password: [hidden]
Confirm password: [hidden]

# Force overwrite existing files
python xsukax-enc-dec.py -e data.xlsx -f
Enter password: [hidden]
Confirm password: [hidden]

# Quiet mode (minimal output)
python xsukax-enc-dec.py -e large_file.iso -q
Enter password: [hidden]
Confirm password: [hidden]

# Explicit file type (useful for ambiguous cases)
python xsukax-enc-dec.py -d archive.enc --file
Enter password: [hidden]

# Explicit folder type for extraction
python xsukax-enc-dec.py -d backup.enc --folder -o RestoredFolder
Enter password: [hidden]
```

**PowerShell Examples (Windows):**

```powershell
# Folders with spaces - use double quotes
python .\xsukax-enc-dec.py -e "Python Books 2"
python .\xsukax-enc-dec.py -d "Python Books 2.enc"

# With explicit type specification
python .\xsukax-enc-dec.py -e "My Documents" --folder
python .\xsukax-enc-dec.py -d "My Documents.enc" --folder

# Force overwrite
python .\xsukax-enc-dec.py -e "Important Files" -f
```

## **Operation Workflows**

### **File Encryption Workflow**

1. **Input Selection**: Choose file via GUI browse or CLI path
2. **Password Entry**: Enter password (hidden) with confirmation for encryption
3. **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
4. **Encryption Process**: 
   - Generate random salt (16 bytes) and IV (16 bytes)
   - Stream file through AES-256-CBC cipher
   - Apply PKCS7 padding
   - Write to temporary file then rename (safe against interruption)
5. **Output**: Original filename preserved with `.enc` extension

**Example Output:**
```
📝 Encrypting: document.pdf → document.pdf.enc
⚡ Using 256KB chunks for optimal performance
[====================] 100.0% - Encryption completed!
⚡ Performance: 125.3 MB/s
⏱️ Time: 2.4 seconds
✅ File encrypted successfully: document.pdf.enc
```

### **Folder Encryption Workflow**

1. **Folder Analysis**: Calculate total size and file count
2. **TAR Archiving** (Stage 1 - 40%):
   - Create uncompressed TAR archive
   - Preserve directory structure
   - Include empty directories
   - No compression overhead for speed
3. **Encryption** (Stage 2 - 60%):
   - Encrypt TAR archive with AES-256-CBC
   - Stream processing for large archives
4. **Cleanup**: Remove temporary TAR file

**Example Output:**
```
📁 Encrypting folder: MyProject
📊 Total size: 156.3 MB, 1,247 files
📦 Using TAR archiving (no compression) for speed
Stage 1/2: TAR Archiving
[========            ] 40.0% - Archiving 1247/1247 files (45.2 MB/s)
Stage 2/2: Encryption
[====================] 100.0% - Encrypting archive (78.5 MB/s)
⚡ Performance: 52.1 MB/s
⏱️ Time: 3.0 seconds
✅ Folder encrypted successfully: MyProject.enc
```

### **Decryption Workflow**

**Files:**
1. Read salt and IV from encrypted file
2. Derive key using password
3. Stream decrypt with automatic padding removal
4. Restore original filename (removes `.enc`)

**Folders:**
1. **Decryption** (Stage 1 - 60%): Decrypt to temporary TAR
2. **Extraction** (Stage 2 - 40%): Extract TAR preserving structure
3. Restore all files, folders, and empty directories

## **Technical Specifications**

### **Encryption Details**

- **Algorithm**: AES-256 in CBC mode
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Salt Size**: 128 bits (16 bytes)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000
- **Padding**: PKCS7
- **Block Size**: 128 bits

### **Performance Optimizations**

**Dynamic Chunk Sizing:**
- Files < 1MB: 64KB chunks
- Files < 100MB: 256KB chunks
- Files < 1GB: 512KB chunks
- Files ≥ 1GB: 1MB chunks

**TAR vs ZIP Performance:**
- 30-50% faster for folder operations
- No CPU cycles wasted on compression
- Lower memory footprint
- AES provides all necessary security

### **File Format Structure**

**Encrypted File Layout:**
```
[Salt (16 bytes)][IV (16 bytes)][Encrypted Data with PKCS7 Padding]
```

**Encrypted Folder Structure:**
```
[Salt (16 bytes)][IV (16 bytes)][Encrypted TAR Archive]
```

## **Security Considerations**

### **Password Requirements**

**Minimum Recommendations:**
- Length: 12+ characters
- Include: uppercase, lowercase, numbers, symbols
- Avoid: dictionary words, personal information

**Password Strength Indicator:**
- Score calculation based on length and complexity
- Real-time visual feedback (color-coded)
- Specific improvement suggestions
- Warning prompts for weak passwords

### **Security Features**

- **No Password Storage**: Passwords never saved to disk or command history
- **Interactive Entry Only**: Uses `getpass` for hidden input
- **Secure Random Generation**: Uses `secrets` module for salt/IV
- **Memory Security**: Keys handled securely in memory
- **Safe File Operations**: Temporary files with atomic rename

### **Best Practices**

1. **Use Strong Passwords**: Follow the strength indicator recommendations
2. **Secure Password Storage**: Use a password manager for encryption passwords
3. **Backup Encrypted Files**: Keep copies of `.enc` files separately
4. **Test First**: Verify encryption/decryption with test files
5. **Regular Updates**: Keep `cryptography` library updated

## **Troubleshooting**

### **Common Issues**

**"Permission Denied" Errors:**
- **Windows**: Run as Administrator or choose user directories
- **Linux/Mac**: Use `sudo` or select writable locations
- **Solution**: Application auto-detects and offers alternative locations

**"Invalid encrypted file format" Error:**
- Wrong password entered
- File corrupted during transfer
- Not an encrypted file from this tool
- Solution: Verify password and file integrity

**PowerShell Path Issues:**
- Use double quotes for paths with spaces: `"My Folder"`
- Don't use trailing backslashes
- Use tab completion for accurate paths

**Large File Performance:**
- Files > 10GB may take several minutes
- Ensure sufficient disk space (2x file size)
- Monitor progress bar for status

### **Platform-Specific Notes**

**Windows:**
- PowerShell recommended over Command Prompt
- Use double quotes for paths with spaces
- Run as Administrator for system folders

**Linux:**
- Install `python3-tk` for GUI support
- Use terminal for better CLI experience
- Check file permissions for encryption targets

**macOS:**
- GUI requires XQuartz on some systems
- Use Terminal for CLI operations
- Grant disk access permissions if prompted

## **Performance Benchmarks**

Tested on standard hardware (Intel i5, 16GB RAM, SSD):

| Operation | File Size | Time | Speed |
|-----------|-----------|------|-------|
| File Encrypt | 100 MB | 0.8s | 125 MB/s |
| File Decrypt | 100 MB | 0.9s | 111 MB/s |
| Folder Encrypt (TAR) | 1 GB | 19s | 52 MB/s |
| Folder Decrypt (TAR) | 1 GB | 21s | 47 MB/s |
| Folder Encrypt (old ZIP) | 1 GB | 31s | 32 MB/s |

**TAR vs ZIP Improvement: ~35% faster on average**

## **Contributing**

Contributions are welcome! Please feel free to submit issues or pull requests on GitHub.

## **Acknowledgments**

- Built with Python's `cryptography` library
- GUI powered by `tkinter`
- TAR archiving via Python's `tarfile` module

---

**Version**: 4.0 - TAR Archiving & Interactive Passwords  
**Author**: xsukax  
**Repository**: [GitHub - xsukax-AES-256-File-Folder-Encryptor-Decryptor](https://github.com/xsukax/xsukax-AES-256-File-Folder-Encryptor-Decryptor)

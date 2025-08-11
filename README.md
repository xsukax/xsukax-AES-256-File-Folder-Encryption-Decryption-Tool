# **xsukax AES-256 File & Folder Encryptor & Decryptor**

## **General Description**

### **What is xsukax AES-256 File & Folder Encryptor & Decryptor**

xsukax AES-256 File & Folder Encryptor & Decryptor is a comprehensive Python application that provides military-grade encryption for both individual files and entire folder structures. Built with a modern graphical user interface (GUI), this tool makes advanced cryptography accessible to users of all technical levels.

### **Core Functionality**

The application offers four distinct operation modes:

1. **📄🔒 File Encryption**: Transform any file (documents, images, videos, etc.) into a secure `.enc` file
2. **📄🔓 File Decryption**: Restore encrypted files to their original format with perfect filename preservation
3. **📁🔒 Folder Encryption**: Compress and encrypt entire directory structures into a single secure archive
4. **📁🔓 Folder Decryption**: Extract encrypted folders while maintaining complete directory structure, including empty folders

### **Key Features**

- **Enterprise-Grade Security**: Uses AES-256-CBC encryption with PBKDF2-HMAC-SHA256 key derivation
- **User-Friendly Interface**: Clean, intuitive GUI with real-time progress tracking
- **Intelligent File Handling**: Automatically preserves file extensions and original filenames
- **Complete Folder Support**: Maintains directory structure, including empty folders and nested hierarchies
- **Permission Management**: Smart handling of file system permissions with automatic fallback options
- **Cancellation Support**: Ability to safely cancel long-running operations
- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux systems

### **Use Cases and Applications**

**Personal Use:**
- Securing sensitive documents (tax records, legal documents, personal photos)
- Creating encrypted backups of important files
- Protecting confidential information on shared computers
- Securing files before cloud storage or email transmission

**Professional Use:**
- Protecting client data and confidential business documents
- Securing intellectual property and trade secrets
- Creating encrypted archives for long-term storage
- Complying with data protection regulations (GDPR, HIPAA, etc.)

**Educational Use:**
- Teaching cryptography concepts with practical implementation
- Demonstrating secure file handling practices
- Learning about GUI development with Python

### **Why This Application Matters**

Traditional encryption tools often suffer from complexity, poor user experience, or limited functionality. This application bridges the gap by providing:

- **Simplicity**: No command-line knowledge required
- **Reliability**: Robust error handling and data integrity checks
- **Transparency**: Open-source Python code that can be audited for security
- **Flexibility**: Handles both individual files and complex folder structures
- **Performance**: Efficient processing with progress feedback for large operations

## **Detailed Usage Instructions**

### **Initial Setup and Interface Overview**

1. **Launch the Application**: Run the Python script to open the main interface
2. **Interface Elements**:
   - **Target Selection**: Choose between "📄 File" and "📁 Folder" modes
   - **Operation Selection**: Select "🔒 Encrypt" or "🔓 Decrypt"
   - **Path Entry**: Displays the selected file/folder path
   - **Browse Button**: Opens file/folder selection dialogs
   - **Password Fields**: Secure password entry with show/hide option
   - **Progress Section**: Real-time progress bar and status updates
   - **Results Log**: Detailed operation feedback and statistics

### **Example 1: File Encryption and Decryption Workflow**

**Scenario**: You need to encrypt a confidential PDF document before sending it via email.

**Step-by-Step File Encryption:**

1. **Select File Mode**: Click the "📄 File" radio button
2. **Choose Encryption**: Select "🔒 Encrypt" operation
3. **Browse for File**: Click "Browse File to Encrypt"
   - Navigate to your document (e.g., `contract.pdf`)
   - Select the file and click "Open"
4. **Set Password**: 
   - Enter a strong password in the "Password" field
   - Confirm the password in the "Confirm Password" field
   - Tip: Use a combination of letters, numbers, and symbols
5. **Start Encryption**: Click "🚀 Start Process"
6. **Monitor Progress**: Watch the green progress bar advance
7. **Handle Permissions**: If prompted, choose a save location for the encrypted file
8. **Completion**: The application creates `contract.pdf.enc`

**Expected Output**:
```
📝 Encrypting: contract.pdf → contract.pdf.enc
✅ File encrypted successfully: C:\Documents\contract.pdf.enc
💡 To decrypt: Select this .enc file and the original name will be restored
```

**Step-by-Step File Decryption:**

1. **Select File Mode**: Click "📄 File" radio button
2. **Choose Decryption**: Select "🔓 Decrypt" operation
3. **Browse for Encrypted File**: Click "Browse Encrypted File"
   - Navigate to `contract.pdf.enc`
   - Select the encrypted file and click "Open"
4. **Enter Password**: Input the same password used for encryption
5. **Start Decryption**: Click "🚀 Start Process"
6. **Automatic Restoration**: The application automatically restores `contract.pdf`

**Expected Output**:
```
📝 Decrypting: contract.pdf.enc → contract.pdf
📎 Original file extension restored: .pdf
✅ File decrypted successfully: C:\Documents\contract.pdf
```

### **Example 2: Folder Encryption and Decryption Workflow**

**Scenario**: You need to create an encrypted backup of a project folder containing multiple subdirectories, files, and some empty folders.

**Step-by-Step Folder Encryption:**

1. **Select Folder Mode**: Click the "📁 Folder" radio button
2. **Choose Encryption**: Select "🔒 Encrypt" operation
3. **Browse for Folder**: Click "Browse Folder to Encrypt"
   - Navigate to your project folder (e.g., `MyProject`)
   - Select the folder and click "Select Folder"
4. **Set Password**: Enter and confirm a strong password
5. **Start Encryption**: Click "🚀 Start Process"
6. **Monitor Detailed Progress**: 
   - Phase 1: "Calculating folder size..." (5%)
   - Phase 2: "Creating folder archive..." (10-50%)
   - Phase 3: "Encrypting folder..." (50-100%)
7. **Review Results**: The application creates `MyProject.enc`

**Expected Output**:
```
📁 Added empty folder: temp
📁 Added empty folder: docs/drafts
✅ Folder encrypted successfully: C:\Backup\MyProject.enc
📊 Original folder size: 45,678,901 bytes
📊 Processed 127 items (files + folders)
📊 Encrypted file size: 44,123,456 bytes
```

**Step-by-Step Folder Decryption:**

1. **Select Folder Mode**: Click "📁 Folder" radio button
2. **Choose Decryption**: Select "🔓 Decrypt" operation
3. **Browse for Encrypted File**: Click "Browse Encrypted Folder File"
   - Navigate to `MyProject.enc`
   - Select the encrypted file and click "Open"
4. **Enter Password**: Input the encryption password
5. **Start Decryption**: Click "🚀 Start Process"
6. **Choose Extraction Location**: 
   - A dialog will appear asking where to extract the folder
   - Select your desired destination (e.g., `C:\Restored\`)
   - The application will create `C:\Restored\MyProject\`
7. **Monitor Extraction Progress**:
   - Phase 1: "Decrypting folder data..." (10-60%)
   - Phase 2: "Extracting folder structure..." (70-100%)

**Expected Output**:
```
📁 Created empty folder: temp
📁 Created empty folder: docs/drafts
✅ Folder decrypted successfully to: C:\Restored\MyProject
📊 Extracted 124 files
📊 Created 3 directories (including empty ones)
📊 Total items restored: 127
```

## **Required Python Dependencies**

### **Core Dependencies**

The application requires only one external Python package, making installation straightforward:

```bash
pip install cryptography
```

**Version Compatibility**: The application is compatible with `cryptography` version 3.0 and above. The recommended version is 41.0.0 or later for optimal security and performance.

### **Built-in Dependencies**

The following modules are part of Python's standard library and require no additional installation:

- **`tkinter`**: GUI framework (included with most Python installations)
- **`os`**: Operating system interface
- **`sys`**: System-specific parameters and functions
- **`threading`**: Threading support for non-blocking operations
- **`zipfile`**: ZIP archive handling for folder compression
- **`io`**: Core I/O operations
- **`tempfile`**: Temporary file operations
- **`secrets`**: Cryptographically secure random number generation
- **`time`**: Time-related functions

### **Installation Verification**

To verify that all dependencies are properly installed, run this simple test:

```python
try:
    from cryptography.hazmat.primitives.ciphers import Cipher
    import tkinter as tk
    print("✅ All dependencies are correctly installed!")
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
```

### **Python Version Requirements**

- **Minimum Python Version**: Python 3.7
- **Recommended Python Version**: Python 3.9 or later
- **Platform Support**: Windows, macOS, Linux

**Note**: On some Linux distributions, you may need to install `python3-tk` separately:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# CentOS/RHEL/Fedora
sudo yum install tkinter
# or
sudo dnf install python3-tkinter
```

## **Important Notes**

### **Security Considerations**

**Password Strength**: The security of your encrypted files depends entirely on password strength. Use passwords that are:
- At least 12 characters long
- Include uppercase and lowercase letters
- Contain numbers and special characters
- Avoid dictionary words or personal information

**Key Derivation**: The application uses PBKDF2-HMAC-SHA256 with 100,000 iterations, providing strong protection against brute-force attacks. However, weak passwords remain the primary vulnerability.

**Memory Security**: The application handles encryption keys securely in memory, but cannot protect against advanced memory dump attacks. For maximum security, use the application on trusted systems.

### **Performance Considerations**

**File Size Limits**: While there are no hard limits, performance considerations include:
- **Small files** (< 100 MB): Near-instantaneous processing
- **Medium files** (100 MB - 1 GB): Processing time scales linearly
- **Large files** (> 1 GB): May require several minutes; progress bar provides feedback
- **Very large files** (> 10 GB): Consider available RAM and disk space

**Memory Usage**: The application uses efficient streaming for file operations, but folder encryption temporarily stores ZIP data in memory. For very large folders (> 4 GB), ensure adequate RAM is available.

**Disk Space**: Ensure sufficient free space for both the original and encrypted/decrypted files, especially when processing large folders.

### **Common Troubleshooting**

**Permission Errors**: 
- **Issue**: "Permission denied" when encrypting files on Desktop or system folders
- **Solution**: The application automatically detects permission issues and offers alternative save locations
- **Prevention**: Run as administrator or choose user-owned directories

**"Invalid encrypted file format" Error**:
- **Cause**: File corruption or incorrect file selection
- **Solution**: Verify you're selecting the correct `.enc` file and it hasn't been modified

**Memory Errors with Large Folders**:
- **Symptom**: Application crashes or becomes unresponsive
- **Solution**: Break large folders into smaller chunks or increase system RAM

**GUI Issues on Linux**:
- **Problem**: Interface appears corrupted or unresponsive
- **Solution**: Ensure `python3-tk` is properly installed

### **Best Practices**

1. **Backup Strategy**: Always keep the original `.enc` files until you verify successful decryption
2. **Password Management**: Use a reputable password manager to store encryption passwords
3. **Testing**: Test the encryption/decryption process with non-critical files first
4. **File Organization**: Consider organizing encrypted files in dedicated folders for easier management
5. **Regular Updates**: Keep the `cryptography` library updated for the latest security improvements

### **Additional Resources**

- **AES Encryption Standard**: [NIST Special Publication 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
- **PBKDF2 Key Derivation**: [RFC 2898](https://tools.ietf.org/html/rfc2898)
- **Python Cryptography Library**: [Official Documentation](https://cryptography.io/)
- **File System Security**: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

### **Support and Troubleshooting**

If you encounter issues not covered in this guide:

1. **Check Python Version**: Ensure you're using Python 3.7 or later
2. **Verify Dependencies**: Reinstall the cryptography package if needed
3. **Test with Small Files**: Verify basic functionality before processing large data
4. **Check System Resources**: Ensure adequate disk space and memory
5. **Review Logs**: The application provides detailed feedback in the results area

---

**Conclusion**

The AES-256 File & Folder Encryptor represents a perfect balance between security, functionality, and usability. By combining enterprise-grade encryption with an intuitive interface, it makes data protection accessible to everyone. Whether you're securing a single document or encrypting complex folder structures, this tool provides the reliability and features needed for comprehensive data protection.

Remember that encryption is only as strong as its weakest link—always use strong passwords, keep your encrypted files safe, and follow security best practices for maximum protection of your sensitive data.

#!/usr/bin/env python3
"""
xsukax AES-256 File Encryption/Decryption Tool - Enhanced Version

Features:
- Optional dependency checking with --check-deps flag
- GUI and CLI interfaces with smart auto-naming
- TAR archiving for folders (faster than ZIP)
- Interactive password prompt for better security
- Explicit --file and --folder flags for CLI
- Short options: -e for encrypt, -d for decrypt
- Smooth multi-stage progress tracking for folder operations
- High-performance streaming encryption/decryption

Author: AI Assistant
Date: 2025
Version: 4.1 - Optional Dependency Checking
"""

import os
import sys
import subprocess
import platform

# ============================================================================
# OPTIONAL DEPENDENCY INSTALLER
# ============================================================================

def check_and_install_dependencies():
    """Check and install all required dependencies when requested."""
    
    print("=" * 60)
    print("🔧 Checking and Installing Dependencies...")
    print("=" * 60)
    
    # Detect operating system
    os_type = platform.system()
    distro = ""
    
    if os_type == "Linux":
        try:
            # Try to detect Linux distribution
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release') as f:
                    os_info = f.read().lower()
                    if 'ubuntu' in os_info or 'debian' in os_info:
                        distro = "debian"
                    elif 'fedora' in os_info or 'rhel' in os_info or 'centos' in os_info or 'rocky' in os_info:
                        distro = "redhat"
                    elif 'arch' in os_info:
                        distro = "arch"
        except:
            pass
    
    # Check and install pip if needed
    try:
        import pip
        print("✅ pip is already installed")
    except ImportError:
        print("⚠️  pip is not installed. Installing pip...")
        try:
            if os_type == "Windows":
                # Download get-pip.py and run it
                import urllib.request
                urllib.request.urlretrieve('https://bootstrap.pypa.io/get-pip.py', 'get-pip.py')
                subprocess.check_call([sys.executable, 'get-pip.py'])
                os.remove('get-pip.py')
                print("✅ pip installed successfully")
            else:
                # On Unix-like systems, try using ensurepip first
                subprocess.check_call([sys.executable, '-m', 'ensurepip', '--upgrade'])
                print("✅ pip installed successfully")
        except Exception as e:
            print(f"❌ Failed to install pip automatically: {e}")
            print("Please install pip manually:")
            print("  Windows: python -m ensurepip --upgrade")
            print("  Linux/Mac: sudo apt-get install python3-pip (or equivalent)")
            sys.exit(1)
    
    # Check and install cryptography module
    try:
        import cryptography
        print("✅ cryptography module is already installed")
    except ImportError:
        print("⚠️  cryptography module is not installed. Installing...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cryptography'])
            print("✅ cryptography module installed successfully")
        except Exception as e:
            print(f"❌ Failed to install cryptography: {e}")
            print("Please run manually: pip install cryptography")
            sys.exit(1)
    
    # Check and install tkinter for Linux
    if os_type == "Linux":
        try:
            import tkinter
            print("✅ tkinter (python3-tk) is already installed")
        except ImportError:
            print("⚠️  tkinter is not installed. Installing for Linux...")
            
            install_commands = []
            
            if distro == "debian":
                install_commands = [
                    ['sudo', 'apt-get', 'update'],
                    ['sudo', 'apt-get', 'install', '-y', 'python3-tk']
                ]
                print("📦 Detected Ubuntu/Debian - using apt-get...")
            elif distro == "redhat":
                install_commands = [
                    ['sudo', 'dnf', 'install', '-y', 'python3-tkinter']
                ]
                print("📦 Detected Fedora/RHEL/CentOS - using dnf...")
            elif distro == "arch":
                install_commands = [
                    ['sudo', 'pacman', '-S', '--noconfirm', 'tk']
                ]
                print("📦 Detected Arch Linux - using pacman...")
            else:
                print("⚠️  Could not detect Linux distribution")
                print("Please install tkinter manually:")
                print("  Ubuntu/Debian: sudo apt-get install python3-tk")
                print("  Fedora/RHEL: sudo dnf install python3-tkinter")
                print("  Arch: sudo pacman -S tk")
                
            if install_commands:
                try:
                    for cmd in install_commands:
                        print(f"Running: {' '.join(cmd)}")
                        subprocess.check_call(cmd)
                    print("✅ tkinter installed successfully")
                    
                    # Try importing again to verify
                    import tkinter
                    print("✅ tkinter verified and working")
                except subprocess.CalledProcessError:
                    print("❌ Failed to install tkinter. You may need to enter your password.")
                    print("Please run the appropriate command manually:")
                    print("  Ubuntu/Debian: sudo apt-get install python3-tk")
                    print("  Fedora/RHEL: sudo dnf install python3-tkinter")
                    
                    # Ask if user wants to continue anyway (CLI mode will still work)
                    response = input("\nContinue without GUI support? (y/N): ")
                    if response.lower() != 'y':
                        sys.exit(1)
                except ImportError:
                    print("⚠️  tkinter installation completed but import still fails")
                    print("You may need to restart Python or install a different package")
                    response = input("\nContinue without GUI support? (y/N): ")
                    if response.lower() != 'y':
                        sys.exit(1)
    else:
        # For Windows and macOS, tkinter usually comes with Python
        try:
            import tkinter
            print("✅ tkinter is already installed")
        except ImportError:
            if os_type == "Windows":
                print("⚠️  tkinter is not installed on Windows")
                print("Please reinstall Python with tkinter support")
                print("Download from: https://python.org")
            elif os_type == "Darwin":  # macOS
                print("⚠️  tkinter is not installed on macOS")
                print("You may need to install python-tk via Homebrew:")
                print("  brew install python-tk")
            
            response = input("\nContinue without GUI support? (y/N): ")
            if response.lower() != 'y':
                sys.exit(1)
    
    print("=" * 60)
    print("✅ All dependency checks completed!")
    print("=" * 60)
    print()
    
    # Exit after dependency check
    print("Dependencies have been checked/installed.")
    print("Please run the program again without --check-deps to use it.")
    sys.exit(0)

# Run dependency check only if --check-deps flag is present
if __name__ == "__main__":
    if '--check-deps' in sys.argv:
        check_and_install_dependencies()

# Now import the required modules
import threading
import time
import tarfile
import io
import tempfile
import re
import shutil
import argparse
import getpass
from pathlib import Path
from typing import Optional, Callable, Tuple

try:
    from tkinter import *
    from tkinter import ttk, filedialog, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import secrets
except ImportError:
    print("\n" + "=" * 60)
    print("❌ Missing required dependencies!")
    print("=" * 60)
    print("\nThe cryptography module is not installed.")
    print("\nTo install dependencies automatically, run:")
    print(f"  python {sys.argv[0]} --check-deps")
    print("\nOr install manually:")
    print("  pip install cryptography")
    if os.name != 'nt':  # Not Windows
        print("  sudo apt-get install python3-tk  # For Ubuntu/Debian")
        print("  sudo dnf install python3-tkinter  # For Fedora/RHEL")
    print("=" * 60)
    sys.exit(1)


class AESEncryptionCore:
    """Core encryption/decryption engine used by both GUI and CLI."""
    
    def __init__(self, progress_callback: Optional[Callable] = None, 
                 log_callback: Optional[Callable] = None,
                 cancel_check: Optional[Callable] = None):
        """
        Initialize the encryption core.
        
        Args:
            progress_callback: Function to call with (percentage, message) for progress updates
            log_callback: Function to call with log messages
            cancel_check: Function that returns True if operation should be cancelled
        """
        self.backend = default_backend()
        self.key_length = 32  # 256 bits
        self.iv_length = 16   # 128 bits
        self.salt_length = 16  # 128 bits
        self.base_chunk_size = 65536  # 64KB base chunk size
        self.max_chunk_size = 1048576  # 1MB max chunk size
        
        # Callbacks for progress and logging
        self.progress_callback = progress_callback or self._default_progress
        self.log_callback = log_callback or self._default_log
        self.cancel_check = cancel_check or self._default_cancel_check
        
    def _default_progress(self, percentage: float, message: str):
        """Default progress callback (CLI mode)."""
        # Clear the line and print progress
        print(f"\r\033[K[{'='*int(percentage/2):50s}] {percentage:.1f}% - {message}", end='', flush=True)
        if percentage >= 100:
            print()  # New line at completion
    
    def _default_log(self, message: str):
        """Default log callback."""
        print(f"\n{message}")
    
    def _default_cancel_check(self) -> bool:
        """Default cancel check (never cancel)."""
        return False
    
    def get_optimal_chunk_size(self, file_size: int) -> int:
        """Get optimal chunk size based on file size."""
        if file_size < 1024 * 1024:  # < 1MB
            return self.base_chunk_size  # 64KB
        elif file_size < 100 * 1024 * 1024:  # < 100MB
            return 262144  # 256KB
        elif file_size < 1024 * 1024 * 1024:  # < 1GB
            return 524288  # 512KB
        else:  # >= 1GB
            return self.max_chunk_size  # 1MB
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a key from password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Encrypt a file.
        
        Returns:
            True if successful, False if cancelled or failed
        """
        try:
            # Get file size and optimal chunk size
            file_size = os.path.getsize(input_path)
            chunk_size = self.get_optimal_chunk_size(file_size)
            
            self.log_callback(f"📝 Encrypting: {os.path.basename(input_path)} → {os.path.basename(output_path)}")
            self.log_callback(f"⚡ Using {chunk_size//1024}KB chunks for optimal performance")
            
            start_time = time.time()
            processed_size = 0
            
            # Generate random salt and IV
            salt = secrets.token_bytes(self.salt_length)
            iv = secrets.token_bytes(self.iv_length)
            
            # Derive key from password
            key = self._derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Create padder
            padder = padding.PKCS7(128).padder()
            
            # Use temporary file for safe writing
            temp_output_path = output_path + '.tmp'
            
            try:
                with open(input_path, 'rb') as infile, open(temp_output_path, 'wb') as outfile:
                    # Write salt and IV
                    outfile.write(salt)
                    outfile.write(iv)
                    
                    last_progress = -1
                    
                    while True:
                        # Check for cancellation
                        if self.cancel_check():
                            self.log_callback("❌ Encryption cancelled by user")
                            if os.path.exists(temp_output_path):
                                os.remove(temp_output_path)
                            return False
                        
                        chunk = infile.read(chunk_size)
                        if len(chunk) == 0:
                            # Final chunk
                            padded_data = padder.finalize()
                            if padded_data:
                                encrypted_chunk = encryptor.update(padded_data)
                                outfile.write(encrypted_chunk)
                            encrypted_final = encryptor.finalize()
                            outfile.write(encrypted_final)
                            break
                        elif len(chunk) < chunk_size:
                            # Last chunk with data
                            padded_chunk = padder.update(chunk)
                            padded_final = padder.finalize()
                            encrypted_chunk = encryptor.update(padded_chunk + padded_final)
                            outfile.write(encrypted_chunk)
                            encrypted_final = encryptor.finalize()
                            outfile.write(encrypted_final)
                            processed_size += len(chunk)
                            break
                        else:
                            # Regular chunk
                            padded_chunk = padder.update(chunk)
                            encrypted_chunk = encryptor.update(padded_chunk)
                            outfile.write(encrypted_chunk)
                            processed_size += len(chunk)
                        
                        # Update progress (only if changed by at least 1%)
                        progress = int((processed_size / file_size) * 100) if file_size > 0 else 100
                        if progress != last_progress:
                            elapsed = time.time() - start_time
                            if elapsed > 0:
                                speed = (processed_size / (1024 * 1024)) / elapsed
                                self.progress_callback(progress, f"Encrypting... ({speed:.1f} MB/s)")
                            else:
                                self.progress_callback(progress, "Encrypting...")
                            last_progress = progress
                
                # Move temp file to final location
                shutil.move(temp_output_path, output_path)
                
            except Exception as e:
                if os.path.exists(temp_output_path):
                    try:
                        os.remove(temp_output_path)
                    except:
                        pass
                raise e
            
            # Final progress update
            total_time = time.time() - start_time
            if total_time > 0:
                avg_speed = (file_size / (1024 * 1024)) / total_time
                self.log_callback(f"⚡ Performance: {avg_speed:.1f} MB/s")
                self.log_callback(f"⏱️ Time: {total_time:.1f} seconds")
            
            self.progress_callback(100, "Encryption completed!")
            self.log_callback(f"✅ File encrypted successfully: {output_path}")
            return True
            
        except Exception as e:
            self.log_callback(f"❌ Encryption failed: {str(e)}")
            return False
    
    def decrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Decrypt a file.
        
        Returns:
            True if successful, False if cancelled or failed
        """
        try:
            self.log_callback(f"📝 Decrypting: {os.path.basename(input_path)} → {os.path.basename(output_path)}")
            
            # Get file size and optimal chunk size
            file_size = os.path.getsize(input_path)
            actual_data_size = file_size - self.salt_length - self.iv_length
            chunk_size = self.get_optimal_chunk_size(file_size)
            self.log_callback(f"⚡ Using {chunk_size//1024}KB chunks for optimal performance")
            
            start_time = time.time()
            
            # Use temporary file for safe writing
            temp_output_path = output_path + '.tmp'
            
            try:
                with open(input_path, 'rb') as infile:
                    # Read salt and IV
                    salt = infile.read(self.salt_length)
                    iv = infile.read(self.iv_length)
                    
                    if len(salt) != self.salt_length or len(iv) != self.iv_length:
                        raise ValueError("Invalid encrypted file format")
                    
                    # Derive key from password
                    key = self._derive_key(password, salt)
                    
                    # Create cipher
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                    decryptor = cipher.decryptor()
                    
                    # For small files, decrypt all at once
                    if actual_data_size < 100 * 1024 * 1024:
                        self.progress_callback(10, "Reading encrypted data...")
                        encrypted_data = infile.read()
                        
                        self.progress_callback(50, "Decrypting data...")
                        decrypted_data = decryptor.update(encrypted_data)
                        decrypted_data += decryptor.finalize()
                        
                        self.progress_callback(80, "Removing padding...")
                        unpadder = padding.PKCS7(128).unpadder()
                        unpadded_data = unpadder.update(decrypted_data)
                        unpadded_data += unpadder.finalize()
                        
                        self.progress_callback(90, "Writing decrypted file...")
                        with open(temp_output_path, 'wb') as outfile:
                            outfile.write(unpadded_data)
                    else:
                        # For large files, use streaming
                        with open(temp_output_path, 'wb') as outfile:
                            decrypted_buffer = b''
                            processed_size = 0
                            last_progress = -1
                            
                            while True:
                                if self.cancel_check():
                                    self.log_callback("❌ Decryption cancelled by user")
                                    if os.path.exists(temp_output_path):
                                        os.remove(temp_output_path)
                                    return False
                                
                                chunk = infile.read(chunk_size)
                                if not chunk:
                                    break
                                
                                decrypted_chunk = decryptor.update(chunk)
                                decrypted_buffer += decrypted_chunk
                                processed_size += len(chunk)
                                
                                # Write all but the last 1KB to handle padding
                                if len(decrypted_buffer) > 1024:
                                    write_size = len(decrypted_buffer) - 1024
                                    outfile.write(decrypted_buffer[:write_size])
                                    decrypted_buffer = decrypted_buffer[write_size:]
                                
                                # Update progress
                                progress = int((processed_size / actual_data_size) * 100) if actual_data_size > 0 else 100
                                if progress != last_progress:
                                    elapsed = time.time() - start_time
                                    if elapsed > 0:
                                        speed = (processed_size / (1024 * 1024)) / elapsed
                                        self.progress_callback(progress, f"Decrypting... ({speed:.1f} MB/s)")
                                    else:
                                        self.progress_callback(progress, "Decrypting...")
                                    last_progress = progress
                            
                            # Handle final block with padding
                            self.progress_callback(95, "Finalizing decryption...")
                            decrypted_buffer += decryptor.finalize()
                            
                            unpadder = padding.PKCS7(128).unpadder()
                            unpadded_final = unpadder.update(decrypted_buffer)
                            unpadded_final += unpadder.finalize()
                            outfile.write(unpadded_final)
                
                # Move temp file to final location
                self.progress_callback(98, "Saving file...")
                shutil.move(temp_output_path, output_path)
                
            except ValueError as e:
                if os.path.exists(temp_output_path):
                    try:
                        os.remove(temp_output_path)
                    except:
                        pass
                
                if "padding" in str(e).lower() or "invalid" in str(e).lower():
                    raise ValueError("Decryption failed - incorrect password or corrupted file")
                else:
                    raise e
            except Exception as e:
                if os.path.exists(temp_output_path):
                    try:
                        os.remove(temp_output_path)
                    except:
                        pass
                raise e
            
            # Final updates
            total_time = time.time() - start_time
            if total_time > 0:
                avg_speed = (file_size / (1024 * 1024)) / total_time
                self.log_callback(f"⚡ Performance: {avg_speed:.1f} MB/s")
                self.log_callback(f"⏱️ Time: {total_time:.1f} seconds")
            
            self.progress_callback(100, "Decryption completed!")
            self.log_callback(f"✅ File decrypted successfully: {output_path}")
            return True
            
        except Exception as e:
            self.log_callback(f"❌ Decryption failed: {str(e)}")
            return False
    
    def encrypt_folder(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Encrypt a folder using TAR archiving (faster than ZIP).
        
        Returns:
            True if successful, False if cancelled or failed
        """
        try:
            self.log_callback(f"📁 Encrypting folder: {os.path.basename(input_path)}")
            
            # First, calculate total size and count files
            total_size = 0
            file_list = []
            for root, dirs, files in os.walk(input_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.exists(file_path):
                        try:
                            size = os.path.getsize(file_path)
                            total_size += size
                            relative_path = os.path.relpath(file_path, input_path)
                            file_list.append((file_path, relative_path, size))
                        except:
                            continue
            
            self.log_callback(f"📊 Total size: {total_size / (1024*1024):.1f} MB, {len(file_list)} files")
            self.log_callback(f"📦 Using TAR archiving (no compression) for speed")
            
            if total_size == 0:
                self.log_callback("⚠️ No files to encrypt in the folder")
                return False
            
            start_time = time.time()
            
            # Stage 1: Create TAR archive (0-40% progress)
            temp_tar_path = output_path + ".tmp.tar"
            
            try:
                self.progress_callback(0, "Starting TAR archiving...")
                
                # Use tar without compression for maximum speed
                with tarfile.open(temp_tar_path, 'w') as tar:
                    # Set dereference=False to handle symbolic links properly
                    processed_size = 0
                    last_progress = -1
                    
                    # Add all files and directories
                    for i, (file_path, relative_path, file_size) in enumerate(file_list):
                        if self.cancel_check():
                            self.log_callback("❌ Folder encryption cancelled")
                            return False
                        
                        try:
                            # Add file to TAR
                            tar.add(file_path, arcname=relative_path, recursive=False)
                            processed_size += file_size
                            
                            # Calculate progress for archiving stage (0-40%)
                            archive_progress = int((processed_size / total_size) * 40)
                            if archive_progress != last_progress:
                                elapsed = time.time() - start_time
                                if elapsed > 0:
                                    speed = (processed_size / (1024 * 1024)) / elapsed
                                    self.progress_callback(archive_progress, 
                                        f"Archiving {i+1}/{len(file_list)} files ({speed:.1f} MB/s)")
                                else:
                                    self.progress_callback(archive_progress, 
                                        f"Archiving {i+1}/{len(file_list)} files")
                                last_progress = archive_progress
                            
                        except Exception as e:
                            self.log_callback(f"Warning: Could not add {relative_path}: {e}")
                            continue
                    
                    # Also add empty directories
                    for root, dirs, files in os.walk(input_path):
                        for dir_name in dirs:
                            dir_path = os.path.join(root, dir_name)
                            relative_dir_path = os.path.relpath(dir_path, input_path)
                            try:
                                # Check if directory is empty
                                if not os.listdir(dir_path):
                                    tar.add(dir_path, arcname=relative_dir_path, recursive=False)
                                    self.log_callback(f"📁 Added empty folder: {relative_dir_path}")
                            except:
                                continue
                
                # Get TAR file size for encryption progress
                tar_size = os.path.getsize(temp_tar_path)
                self.progress_callback(40, f"Archive complete ({tar_size / (1024*1024):.1f} MB)")
                
                # Stage 2: Encrypt the TAR file (40-100% progress)
                self.log_callback(f"🔒 Starting encryption of TAR archive...")
                
                # Generate random salt and IV
                salt = secrets.token_bytes(self.salt_length)
                iv = secrets.token_bytes(self.iv_length)
                
                # Derive key from password
                key = self._derive_key(password, salt)
                
                # Create cipher
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                encryptor = cipher.encryptor()
                
                # Create padder
                padder = padding.PKCS7(128).padder()
                
                # Get optimal chunk size
                chunk_size = self.get_optimal_chunk_size(tar_size)
                
                # Encrypt the TAR file
                with open(temp_tar_path, 'rb') as tar_infile, open(output_path, 'wb') as outfile:
                    # Write salt and IV
                    outfile.write(salt)
                    outfile.write(iv)
                    
                    encrypted_size = 0
                    last_progress = 40
                    
                    while True:
                        if self.cancel_check():
                            self.log_callback("❌ Folder encryption cancelled")
                            if os.path.exists(output_path):
                                os.remove(output_path)
                            return False
                        
                        chunk = tar_infile.read(chunk_size)
                        
                        if len(chunk) == 0:
                            padded_final = padder.finalize()
                            if padded_final:
                                encrypted_chunk = encryptor.update(padded_final)
                                outfile.write(encrypted_chunk)
                            encrypted_final = encryptor.finalize()
                            outfile.write(encrypted_final)
                            break
                        elif len(chunk) < chunk_size:
                            padded_chunk = padder.update(chunk)
                            padded_final = padder.finalize()
                            encrypted_chunk = encryptor.update(padded_chunk + padded_final)
                            outfile.write(encrypted_chunk)
                            encrypted_final = encryptor.finalize()
                            outfile.write(encrypted_final)
                            encrypted_size += len(chunk)
                            break
                        else:
                            padded_chunk = padder.update(chunk)
                            encrypted_chunk = encryptor.update(padded_chunk)
                            outfile.write(encrypted_chunk)
                            encrypted_size += len(chunk)
                        
                        # Calculate progress for encryption stage (40-100%)
                        encryption_progress = 40 + int((encrypted_size / tar_size) * 60)
                        if encryption_progress != last_progress:
                            elapsed = time.time() - start_time
                            if elapsed > 0:
                                speed = (encrypted_size / (1024 * 1024)) / elapsed
                                self.progress_callback(encryption_progress, 
                                    f"Encrypting archive ({speed:.1f} MB/s)")
                            else:
                                self.progress_callback(encryption_progress, "Encrypting archive")
                            last_progress = encryption_progress
                
                self.progress_callback(100, "Encryption completed!")
                
            finally:
                # Clean up temp TAR
                if os.path.exists(temp_tar_path):
                    os.remove(temp_tar_path)
            
            # Final stats
            total_time = time.time() - start_time
            if total_time > 0:
                avg_speed = (total_size / (1024 * 1024)) / total_time
                self.log_callback(f"⚡ Performance: {avg_speed:.1f} MB/s")
                self.log_callback(f"⏱️ Time: {total_time:.1f} seconds")
            
            self.log_callback(f"✅ Folder encrypted successfully: {output_path}")
            return True
            
        except Exception as e:
            self.log_callback(f"❌ Folder encryption failed: {str(e)}")
            if 'output_path' in locals() and os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            if 'temp_tar_path' in locals() and os.path.exists(temp_tar_path):
                try:
                    os.remove(temp_tar_path)
                except:
                    pass
            return False
    
    def decrypt_folder(self, input_path: str, output_path: str, password: str) -> bool:
        """
        Decrypt a folder from TAR archive.
        
        Returns:
            True if successful, False if cancelled or failed
        """
        try:
            self.log_callback(f"📁 Decrypting folder: {os.path.basename(input_path)}")
            
            file_size = os.path.getsize(input_path)
            chunk_size = self.get_optimal_chunk_size(file_size)
            
            start_time = time.time()
            
            # Stage 1: Decrypt to temporary TAR (0-60% progress)
            temp_tar_path = output_path + ".tmp.tar"
            
            try:
                self.progress_callback(0, "Starting folder decryption...")
                
                with open(input_path, 'rb') as infile:
                    # Read salt and IV
                    salt = infile.read(self.salt_length)
                    iv = infile.read(self.iv_length)
                    
                    if len(salt) != self.salt_length or len(iv) != self.iv_length:
                        raise ValueError("Invalid encrypted folder format")
                    
                    # Derive key from password
                    key = self._derive_key(password, salt)
                    
                    # Create cipher
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                    decryptor = cipher.decryptor()
                    
                    # Create unpadder
                    unpadder = padding.PKCS7(128).unpadder()
                    
                    with open(temp_tar_path, 'wb') as temp_outfile:
                        decrypted_data = b''
                        processed_size = self.salt_length + self.iv_length
                        last_progress = -1
                        
                        while True:
                            if self.cancel_check():
                                self.log_callback("❌ Folder decryption cancelled")
                                return False
                            
                            chunk = infile.read(chunk_size)
                            if len(chunk) == 0:
                                break
                            
                            decrypted_chunk = decryptor.update(chunk)
                            decrypted_data += decrypted_chunk
                            processed_size += len(chunk)
                            
                            # Write in larger blocks
                            if len(decrypted_data) >= chunk_size * 4:
                                temp_outfile.write(decrypted_data)
                                decrypted_data = b''
                            
                            # Calculate progress for decryption stage (0-60%)
                            decryption_progress = int((processed_size / file_size) * 60)
                            if decryption_progress != last_progress:
                                elapsed = time.time() - start_time
                                if elapsed > 0:
                                    speed = (processed_size / (1024 * 1024)) / elapsed
                                    self.progress_callback(decryption_progress, 
                                        f"Decrypting archive ({speed:.1f} MB/s)")
                                else:
                                    self.progress_callback(decryption_progress, "Decrypting archive")
                                last_progress = decryption_progress
                        
                        # Finalize decryption
                        decrypted_data += decryptor.finalize()
                        
                        # Remove padding
                        unpadded_data = unpadder.update(decrypted_data)
                        unpadded_data += unpadder.finalize()
                        
                        temp_outfile.write(unpadded_data)
                
                self.progress_callback(60, "Archive decrypted, starting extraction...")
                
                # Stage 2: Extract TAR archive (60-100% progress)
                self.log_callback(f"📂 Extracting files from TAR archive to: {output_path}")
                
                # Create output folder
                if not os.path.exists(output_path):
                    os.makedirs(output_path)
                
                extracted_files = 0
                extracted_dirs = 0
                
                with tarfile.open(temp_tar_path, 'r') as tar:
                    members = tar.getmembers()
                    total_members = len(members)
                    
                    last_progress = 60
                    
                    for i, member in enumerate(members):
                        if self.cancel_check():
                            self.log_callback("❌ Folder extraction cancelled")
                            return False
                        
                        try:
                            # Extract member
                            tar.extract(member, output_path)
                            
                            if member.isdir():
                                extracted_dirs += 1
                            else:
                                extracted_files += 1
                            
                            # Calculate progress for extraction stage (60-100%)
                            extraction_progress = 60 + int(((i + 1) / total_members) * 40)
                            if extraction_progress != last_progress:
                                self.progress_callback(extraction_progress, 
                                    f"Extracting {extracted_files} files, {extracted_dirs} folders")
                                last_progress = extraction_progress
                            
                        except Exception as e:
                            self.log_callback(f"Warning: Could not extract {member.name}: {e}")
                            continue
                
                self.progress_callback(100, "Extraction completed!")
                
            finally:
                # Clean up temp TAR
                if os.path.exists(temp_tar_path):
                    os.remove(temp_tar_path)
            
            # Final stats
            total_time = time.time() - start_time
            if total_time > 0:
                avg_speed = (file_size / (1024 * 1024)) / total_time
                self.log_callback(f"⚡ Performance: {avg_speed:.1f} MB/s")
                self.log_callback(f"⏱️ Time: {total_time:.1f} seconds")
            
            self.log_callback(f"✅ Folder decrypted: {extracted_files} files, {extracted_dirs} directories")
            return True
            
        except Exception as e:
            self.log_callback(f"❌ Folder decryption failed: {str(e)}")
            if 'output_path' in locals() and os.path.exists(output_path):
                try:
                    shutil.rmtree(output_path)
                except:
                    pass
            if 'temp_tar_path' in locals() and os.path.exists(temp_tar_path):
                try:
                    os.remove(temp_tar_path)
                except:
                    pass
            return False


class CLI:
    """Command-line interface for the encryption tool."""
    
    @staticmethod
    def check_password_strength(password: str) -> Tuple[int, list]:
        """Check password strength and return score and feedback."""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("At least 8 characters")
            
        if len(password) >= 12:
            score += 1
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        return min(score, 5), feedback
    
    @staticmethod
    def run():
        """Run the CLI interface."""
        parser = argparse.ArgumentParser(
            prog='file-enc-dec.py',
            description='xsukax AES-256 File/Folder Encryption/Decryption Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  Quick usage (auto-generates output name):
    %(prog)s -e file.txt                    # Creates file.txt.enc
    %(prog)s -d file.txt.enc                # Creates file.txt
    %(prog)s -e "My Folder"                 # Creates My Folder.enc
    %(prog)s -d "My Folder.enc"             # Creates My Folder
    
  Specify output name:
    %(prog)s -e file.txt -o encrypted.enc
    %(prog)s -d file.enc -o decrypted.txt
    
  Explicit file/folder type:
    %(prog)s -e file.7z --file              # Creates file.7z.enc
    %(prog)s -d file.7z.enc --file          # Creates file.7z
    %(prog)s -e MyFolder --folder            # Creates MyFolder.enc (TAR archive)
    %(prog)s -d archive.enc --folder -o ExtractedFolder
    
  Other options:
    %(prog)s -e file.txt -f                 # Force overwrite
    %(prog)s -e file.txt -q                 # Quiet mode
    %(prog)s -e file.txt --check-strength   # Check password strength
    
  Dependency management:
    %(prog)s --check-deps                   # Check and install dependencies
    
Note: Folders are archived using TAR (no compression) for faster processing.
      The encryption provides the security, not compression.
      Run with --check-deps to automatically install missing dependencies.
            """
        )
        
        # Add --check-deps as standalone option
        parser.add_argument('--check-deps', action='store_true',
                          help='Check and install missing dependencies')
        
        # Create mutually exclusive group for operation
        op_group = parser.add_mutually_exclusive_group(required=False)
        op_group.add_argument('-e', '--encrypt', action='store_true',
                            help='Encrypt the input')
        op_group.add_argument('-d', '--decrypt', action='store_true',
                            help='Decrypt the input')
        
        parser.add_argument('input', nargs='?', help='Input file or folder path')
        parser.add_argument('-o', '--output',
                          help='Output path (optional, auto-generated if not specified)')
        
        # Create mutually exclusive group for type specification
        type_group = parser.add_mutually_exclusive_group()
        type_group.add_argument('--file', action='store_true',
                              help='Explicitly specify input is a file')
        type_group.add_argument('--folder', action='store_true',
                              help='Explicitly specify input is a folder')
        
        parser.add_argument('-f', '--force', action='store_true',
                          help='Overwrite output if it exists')
        parser.add_argument('-q', '--quiet', action='store_true',
                          help='Minimal output')
        parser.add_argument('--check-strength', action='store_true',
                          help='Check password strength (encryption only)')
        
        args = parser.parse_args()
        
        # If --check-deps was handled earlier, this won't be reached
        # But we check anyway for safety
        if args.check_deps:
            check_and_install_dependencies()
            return
        
        # Check if we have an operation
        if not args.encrypt and not args.decrypt:
            parser.error("Either -e/--encrypt or -d/--decrypt is required")
        
        # Check if input is provided
        if not args.input:
            parser.error("Input file or folder path is required")
        
        # Determine operation
        operation = 'encrypt' if args.encrypt else 'decrypt'
        
        # Check if input exists
        if not os.path.exists(args.input):
            print(f"Error: Input path does not exist: {args.input}")
            sys.exit(1)
        
        # Auto-generate output path if not specified
        if not args.output:
            if operation == 'encrypt':
                # Add .enc extension
                args.output = args.input + '.enc'
            else:  # decrypt
                # Remove .enc extension if present, otherwise add .decrypted
                if args.input.endswith('.enc'):
                    args.output = args.input[:-4]
                else:
                    args.output = args.input + '.decrypted'
            
            if not args.quiet:
                print(f"ℹ️  Output path auto-generated: {args.output}")
        
        # Determine input type
        if args.file:
            is_folder = False
            if os.path.isdir(args.input):
                print(f"Error: {args.input} is a directory but --file was specified")
                sys.exit(1)
        elif args.folder:
            is_folder = True
            # For folder decryption, the input should be an encrypted file
            if operation == 'decrypt' and not os.path.isfile(args.input):
                print(f"Error: For folder decryption, input should be an encrypted archive file")
                sys.exit(1)
            # For folder encryption, the input should be a directory
            elif operation == 'encrypt' and not os.path.isdir(args.input):
                print(f"Error: {args.input} is not a directory but --folder was specified")
                sys.exit(1)
        else:
            # Auto-detect based on input
            if operation == 'encrypt':
                # For encryption, check if input is a directory
                is_folder = os.path.isdir(args.input)
            else:
                # For decryption, check if we should treat as folder
                # If the input file is a directory, it's definitely a file operation
                if os.path.isdir(args.input):
                    print(f"Error: Cannot decrypt a directory. Input must be an encrypted file.")
                    sys.exit(1)
                
                # Check if output path suggests folder operation
                if args.output.endswith('/') or args.output.endswith('\\'):
                    is_folder = True
                    # Remove trailing slash
                    args.output = args.output.rstrip('/\\')
                else:
                    # Default to file operation for decryption
                    is_folder = False
        
        # Check if output already exists
        if os.path.exists(args.output) and not args.force:
            response = input(f"Output path already exists: {args.output}\nOverwrite? (y/N): ")
            if response.lower() != 'y':
                print("Operation cancelled")
                sys.exit(0)
        
        # Get password interactively
        if operation == 'encrypt':
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: Passwords do not match")
                sys.exit(1)
            
            # Check password strength if requested
            if args.check_strength:
                score, feedback = CLI.check_password_strength(password)
                strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
                print(f"\nPassword strength: {strength_levels[min(score-1, 4)] if score > 0 else 'Very Weak'}")
                if feedback:
                    print(f"Suggestions: {', '.join(feedback)}")
                
                if score <= 2:
                    response = input("\nPassword is weak. Continue anyway? (y/N): ")
                    if response.lower() != 'y':
                        print("Operation cancelled")
                        sys.exit(0)
        else:
            password = getpass.getpass("Enter password: ")
        
        # Set up callbacks
        def log_callback(message):
            if not args.quiet:
                print(message)
        
        # Create encryption core
        core = AESEncryptionCore(log_callback=log_callback)
        
        # Log what we're doing
        if not args.quiet:
            op_type = "folder" if is_folder else "file"
            print(f"\n{'='*50}")
            print(f"🔐 Operation: {operation.upper()} {op_type.upper()}")
            print(f"📥 Input: {args.input}")
            print(f"📤 Output: {args.output}")
            if is_folder:
                print(f"📦 Method: TAR archiving (no compression)")
            print(f"{'='*50}\n")
        
        try:
            if operation == 'encrypt':
                if is_folder:
                    success = core.encrypt_folder(args.input, args.output, password)
                else:
                    success = core.encrypt_file(args.input, args.output, password)
            else:  # decrypt
                if is_folder:
                    # For folder decryption, create output directory if needed
                    if not os.path.exists(args.output):
                        os.makedirs(args.output, exist_ok=True)
                    success = core.decrypt_folder(args.input, args.output, password)
                else:
                    success = core.decrypt_file(args.input, args.output, password)
            
            sys.exit(0 if success else 1)
            
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


class AESFileEncryptorGUI:
    """GUI interface for the encryption tool."""
    
    def __init__(self):
        self.cancel_requested = False
        self.core = None  # Will be created for each operation
        
        # For smooth progress updates
        self.last_update_time = 0
        self.update_interval = 0.05  # Update every 50ms for smooth animation
        
        # GUI setup
        self.setup_gui()
    
    def check_password_strength(self, password: str) -> tuple:
        """Check password strength."""
        return CLI.check_password_strength(password)
    
    def setup_gui(self):
        """Initialize and setup the GUI components."""
        self.root = Tk()
        self.root.title("xsukax AES-256 File/Folder Encryption/Decryption Tool")
        self.root.geometry("700x650")
        self.root.resizable(True, True)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(W, E, N, S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="xsukax AES-256 File/Folder Encryption/Decryption Tool", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File/Folder selection section
        ttk.Label(main_frame, text="Select Target:", font=('Arial', 10, 'bold')).grid(
            row=1, column=0, sticky=W, pady=(0, 5))
        
        # Target type selection
        self.target_type_var = StringVar(value="file")
        file_rb = ttk.Radiobutton(main_frame, text="📄 File", 
                                 variable=self.target_type_var, value="file",
                                 command=self.on_target_type_change)
        file_rb.grid(row=2, column=0, sticky=W, pady=2)
        
        folder_rb = ttk.Radiobutton(main_frame, text="📁 Folder", 
                                   variable=self.target_type_var, value="folder",
                                   command=self.on_target_type_change)
        folder_rb.grid(row=2, column=1, sticky=W, pady=2)
        
        # Path selection
        self.file_path_var = StringVar()
        self.path_entry = ttk.Entry(main_frame, textvariable=self.file_path_var, width=50)
        self.path_entry.grid(row=3, column=0, columnspan=2, sticky=(W, E), padx=(0, 10))
        
        self.browse_btn = ttk.Button(main_frame, text="Browse", command=self.browse_target)
        self.browse_btn.grid(row=3, column=2, sticky=W)
        
        # Operation selection
        ttk.Label(main_frame, text="Operation:", font=('Arial', 10, 'bold')).grid(
            row=4, column=0, sticky=W, pady=(20, 5))
        
        self.operation_var = StringVar(value="encrypt")
        encrypt_rb = ttk.Radiobutton(main_frame, text="🔒 Encrypt", 
                                   variable=self.operation_var, value="encrypt")
        encrypt_rb.grid(row=5, column=0, sticky=W, pady=2)
        
        decrypt_rb = ttk.Radiobutton(main_frame, text="🔓 Decrypt", 
                                   variable=self.operation_var, value="decrypt")
        decrypt_rb.grid(row=5, column=1, sticky=W, pady=2)
        
        # Password section
        ttk.Label(main_frame, text="Password:", font=('Arial', 10, 'bold')).grid(
            row=6, column=0, sticky=W, pady=(20, 5))
        
        self.password_var = StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                 show="*", width=40)
        password_entry.grid(row=7, column=0, columnspan=2, sticky=(W, E), padx=(0, 10))
        
        # Show/Hide password checkbox
        self.show_password_var = BooleanVar()
        show_password_cb = ttk.Checkbutton(main_frame, text="Show password", 
                                         variable=self.show_password_var,
                                         command=self.toggle_password)
        show_password_cb.grid(row=8, column=0, sticky=W, pady=(5, 0))
        
        # Password strength section
        strength_label = ttk.Label(main_frame, text="Password Strength:", font=('Arial', 9, 'bold'))
        strength_label.grid(row=9, column=0, sticky=W, pady=(15, 2))
        
        # Password strength indicator frame
        strength_frame = ttk.Frame(main_frame)
        strength_frame.grid(row=10, column=0, columnspan=3, sticky=(W, E), pady=(0, 15))
        strength_frame.columnconfigure(1, weight=1)
        
        # Password strength progress bar
        self.strength_var = DoubleVar()
        self.strength_bar = ttk.Progressbar(strength_frame, variable=self.strength_var,
                                          maximum=5, length=150, style="Strength.Horizontal.TProgressbar")
        self.strength_bar.grid(row=0, column=0, sticky=W, padx=(0, 10))
        
        # Password strength text
        self.strength_label = ttk.Label(strength_frame, text="Enter password above", 
                                      font=('Arial', 9), foreground="gray")
        self.strength_label.grid(row=0, column=1, sticky=W)
        
        self.password_entry = password_entry
        
        # Bind password change event
        self.password_var.trace('w', self.on_password_change)
        
        # Process buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=11, column=0, columnspan=3, pady=(30, 10), sticky=(W, E))
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        
        # Process button
        self.process_btn = ttk.Button(buttons_frame, text="🚀 Start Process", 
                                    command=self.start_process, style='Accent.TButton')
        self.process_btn.grid(row=0, column=0, sticky=(W, E), padx=(0, 5))
        
        # Cancel button
        self.cancel_btn = ttk.Button(buttons_frame, text="❌ Cancel", 
                                   command=self.cancel_process, state="disabled")
        self.cancel_btn.grid(row=0, column=1, sticky=(W, E), padx=(5, 0))
        self.cancel_btn.grid_remove()
        
        # Progress section
        ttk.Label(main_frame, text="Progress:", font=('Arial', 10, 'bold')).grid(
            row=12, column=0, sticky=W, pady=(10, 5))
        
        # Stage indicator (for folder operations)
        self.stage_label = ttk.Label(main_frame, text="", 
                                   font=('Arial', 9, 'italic'), foreground='#6c757d')
        self.stage_label.grid(row=13, column=0, columnspan=3, sticky=W, pady=(0, 5))
        
        # Configure style for green progress bar
        style.configure("Green.Horizontal.TProgressbar", 
                       background='#28a745',
                       troughcolor='#f8f9fa',
                       borderwidth=1,
                       lightcolor='#28a745',
                       darkcolor='#28a745')
        
        # Configure styles for password strength indicator
        style.configure("Strength.Horizontal.TProgressbar",
                       background='#dc3545',
                       troughcolor='#f8f9fa',
                       borderwidth=1)
        
        self.progress_var = DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                          maximum=100, length=400, 
                                          style="Green.Horizontal.TProgressbar")
        self.progress_bar.grid(row=14, column=0, columnspan=3, sticky=(W, E), pady=(0, 5))
        
        self.status_var = StringVar(value="Ready to process files...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                               font=('Arial', 9), foreground='#28a745')
        status_label.grid(row=15, column=0, columnspan=3, sticky=W)
        
        # Results section
        self.result_text = Text(main_frame, height=8, width=70, wrap=WORD, 
                              state=DISABLED, font=('Consolas', 9))
        self.result_text.grid(row=16, column=0, columnspan=3, pady=(15, 0), sticky=(W, E, N, S))
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=self.result_text.yview)
        scrollbar.grid(row=16, column=3, sticky=(N, S))
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure row weight for text area
        main_frame.rowconfigure(16, weight=1)
        
        # Add initial helpful message
        self.log_message("🔒 xsukax AES-256 File/Folder Encryption/Decryption Tool")
        self.log_message("✨ Key Features:")
        self.log_message("   • TAR archiving for folders (30-50% faster)")
        self.log_message("   • Interactive password prompt (secure)")
        self.log_message("   • Auto-generated output names")
        self.log_message("   • Dynamic chunk sizing for performance")
        self.log_message("   • Real-time speed monitoring")
        self.log_message("")
        self.log_message("📦 Dependency Management:")
        self.log_message("   • Run with --check-deps to install dependencies")
        self.log_message("   • Auto-detects Linux distro for tkinter install")
        self.log_message("   • Installs pip and cryptography if needed")
        self.log_message("")
        self.log_message("💻 CLI Examples:")
        self.log_message("   python file-enc-dec.py -e \"My Folder\"")
        self.log_message("   python file-enc-dec.py -d \"My Folder.enc\"")
        self.log_message("   python file-enc-dec.py --check-deps")
        self.log_message("")
        
        # Bind operation change to update UI
        self.operation_var.trace('w', self.on_operation_change)
    
    def browse_target(self):
        """Open file or folder dialog based on selected target type and operation."""
        target_type = self.target_type_var.get()
        operation = self.operation_var.get()
        
        if target_type == "file":
            if operation == "encrypt":
                file_path = filedialog.askopenfilename(
                    title="Select file to encrypt",
                    filetypes=[("All files", "*.*")]
                )
            else:
                file_path = filedialog.askopenfilename(
                    title="Select encrypted file to decrypt",
                    filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
                )
            
            if file_path:
                self.file_path_var.set(file_path)
                
        else:  # folder
            if operation == "encrypt":
                folder_path = filedialog.askdirectory(
                    title="Select folder to encrypt"
                )
                if folder_path:
                    self.file_path_var.set(folder_path)
            else:
                encrypted_file = filedialog.askopenfilename(
                    title="Select encrypted folder file (.enc) to decrypt",
                    filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
                )
                if encrypted_file:
                    self.file_path_var.set(encrypted_file)
    
    def on_target_type_change(self):
        """Handle target type change."""
        self.file_path_var.set("")
        self.on_operation_change()
    
    def on_operation_change(self, *args):
        """Handle operation change."""
        target_type = self.target_type_var.get()
        operation = self.operation_var.get()
        
        if target_type == "file":
            if operation == "encrypt":
                self.browse_btn.configure(text="Browse File")
            else:
                self.browse_btn.configure(text="Browse Encrypted")
        else:
            if operation == "encrypt":
                self.browse_btn.configure(text="Browse Folder")
            else:
                self.browse_btn.configure(text="Browse Archive")
    
    def cancel_process(self):
        """Cancel the current operation."""
        self.cancel_requested = True
        self.log_message("⚠️ Cancellation requested...")
        self.cancel_btn.configure(state="disabled")
    
    def show_cancel_button(self):
        """Show the cancel button."""
        self.cancel_btn.grid()
        self.cancel_btn.configure(state="normal")
    
    def hide_cancel_button(self):
        """Hide the cancel button."""
        self.cancel_btn.grid_remove()
        self.cancel_btn.configure(state="disabled")
    
    def toggle_password(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")
    
    def on_password_change(self, *args):
        """Handle password change to update strength indicator."""
        password = self.password_var.get()
        
        if not password:
            self.strength_var.set(0)
            self.strength_label.configure(text="Enter password above", foreground="gray")
            return
        
        score, feedback = self.check_password_strength(password)
        self.strength_var.set(score)
        
        # Update color and text based on strength
        colors = ["#dc3545", "#fd7e14", "#ffc107", "#20c997", "#28a745"]
        texts = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
        
        color = colors[min(score-1, 4)] if score > 0 else colors[0]
        text = texts[min(score-1, 4)] if score > 0 else texts[0]
        
        # Update progress bar color
        style = ttk.Style()
        style.configure("Strength.Horizontal.TProgressbar",
                       background=color,
                       troughcolor='#f8f9fa',
                       borderwidth=1)
        
        # Update label
        if feedback:
            self.strength_label.configure(
                text=f"{text} - {feedback[0]}", 
                foreground=color
            )
        else:
            self.strength_label.configure(text=f"{text} - Excellent!", foreground=color)
    
    def log_message(self, message):
        """Add a message to the results text area."""
        self.result_text.configure(state=NORMAL)
        self.result_text.insert(END, f"{message}\n")
        self.result_text.configure(state=DISABLED)
        self.result_text.see(END)
        self.root.update_idletasks()
    
    def update_progress(self, value, status):
        """Update progress bar and status with smooth animation."""
        current_time = time.time()
        
        # Only update if enough time has passed
        if current_time - self.last_update_time >= self.update_interval:
            self.progress_var.set(value)
            self.status_var.set(status)
            
            # Update stage label for folder operations
            if "Archiving" in status:
                self.stage_label.configure(text="Stage 1/2: TAR Archiving")
            elif "Encrypting archive" in status:
                self.stage_label.configure(text="Stage 2/2: Encryption")
            elif "Decrypting archive" in status:
                self.stage_label.configure(text="Stage 1/2: Decryption")
            elif "Extracting" in status:
                self.stage_label.configure(text="Stage 2/2: TAR Extraction")
            else:
                self.stage_label.configure(text="")
            
            self.root.update_idletasks()
            self.last_update_time = current_time
    
    def validate_inputs(self):
        """Validate user inputs before processing."""
        if not self.file_path_var.get():
            messagebox.showerror("Error", "Please select a file or folder!")
            return False
        
        target_path = self.file_path_var.get()
        
        if not os.path.exists(target_path):
            messagebox.showerror("Error", "Selected path does not exist!")
            return False
        
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password!")
            return False
        
        # Check password strength
        password = self.password_var.get()
        score, feedback = self.check_password_strength(password)
        if score <= 1:
            result = messagebox.askyesno("Weak Password", 
                                       f"Your password is very weak.\n"
                                       f"Suggestions: {', '.join(feedback[:3])}\n\n"
                                       f"Continue anyway?")
            if not result:
                return False
        
        return True
    
    def get_output_path(self, input_path: str) -> str:
        """Get output path for the operation."""
        target_type = self.target_type_var.get()
        operation = self.operation_var.get()
        
        if operation == "encrypt":
            suggested_output = input_path + ".enc"
        else:
            if input_path.endswith('.enc'):
                suggested_output = input_path[:-4]
            else:
                suggested_output = input_path + ".decrypted"
        
        # Check if output exists
        if os.path.exists(suggested_output):
            result = messagebox.askyesno("File Exists", 
                                       f"Output already exists: {os.path.basename(suggested_output)}\n"
                                       "Overwrite?")
            if not result:
                # Let user choose alternative
                if target_type == "folder" and operation == "decrypt":
                    output_path = filedialog.askdirectory(
                        title="Choose extraction location"
                    )
                else:
                    output_path = filedialog.asksaveasfilename(
                        title="Save as...",
                        initialfile=os.path.basename(suggested_output)
                    )
                
                return output_path if output_path else None
        
        # For folder decryption, ask where to extract
        if target_type == "folder" and operation == "decrypt":
            folder_name = os.path.basename(suggested_output)
            parent_dir = filedialog.askdirectory(
                title=f"Choose where to extract '{folder_name}'"
            )
            if parent_dir:
                return os.path.join(parent_dir, folder_name)
            return None
        
        return suggested_output
    
    def process_file(self):
        """Process the file or folder based on the selected operation."""
        try:
            self.cancel_requested = False
            self.process_btn.configure(state="disabled", text="Processing...")
            self.show_cancel_button()
            self.progress_var.set(0)
            self.stage_label.configure(text="")
            self.last_update_time = 0
            
            target_path = self.file_path_var.get()
            password = self.password_var.get()
            operation = self.operation_var.get()
            target_type = self.target_type_var.get()
            
            # Get output path
            output_path = self.get_output_path(target_path)
            if not output_path:
                self.log_message("❌ Operation cancelled - No output selected")
                return
            
            # Create encryption core with callbacks
            self.core = AESEncryptionCore(
                progress_callback=self.update_progress,
                log_callback=self.log_message,
                cancel_check=lambda: self.cancel_requested
            )
            
            # Perform operation
            success = False
            if target_type == "file" and operation == "encrypt":
                success = self.core.encrypt_file(target_path, output_path, password)
            elif target_type == "file" and operation == "decrypt":
                success = self.core.decrypt_file(target_path, output_path, password)
            elif target_type == "folder" and operation == "encrypt":
                success = self.core.encrypt_folder(target_path, output_path, password)
            elif target_type == "folder" and operation == "decrypt":
                success = self.core.decrypt_folder(target_path, output_path, password)
            
            if success and not self.cancel_requested:
                messagebox.showinfo("Success", f"Operation completed successfully!\n{output_path}")
                    
        finally:
            self.process_btn.configure(state="normal", text="🚀 Start Process")
            self.hide_cancel_button()
            self.stage_label.configure(text="")
            if self.cancel_requested:
                self.update_progress(0, "Operation cancelled")
                self.progress_var.set(0)
    
    def start_process(self):
        """Validate inputs and start processing in a separate thread."""
        if not self.validate_inputs():
            return
        
        # Clear previous results
        self.result_text.configure(state=NORMAL)
        self.result_text.delete(1.0, END)
        self.result_text.configure(state=DISABLED)
        
        # Start processing in a separate thread
        thread = threading.Thread(target=self.process_file, daemon=True)
        thread.start()
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point - determine CLI or GUI mode."""
    # Check if running in CLI mode (any of the CLI arguments present)
    cli_args = ['-e', '--encrypt', '-d', '--decrypt', '-h', '--help', '--check-deps']
    
    # If any CLI argument is present or tkinter is not available, use CLI
    if len(sys.argv) > 1 and (sys.argv[1] in cli_args or sys.argv[1].startswith('-')):
        # CLI mode
        CLI.run()
    elif not TKINTER_AVAILABLE:
        # No GUI available and no CLI arguments
        print("\n" + "=" * 60)
        print("⚠️  GUI is not available (tkinter not installed)")
        print("=" * 60)
        print("\nYou can use the CLI mode instead. Examples:")
        print("  Encrypt a file:    python", sys.argv[0], "-e file.txt")
        print("  Decrypt a file:    python", sys.argv[0], "-d file.txt.enc")
        print("  Encrypt a folder:  python", sys.argv[0], "-e MyFolder")
        print("  Decrypt a folder:  python", sys.argv[0], "-d MyFolder.enc")
        print("  Show help:         python", sys.argv[0], "-h")
        print("\nTo check and install dependencies:")
        print("  python", sys.argv[0], "--check-deps")
        print("=" * 60)
        sys.exit(0)
    else:
        # GUI mode
        try:
            app = AESFileEncryptorGUI()
            app.run()
        except ImportError as e:
            print(f"Error: Missing required dependency - {e}")
            print("\nTo install dependencies automatically, run:")
            print(f"  python {sys.argv[0]} --check-deps")
            print("\nOr install manually:")
            print("  pip install cryptography")
            if os.name != 'nt':  # Not Windows
                print("  sudo apt-get install python3-tk  # For Ubuntu/Debian")
                print("  sudo dnf install python3-tkinter  # For Fedora/RHEL")
            sys.exit(1)
        except Exception as e:
            print(f"Error starting application: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()

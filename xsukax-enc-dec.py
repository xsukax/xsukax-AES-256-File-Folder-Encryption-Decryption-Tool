#!/usr/bin/env python3
"""
xsukax AES-256 File Encryption/Decryption GUI Tool

A user-friendly GUI application for encrypting and decrypting files using AES-256 encryption.
Features a modern interface with progress bars and status updates.

Author: AI Assistant
Date: 2025
"""

import os
import sys
import threading
import time
import zipfile
import io
import tempfile
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets


class AESFileEncryptorGUI:
    """
    GUI class for AES-256 file encryption and decryption with progress tracking.
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.key_length = 32  # 256 bits
        self.iv_length = 16   # 128 bits
        self.salt_length = 16  # 128 bits
        self.chunk_size = 8192  # 8KB chunks
        self.cancel_requested = False  # Flag for cancellation
        
        # GUI setup
        self.setup_gui()
        
    def setup_gui(self):
        """Initialize and setup the GUI components."""
        self.root = Tk()
        self.root.title("xsukax AES-256 File & Folder Encryptor & Decryptor")
        self.root.geometry("600x500")
        self.root.iconbitmap("xsukax.ico")
        self.root.resizable(True, False)
        
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
        title_label = ttk.Label(main_frame, text="xsukax AES-256 File & Folder Encryptor & Decryptor", 
                               font=('Arial', 15, 'bold'))
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
                                 show="*", width=30)
        password_entry.grid(row=7, column=0, sticky=(W, E), padx=(0, 10))
        
        # Show/Hide password
        self.show_password_var = BooleanVar()
        show_password_cb = ttk.Checkbutton(main_frame, text="Show password", 
                                         variable=self.show_password_var,
                                         command=self.toggle_password)
        show_password_cb.grid(row=7, column=1, sticky=W)
        
        self.password_entry = password_entry  # Store reference for show/hide
        
        # Confirm password (for encryption)
        ttk.Label(main_frame, text="Confirm Password:", font=('Arial', 10, 'bold')).grid(
            row=8, column=0, sticky=W, pady=(15, 5))
        
        self.confirm_password_var = StringVar()
        self.confirm_password_entry = ttk.Entry(main_frame, textvariable=self.confirm_password_var, 
                                              show="*", width=30)
        self.confirm_password_entry.grid(row=9, column=0, sticky=(W, E), padx=(0, 10))
        
        # Process buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=10, column=0, columnspan=3, pady=(30, 10), sticky=(W, E))
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        
        # Process button
        self.process_btn = ttk.Button(buttons_frame, text="🚀 Start Process", 
                                    command=self.start_process, style='Accent.TButton')
        self.process_btn.grid(row=0, column=0, sticky=(W, E), padx=(0, 5))
        
        # Cancel button (initially hidden)
        self.cancel_btn = ttk.Button(buttons_frame, text="❌ Cancel", 
                                   command=self.cancel_process, state="disabled")
        self.cancel_btn.grid(row=0, column=1, sticky=(W, E), padx=(5, 0))
        self.cancel_btn.grid_remove()  # Hide initially
        
        # Progress section
        ttk.Label(main_frame, text="Progress:", font=('Arial', 10, 'bold')).grid(
            row=11, column=0, sticky=W, pady=(10, 5))
        
        # Configure style for green progress bar
        style.configure("Green.Horizontal.TProgressbar", 
                       background='#28a745',  # Green color
                       troughcolor='#f8f9fa',
                       borderwidth=1,
                       lightcolor='#28a745',
                       darkcolor='#28a745')
        
        self.progress_var = DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                          maximum=100, length=400, 
                                          style="Green.Horizontal.TProgressbar")
        self.progress_bar.grid(row=12, column=0, columnspan=3, sticky=(W, E), pady=(0, 5))
        
        self.status_var = StringVar(value="Ready to process files...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                               font=('Arial', 9), foreground='#28a745')  # Green color
        status_label.grid(row=13, column=0, columnspan=3, sticky=W)
        
        # Results section
        self.result_text = Text(main_frame, height=8, width=70, wrap=WORD, 
                              state=DISABLED, font=('Consolas', 9))
        self.result_text.grid(row=14, column=0, columnspan=3, pady=(15, 0), sticky=(W, E, N, S))
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=self.result_text.yview)
        scrollbar.grid(row=14, column=3, sticky=(N, S))
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure row weight for text area
        main_frame.rowconfigure(14, weight=1)
        
        # Add initial helpful message
        self.log_message("🔒 xsukax AES-256 File & Folder Encryptor - 4 Operation Modes:")
        self.log_message("   📄🔒 File Encrypt: document.pdf → document.pdf.enc")
        self.log_message("   📄🔓 File Decrypt: document.pdf.enc → document.pdf")
        self.log_message("   📁🔒 Folder Encrypt: MyFolder → MyFolder.enc")
        self.log_message("   📁🔓 Folder Decrypt: MyFolder.enc → Choose extraction location")
        self.log_message("")
        self.log_message("✨ File extensions are now properly preserved!")
        self.log_message("💡 Tip: If you encounter permission errors, try:")
        self.log_message("   • Running as administrator")
        self.log_message("   • Selecting a different output location")
        self.log_message("   • Moving files to a folder you own (like Documents)")
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
            else:  # decrypt
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
            else:  # decrypt
                # For folder decryption, first select the encrypted .enc file
                encrypted_file = filedialog.askopenfilename(
                    title="Select encrypted folder file (.enc) to decrypt",
                    filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
                )
                if encrypted_file:
                    self.file_path_var.set(encrypted_file)
    
    def on_target_type_change(self):
        """Handle target type change to update UI accordingly."""
        # Clear the current path when switching types
        self.file_path_var.set("")
        
        # Update browse button text and operation description
        target_type = self.target_type_var.get()
        operation = self.operation_var.get()
        
        if target_type == "file":
            if operation == "encrypt":
                self.browse_btn.configure(text="Browse File to Encrypt")
            else:
                self.browse_btn.configure(text="Browse Encrypted File")
        else:  # folder
            if operation == "encrypt":
                self.browse_btn.configure(text="Browse Folder to Encrypt")
            else:
                self.browse_btn.configure(text="Browse Encrypted Folder File")
    
    def on_operation_change(self, *args):
        """Handle operation change to show/hide confirm password."""
        if self.operation_var.get() == "encrypt":
            self.confirm_password_entry.configure(state="normal")
        else:
            self.confirm_password_entry.configure(state="disabled")
            self.confirm_password_var.set("")
        
        # Update browse button text
        self.on_target_type_change()
    
    def cancel_process(self):
        """Cancel the current encryption/decryption process."""
        self.cancel_requested = True
        self.log_message("⚠️ Cancellation requested... Please wait for current chunk to finish.")
        self.update_progress(self.progress_var.get(), "Cancelling operation...")
        self.cancel_btn.configure(state="disabled")
    
    def show_cancel_button(self):
        """Show the cancel button during processing."""
        self.cancel_btn.grid()
        self.cancel_btn.configure(state="normal")
    
    def hide_cancel_button(self):
        """Hide the cancel button when not processing."""
        self.cancel_btn.grid_remove()
        self.cancel_btn.configure(state="disabled")
    
    def toggle_password(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
            self.confirm_password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")
            self.confirm_password_entry.configure(show="*")
    
    def log_message(self, message, color="black"):
        """Add a message to the results text area."""
        self.result_text.configure(state=NORMAL)
        self.result_text.insert(END, f"{message}\n")
        self.result_text.configure(state=DISABLED)
        self.result_text.see(END)
        self.root.update()
    
    def update_progress(self, value, status):
        """Update progress bar and status."""
        self.progress_var.set(value)
        self.status_var.set(status)
        self.root.update()
    
    def check_write_permission(self, directory_path: str) -> bool:
        """Check if we have write permission to a directory."""
        try:
            with tempfile.NamedTemporaryFile(dir=directory_path, delete=True):
                pass
            return True
        except (OSError, PermissionError):
            return False
    
    def get_safe_output_path(self, input_path: str, extension: str, operation_name: str) -> str:
        """Get a safe output path, asking user if needed due to permission issues."""
        if os.path.isfile(input_path):
            # For files - ALWAYS append extension to preserve full original filename
            parent_dir = os.path.dirname(input_path)
            original_filename = os.path.basename(input_path)
            suggested_output = os.path.join(parent_dir, original_filename + extension)
        else:
            # For folders
            parent_dir = os.path.dirname(input_path.rstrip(os.sep))
            folder_name = os.path.basename(input_path.rstrip(os.sep))
            suggested_output = os.path.join(parent_dir, folder_name + extension)
        
        # Check write permission
        if self.check_write_permission(parent_dir):
            # Check if file already exists
            if os.path.exists(suggested_output):
                result = messagebox.askyesno("File Exists", 
                                           f"The file '{os.path.basename(suggested_output)}' already exists.\n"
                                           "Do you want to overwrite it?")
                if not result:
                    return None
            return suggested_output
        else:
            # No permission, ask user to choose location
            self.log_message(f"⚠️ No write permission to '{parent_dir}', please choose save location...")
            
            if os.path.isfile(input_path):
                # Preserve full original filename + extension
                original_filename = os.path.basename(input_path)
                default_name = original_filename + extension
            else:
                default_name = os.path.basename(input_path.rstrip(os.sep)) + extension
            
            output_path = filedialog.asksaveasfilename(
                title=f"Save {operation_name} file as...",
                defaultextension=extension,
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
                initialfilename=default_name
            )
            
            return output_path if output_path else None
    
    def validate_inputs(self):
        """Validate user inputs before processing."""
        if not self.file_path_var.get():
            messagebox.showerror("Error", "Please select a file or folder!")
            return False
        
        target_path = self.file_path_var.get()
        target_type = self.target_type_var.get()
        operation = self.operation_var.get()
        
        # Validate based on the 4 different scenarios
        if target_type == "file" and operation == "encrypt":
            # File Encryption: Check if file exists and is readable
            if not os.path.exists(target_path):
                messagebox.showerror("Error", "Selected file does not exist!")
                return False
            if not os.path.isfile(target_path):
                messagebox.showerror("Error", "Selected path is not a file!")
                return False
            
            try:
                with open(target_path, 'rb') as test_file:
                    test_file.read(1)
            except PermissionError:
                messagebox.showerror("Permission Error", 
                                   "Cannot read the selected file.\n"
                                   "Please check file permissions or try running as administrator.")
                return False
            except Exception as e:
                messagebox.showerror("File Error", f"Cannot access the selected file: {str(e)}")
                return False
        
        elif target_type == "file" and operation == "decrypt":
            # File Decryption: Check if encrypted file exists
            if not os.path.exists(target_path):
                messagebox.showerror("Error", "Selected encrypted file does not exist!")
                return False
            if not os.path.isfile(target_path):
                messagebox.showerror("Error", "Selected path is not a file!")
                return False
            
            # Warn if file doesn't have .enc extension
            if not target_path.endswith('.enc'):
                result = messagebox.askyesno("Warning", 
                                           "Selected file doesn't have .enc extension. Continue anyway?")
                if not result:
                    return False
        
        elif target_type == "folder" and operation == "encrypt":
            # Folder Encryption: Check if folder exists and is readable
            if not os.path.exists(target_path):
                messagebox.showerror("Error", "Selected folder does not exist!")
                return False
            if not os.path.isdir(target_path):
                messagebox.showerror("Error", "Selected path is not a folder!")
                return False
            
            try:
                os.listdir(target_path)
            except PermissionError:
                messagebox.showerror("Permission Error", 
                                   "Cannot read the selected folder.\n"
                                   "Please check folder permissions or try running as administrator.")
                return False
            except Exception as e:
                messagebox.showerror("Folder Error", f"Cannot access the selected folder: {str(e)}")
                return False
        
        elif target_type == "folder" and operation == "decrypt":
            # Folder Decryption: Check if encrypted file exists
            if not os.path.exists(target_path):
                messagebox.showerror("Error", "Selected encrypted folder file does not exist!")
                return False
            if not os.path.isfile(target_path):
                messagebox.showerror("Error", "Selected path is not an encrypted file!")
                return False
            
            # Strongly recommend .enc extension for folder decryption
            if not target_path.endswith('.enc'):
                result = messagebox.askyesno("Warning", 
                                           "Selected file doesn't have .enc extension.\n"
                                           "This may not be an encrypted folder file. Continue anyway?")
                if not result:
                    return False
        
        # Password validation
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password!")
            return False
        
        if operation == "encrypt":
            if not self.confirm_password_var.get():
                messagebox.showerror("Error", "Please confirm your password!")
                return False
            
            if self.password_var.get() != self.confirm_password_var.get():
                messagebox.showerror("Error", "Passwords do not match!")
                return False
        
        return True
    
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
    
    def encrypt_file_with_progress(self, input_file_path: str, password: str):
        """Encrypt a file with progress updates."""
        try:
            # Get safe output path - this will now preserve full filename + .enc
            output_file_path = self.get_safe_output_path(input_file_path, ".enc", "encrypted")
            if not output_file_path:
                self.log_message("❌ Operation cancelled - No output file selected")
                return
            
            # Log the filename convention being used
            original_name = os.path.basename(input_file_path)
            encrypted_name = os.path.basename(output_file_path)
            self.log_message(f"📝 Encrypting: {original_name} → {encrypted_name}")
            
            # Get file size for progress calculation
            file_size = os.path.getsize(input_file_path)
            processed_size = 0
            
            # Generate random salt and IV
            salt = secrets.token_bytes(self.salt_length)
            iv = secrets.token_bytes(self.iv_length)
            
            # Derive key from password
            key = self._derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Create padder for PKCS7 padding
            padder = padding.PKCS7(128).padder()
            
            with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
                # Write salt and IV to the beginning
                outfile.write(salt)
                outfile.write(iv)
                
                # Encrypt file in chunks
                while True:
                    # Check for cancellation
                    if self.cancel_requested:
                        self.log_message("❌ Encryption cancelled by user")
                        # Clean up partial file
                        if os.path.exists(output_file_path):
                            os.remove(output_file_path)
                        return
                    
                    chunk = infile.read(self.chunk_size)
                    if len(chunk) == 0:
                        # Final chunk - pad and finalize
                        padded_data = padder.finalize()
                        if padded_data:
                            encrypted_chunk = encryptor.update(padded_data)
                            outfile.write(encrypted_chunk)
                        encrypted_final = encryptor.finalize()
                        outfile.write(encrypted_final)
                        break
                    elif len(chunk) < self.chunk_size:
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
                        # Full chunk
                        padded_chunk = padder.update(chunk)
                        encrypted_chunk = encryptor.update(padded_chunk)
                        outfile.write(encrypted_chunk)
                        processed_size += len(chunk)
                    
                    # Update progress
                    progress = (processed_size / file_size) * 100
                    self.update_progress(progress, f"Encrypting... {progress:.1f}%")
            
            self.update_progress(100, "Encryption completed!")
            self.log_message(f"✅ File encrypted successfully: {output_file_path}")
            self.log_message(f"💡 To decrypt: Select this .enc file and the original name will be restored")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_name}\n\nTo decrypt: Select the .enc file and the original filename will be automatically restored.")
            
        except Exception as e:
            self.log_message(f"❌ Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            # Clean up partial file
            if 'output_file_path' in locals() and os.path.exists(output_file_path):
                try:
                    os.remove(output_file_path)
                except:
                    pass
    
    def decrypt_file_with_progress(self, input_file_path: str, password: str):
        """Decrypt a file that was encrypted with AES-256-CBC."""
        try:
            # Smart output path determination to preserve original extension
            if input_file_path.endswith('.enc'):
                # Remove .enc extension to get original filename
                output_file_path = input_file_path[:-4]
                original_name = os.path.basename(output_file_path)
                encrypted_name = os.path.basename(input_file_path)
                self.log_message(f"📝 Decrypting: {encrypted_name} → {original_name}")
            else:
                # If input doesn't end with .enc, add .decrypted suffix
                output_file_path = input_file_path + ".decrypted"
                self.log_message(f"⚠️ File doesn't end with .enc, creating: {os.path.basename(output_file_path)}")
            
            # Check if output file already exists
            if os.path.exists(output_file_path):
                result = messagebox.askyesno("File Exists", 
                                           f"The file '{os.path.basename(output_file_path)}' already exists.\n"
                                           "Do you want to overwrite it?")
                if not result:
                    # Let user choose alternative location
                    original_name = os.path.basename(output_file_path)
                    output_file_path = filedialog.asksaveasfilename(
                        title="Save decrypted file as...",
                        initialfilename=original_name,
                        filetypes=[("All files", "*.*")]
                    )
                    if not output_file_path:
                        self.log_message("❌ Operation cancelled - No output file selected")
                        return
            
            # Get file size for progress calculation
            file_size = os.path.getsize(input_file_path)
            processed_size = 0
            
            with open(input_file_path, 'rb') as infile:
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
                
                # Create unpadder
                unpadder = padding.PKCS7(128).unpadder()
                
                with open(output_file_path, 'wb') as outfile:
                    # Decrypt file in chunks
                    decrypted_data = b''
                    processed_size = self.salt_length + self.iv_length  # Account for salt and IV
                    
                    while True:
                        # Check for cancellation
                        if self.cancel_requested:
                            self.log_message("❌ Decryption cancelled by user")
                            # Clean up partial file
                            if os.path.exists(output_file_path):
                                os.remove(output_file_path)
                            return
                        
                        chunk = infile.read(self.chunk_size)
                        if len(chunk) == 0:
                            break
                        
                        decrypted_chunk = decryptor.update(chunk)
                        decrypted_data += decrypted_chunk
                        processed_size += len(chunk)
                        
                        # Update progress (decryption takes 10-90% of total progress)
                        progress = (processed_size / file_size) * 90
                        self.update_progress(progress, f"Decrypting... {progress:.1f}%")
                    
                    # Finalize decryption
                    self.update_progress(90, "Finalizing decryption...")
                    decrypted_data += decryptor.finalize()
                    
                    # Remove padding
                    unpadded_data = unpadder.update(decrypted_data)
                    unpadded_data += unpadder.finalize()
                    
                    # Write decrypted data
                    outfile.write(unpadded_data)
            
            self.update_progress(100, "Decryption completed!")
            self.log_message(f"✅ File decrypted successfully: {output_file_path}")
            
            # Show file extension information
            original_ext = os.path.splitext(output_file_path)[1]
            if original_ext:
                self.log_message(f"📎 Original file extension restored: {original_ext}")
            else:
                self.log_message("📎 Original file had no extension")
                
            messagebox.showinfo("Success", f"File decrypted successfully!\nOriginal filename restored: {os.path.basename(output_file_path)}")
            
        except Exception as e:
            self.log_message(f"❌ Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            # Clean up partial file
            if 'output_file_path' in locals() and os.path.exists(output_file_path):
                try:
                    os.remove(output_file_path)
                except:
                    pass
    
    def get_folder_size(self, folder_path: str) -> int:
        """Calculate total size of all files in a folder recursively."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        except Exception as e:
            self.log_message(f"Warning: Could not calculate size for some files: {e}")
        return total_size
    
    def encrypt_folder_with_progress(self, folder_path: str, password: str):
        """Encrypt a folder recursively with progress updates."""
        try:
            # Get safe output path
            output_file_path = self.get_safe_output_path(folder_path, ".enc", "encrypted folder")
            if not output_file_path:
                self.log_message("❌ Operation cancelled - No output file selected")
                return
            
            # Calculate total folder size for progress tracking
            self.update_progress(5, "Calculating folder size...")
            total_size = self.get_folder_size(folder_path)
            processed_size = 0
            
            # Count total items (files + directories) for better progress tracking
            total_items = 0
            for root, dirs, files in os.walk(folder_path):
                total_items += len(files) + len(dirs)
            
            # Create ZIP archive in memory
            self.update_progress(10, "Creating folder archive...")
            zip_buffer = io.BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
                processed_items = 0
                
                for root, dirs, files in os.walk(folder_path):
                    # Check for cancellation
                    if self.cancel_requested:
                        self.log_message("❌ Folder encryption cancelled by user")
                        return
                    
                    # Add empty directories first
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        relative_dir_path = os.path.relpath(dir_path, folder_path)
                        
                        # Check if directory is empty
                        try:
                            if not os.listdir(dir_path):  # Empty directory
                                # Add empty directory to ZIP (must end with /)
                                zipf.writestr(relative_dir_path + '/', '')
                                self.log_message(f"📁 Added empty folder: {relative_dir_path}")
                                processed_items += 1
                                
                                # Update progress for directories
                                archive_progress = 10 + (processed_items / total_items) * 30
                                self.update_progress(archive_progress, f"Adding empty folder: {relative_dir_path}")
                        except (OSError, PermissionError):
                            self.log_message(f"Warning: Could not access directory {relative_dir_path}")
                            continue
                    
                    # Add files
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Skip if file doesn't exist (might be a broken link)
                        if not os.path.exists(file_path):
                            continue
                        
                        # Calculate relative path for ZIP archive
                        relative_path = os.path.relpath(file_path, folder_path)
                        
                        try:
                            # Add file to ZIP with progress tracking
                            file_size = os.path.getsize(file_path)
                            zipf.write(file_path, relative_path)
                            processed_size += file_size
                            processed_items += 1
                            
                            # Update progress (archiving takes 10-50% of total progress)
                            archive_progress = 10 + (processed_items / total_items) * 40
                            self.update_progress(archive_progress, 
                                               f"Archiving: {relative_path[:50]}...")
                            
                        except Exception as e:
                            self.log_message(f"Warning: Could not add file {relative_path}: {e}")
                            continue
            
            # Check for cancellation after archiving
            if self.cancel_requested:
                self.log_message("❌ Folder encryption cancelled by user")
                return
            
            # Get ZIP data
            zip_data = zip_buffer.getvalue()
            zip_buffer.close()
            
            self.update_progress(50, "Starting encryption...")
            
            # Generate random salt and IV
            salt = secrets.token_bytes(self.salt_length)
            iv = secrets.token_bytes(self.iv_length)
            
            # Derive key from password
            key = self._derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Create padder for PKCS7 padding
            padder = padding.PKCS7(128).padder()
            
            # Encrypt the ZIP data
            with open(output_file_path, 'wb') as outfile:
                # Write salt and IV to the beginning
                outfile.write(salt)
                outfile.write(iv)
                
                # Encrypt ZIP data in chunks
                zip_size = len(zip_data)
                encrypted_size = 0
                
                # Process ZIP data in chunks
                for i in range(0, zip_size, self.chunk_size):
                    # Check for cancellation
                    if self.cancel_requested:
                        self.log_message("❌ Folder encryption cancelled by user")
                        if os.path.exists(output_file_path):
                            os.remove(output_file_path)
                        return
                    
                    chunk = zip_data[i:i + self.chunk_size]
                    
                    if i + self.chunk_size >= zip_size:
                        # Last chunk - pad and finalize
                        padded_chunk = padder.update(chunk)
                        padded_final = padder.finalize()
                        encrypted_chunk = encryptor.update(padded_chunk + padded_final)
                        outfile.write(encrypted_chunk)
                        encrypted_final = encryptor.finalize()
                        outfile.write(encrypted_final)
                        encrypted_size += len(chunk)
                        break
                    else:
                        # Regular chunk
                        padded_chunk = padder.update(chunk)
                        encrypted_chunk = encryptor.update(padded_chunk)
                        outfile.write(encrypted_chunk)
                        encrypted_size += len(chunk)
                    
                    # Update progress (encryption takes 50-100% of total progress)
                    encrypt_progress = 50 + (encrypted_size / zip_size) * 50
                    self.update_progress(encrypt_progress, f"Encrypting folder... {encrypt_progress:.1f}%")
            
            self.update_progress(100, "Folder encryption completed!")
            self.log_message(f"✅ Folder encrypted successfully: {output_file_path}")
            self.log_message(f"📊 Original folder size: {total_size:,} bytes")
            self.log_message(f"📊 Processed {processed_items} items (files + folders)")
            self.log_message(f"📊 Encrypted file size: {os.path.getsize(output_file_path):,} bytes")
            messagebox.showinfo("Success", f"Folder encrypted successfully!\nSaved as: {output_file_path}\n\nProcessed {processed_items} items including empty folders.")
            
        except Exception as e:
            self.log_message(f"❌ Folder encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Folder encryption failed: {str(e)}")
            # Clean up partial file
            if 'output_file_path' in locals() and os.path.exists(output_file_path):
                try:
                    os.remove(output_file_path)
                except:
                    pass
    
    def decrypt_folder_with_progress(self, encrypted_file_path: str, output_folder_path: str, password: str):
        """Decrypt an encrypted folder file with progress updates."""
        try:
            # Get file size for progress calculation
            file_size = os.path.getsize(encrypted_file_path)
            
            self.update_progress(5, "Starting folder decryption...")
            
            with open(encrypted_file_path, 'rb') as infile:
                # Read salt and IV
                salt = infile.read(self.salt_length)
                iv = infile.read(self.iv_length)
                
                if len(salt) != self.salt_length or len(iv) != self.iv_length:
                    raise ValueError("Invalid encrypted folder file format")
                
                # Derive key from password
                key = self._derive_key(password, salt)
                
                # Create cipher
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                decryptor = cipher.decryptor()
                
                # Create unpadder
                unpadder = padding.PKCS7(128).unpadder()
                
                # Decrypt file in chunks
                decrypted_data = b''
                processed_size = self.salt_length + self.iv_length  # Account for salt and IV
                
                self.update_progress(10, "Decrypting folder data...")
                
                while True:
                    # Check for cancellation
                    if self.cancel_requested:
                        self.log_message("❌ Folder decryption cancelled by user")
                        return
                    
                    chunk = infile.read(self.chunk_size)
                    if len(chunk) == 0:
                        break
                    
                    decrypted_chunk = decryptor.update(chunk)
                    decrypted_data += decrypted_chunk
                    processed_size += len(chunk)
                    
                    # Update progress (decryption takes 10-60% of total progress)
                    decrypt_progress = 10 + (processed_size / file_size) * 50
                    self.update_progress(decrypt_progress, f"Decrypting... {decrypt_progress:.1f}%")
                
                # Finalize decryption
                self.update_progress(60, "Finalizing decryption...")
                decrypted_data += decryptor.finalize()
                
                # Remove padding
                unpadded_data = unpadder.update(decrypted_data)
                unpadded_data += unpadder.finalize()
            
            # Check for cancellation
            if self.cancel_requested:
                self.log_message("❌ Folder decryption cancelled by user")
                return
            
            # Extract ZIP archive
            self.update_progress(70, "Extracting folder structure...")
            
            # Create output folder if it doesn't exist
            if not os.path.exists(output_folder_path):
                os.makedirs(output_folder_path)
            
            # Extract ZIP from decrypted data
            zip_buffer = io.BytesIO(unpadded_data)
            extracted_files = 0
            
            with zipfile.ZipFile(zip_buffer, 'r') as zipf:
                file_list = zipf.namelist()
                total_files = len(file_list)
                
                for i, file_info in enumerate(file_list):
                    # Check for cancellation
                    if self.cancel_requested:
                        self.log_message("❌ Folder decryption cancelled by user")
                        return
                    
                    try:
                        zipf.extract(file_info, output_folder_path)
                        extracted_files += 1
                        
                        # Update progress (extraction takes 70-100% of total progress)
                        extract_progress = 70 + (extracted_files / total_files) * 30
                        self.update_progress(extract_progress, 
                                           f"Extracting: {file_info[:50]}...")
                        
                    except Exception as e:
                        self.log_message(f"Warning: Could not extract file {file_info}: {e}")
                        continue
            
            zip_buffer.close()
            
            self.update_progress(100, "Folder decryption completed!")
            self.log_message(f"✅ Folder decrypted successfully to: {output_folder_path}")
            self.log_message(f"📊 Extracted {extracted_files} files")
            messagebox.showinfo("Success", f"Folder decrypted successfully!\nExtracted to: {output_folder_path}")
            
        except Exception as e:
            self.log_message(f"❌ Folder decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Folder decryption failed: {str(e)}")
            # Clean up partial folder if it exists
            if 'output_folder_path' in locals() and os.path.exists(output_folder_path):
                try:
                    import shutil
                    shutil.rmtree(output_folder_path)
                    self.log_message(f"🧹 Cleaned up partial folder: {output_folder_path}")
                except:
                    pass
    
    def decrypt_folder_from_file(self, encrypted_file_path: str, password: str):
        """Decrypt an encrypted folder file and ask user where to extract it."""
        try:
            # Ask user where to extract the folder
            destination_parent = filedialog.askdirectory(
                title="Select where to extract the decrypted folder"
            )
            
            if not destination_parent:
                self.log_message("❌ Operation cancelled - No destination selected")
                return
            
            # Create output folder name based on encrypted file name
            encrypted_filename = os.path.basename(encrypted_file_path)
            if encrypted_filename.endswith('.enc'):
                folder_name = encrypted_filename[:-4]  # Remove .enc extension
            else:
                folder_name = encrypted_filename + "_decrypted"
            
            output_folder_path = os.path.join(destination_parent, folder_name)
            
            # Check if destination already exists
            if os.path.exists(output_folder_path):
                result = messagebox.askyesno("Folder Exists", 
                                           f"The folder '{folder_name}' already exists at the destination.\n"
                                           "Do you want to overwrite it?")
                if not result:
                    self.log_message("❌ Operation cancelled - Folder already exists")
                    return
                else:
                    # Remove existing folder
                    import shutil
                    shutil.rmtree(output_folder_path)
            
            self.log_message(f"Extracting to: {output_folder_path}")
            
            # Call the actual decryption method
            self.decrypt_folder_with_progress(encrypted_file_path, output_folder_path, password)
            
        except Exception as e:
            self.log_message(f"❌ Folder decryption setup failed: {str(e)}")
            messagebox.showerror("Error", f"Folder decryption setup failed: {str(e)}")
    
    def process_file(self):
        """Process the file or folder based on the selected operation (4 scenarios)."""
        try:
            self.cancel_requested = False  # Reset cancellation flag
            self.process_btn.configure(state="disabled", text="Processing...")
            self.show_cancel_button()  # Show cancel button
            self.progress_var.set(0)
            
            target_path = self.file_path_var.get()
            password = self.password_var.get()
            operation = self.operation_var.get()
            target_type = self.target_type_var.get()
            
            # Determine which of the 4 methods to call
            if target_type == "file" and operation == "encrypt":
                # Method 1: File Encryption
                self.log_message(f"🔒 Starting file encryption: {os.path.basename(target_path)}")
                self.encrypt_file_with_progress(target_path, password)
                
            elif target_type == "file" and operation == "decrypt":
                # Method 2: File Decryption
                self.log_message(f"🔓 Starting file decryption: {os.path.basename(target_path)}")
                self.decrypt_file_with_progress(target_path, password)
                
            elif target_type == "folder" and operation == "encrypt":
                # Method 3: Folder Encryption
                folder_name = os.path.basename(target_path.rstrip(os.sep))
                self.log_message(f"📁🔒 Starting folder encryption: {folder_name}")
                self.encrypt_folder_with_progress(target_path, password)
                
            elif target_type == "folder" and operation == "decrypt":
                # Method 4: Folder Decryption
                encrypted_filename = os.path.basename(target_path)
                self.log_message(f"📁🔓 Starting folder decryption: {encrypted_filename}")
                self.decrypt_folder_from_file(target_path, password)
            
            else:
                # This shouldn't happen with proper validation
                self.log_message("❌ Invalid operation combination")
                messagebox.showerror("Error", "Invalid operation combination!")
                    
        finally:
            self.process_btn.configure(state="normal", text="🚀 Start Process")
            self.hide_cancel_button()  # Hide cancel button
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
        
        # Start processing in a separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.process_file, daemon=True)
        thread.start()
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main function to start the GUI application."""
    try:
        app = AESFileEncryptorGUI()
        app.run()
    except ImportError as e:
        print(f"Error: Missing required dependency - {e}")
        print("Please install required packages:")
        print("pip install cryptography")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
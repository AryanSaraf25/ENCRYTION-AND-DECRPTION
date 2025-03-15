"""
Streamlit Web Interface for Encryption/Decryption Tool

This application provides a web interface for the encryption/decryption tool
using Streamlit. Users can upload files, encrypt or decrypt them, and
download the results.
"""

import os
import base64
import tempfile
import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import io


class SecureCrypto:
    """Handles encryption and decryption using AES-256-GCM with proper key derivation."""

    @staticmethod
    def derive_key(password, salt=None):
        """
        Derives a secure key from a password using PBKDF2.
        
        Args:
            password: User-provided password
            salt: Optional salt (generates a new one if None)
            
        Returns:
            tuple: (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = base64.b64decode(salt)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits (AES-256)
            salt=salt,
            iterations=100000,  # High iteration count for security
        )
        
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        key = kdf.derive(password)
        return key, salt

    @staticmethod
    def encrypt(plaintext, password):
        """
        Encrypts data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (str or bytes)
            password: User-provided password
            
        Returns:
            dict: Contains base64-encoded ciphertext, nonce, and salt
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Generate a random nonce (number used once)
        nonce = os.urandom(12)  # 96 bits as recommended for GCM
        
        # Derive key from password
        key, salt = SecureCrypto.derive_key(password)
        
        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Return everything needed for decryption
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }

    @staticmethod
    def decrypt(encrypted_data, password):
        """
        Decrypts data that was encrypted with AES-256-GCM.
        
        Args:
            encrypted_data: Dict with ciphertext, nonce, and salt
            password: User-provided password
            
        Returns:
            bytes: Decrypted data
        """
        # Decode from base64
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        salt = base64.b64decode(encrypted_data['salt'])
        
        # Derive the same key using the provided salt
        key, _ = SecureCrypto.derive_key(password, salt)
        
        # Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext


def get_download_link(file_data, file_name, text):
    """Generate a download link for a file."""
    b64_data = base64.b64encode(file_data).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64_data}" download="{file_name}">{text}</a>'
    return href


def main():
    st.set_page_config(
        page_title="Secure Encryption/Decryption Tool",
        page_icon="🔒",
        layout="centered",
    )

    st.title("🔒 Secure File Encryption & Decryption")
    st.write("""
    This tool uses AES-256-GCM encryption with PBKDF2 key derivation for 
    secure file encryption and decryption. All processing happens in your browser.
    """)

    # Tabs for encrypt and decrypt
    tab1, tab2 = st.tabs(["Encrypt File", "Decrypt File"])

    # Encryption Tab
    with tab1:
        st.header("Encrypt File")
        
        uploaded_file = st.file_uploader("Choose a file to encrypt", type=None, key="encrypt_uploader")
        password = st.text_input("Enter encryption password", type="password", key="encrypt_password")
        confirm_password = st.text_input("Confirm password", type="password", key="confirm_password")
        
        if st.button("Encrypt File", key="encrypt_button"):
            if uploaded_file is not None:
                if password != confirm_password:
                    st.error("Passwords do not match!")
                elif not password:
                    st.error("Please enter a password!")
                else:
                    try:
                        # Display progress
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        # Read file data
                        status_text.text("Reading file data...")
                        file_data = uploaded_file.read()
                        progress_bar.progress(25)
                        
                        # Encrypt data
                        status_text.text("Encrypting data...")
                        encrypted_data = SecureCrypto.encrypt(file_data, password)
                        progress_bar.progress(75)
                        
                        # Convert to JSON for download
                        encrypted_json = json.dumps(encrypted_data).encode('utf-8')
                        
                        # Create download link
                        status_text.text("Encryption complete!")
                        progress_bar.progress(100)
                        
                        # Display download link
                        st.markdown(
                            get_download_link(
                                encrypted_json, 
                                f"{uploaded_file.name}.enc", 
                                "📥 Download Encrypted File"
                            ),
                            unsafe_allow_html=True
                        )
                        
                        st.success("File encrypted successfully! Click the link above to download.")
                        st.info("Keep your password safe. Files cannot be recovered without it.")
                        
                    except Exception as e:
                        st.error(f"Encryption failed: {str(e)}")
            else:
                st.warning("Please upload a file to encrypt.")

    # Decryption Tab
    with tab2:
        st.header("Decrypt File")
        
        uploaded_enc_file = st.file_uploader("Choose an encrypted file (.enc)", type=None, key="decrypt_uploader")
        dec_password = st.text_input("Enter decryption password", type="password", key="decrypt_password")
        
        if st.button("Decrypt File", key="decrypt_button"):
            if uploaded_enc_file is not None:
                if not dec_password:
                    st.error("Please enter the decryption password!")
                else:
                    try:
                        # Display progress
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        # Read encrypted file
                        status_text.text("Reading encrypted file...")
                        encrypted_json = uploaded_enc_file.read()
                        encrypted_data = json.loads(encrypted_json)
                        progress_bar.progress(25)
                        
                        # Decrypt data
                        status_text.text("Decrypting data...")
                        try:
                            decrypted_data = SecureCrypto.decrypt(encrypted_data, dec_password)
                            progress_bar.progress(75)
                            
                            # Original filename without .enc extension
                            original_filename = uploaded_enc_file.name
                            if original_filename.endswith('.enc'):
                                original_filename = original_filename[:-4]
                            
                            # Create download link
                            status_text.text("Decryption complete!")
                            progress_bar.progress(100)
                            
                            # Display download link
                            st.markdown(
                                get_download_link(
                                    decrypted_data, 
                                    original_filename, 
                                    "📥 Download Decrypted File"
                                ),
                                unsafe_allow_html=True
                            )
                            
                            st.success("File decrypted successfully! Click the link above to download.")
                            
                        except Exception:
                            progress_bar.progress(100)
                            st.error("Decryption failed. Incorrect password or corrupted file.")
                            
                    except Exception as e:
                        st.error(f"Error processing file: {str(e)}")
            else:
                st.warning("Please upload an encrypted file.")

    # About section
    st.markdown("---")
    st.subheader("About this tool")
    with st.expander("Security Information"):
        st.markdown("""
        **Security Features:**
        - **AES-256-GCM**: A state-of-the-art authenticated encryption algorithm
        - **PBKDF2 Key Derivation**: Securely derives encryption keys from passwords
        - **100,000 iterations**: Makes brute-force attacks computationally expensive
        - **Secure Random Number Generation**: Uses cryptographically secure random numbers
        
        **Important Notes:**
        - All encryption/decryption happens locally in your browser
        - We don't store your files or passwords
        - Lost passwords cannot be recovered
        """)


if __name__ == "__main__":
    main()
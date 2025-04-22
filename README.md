# ENCRYTION-AND-DECRPTION
# Secure File Encryption & Decryption Tool

A Streamlit web application for securely encrypting and decrypting files using AES-256-GCM encryption.

## Features

- AES-256-GCM encryption with PBKDF2 key derivation (100,000 iterations)
- Browser-based processing - no data leaves your computer
- Simple interface for file upload, encryption/decryption, and download
- Visual progress tracking
- No storage of files or passwords

## Getting Started

```
git clone https://github.com/yourusername/secure-file-encryption.git
cd secure-file-encryption
pip install -r requirements.txt
streamlit run app.py
```

Then open http://localhost:8501 in your browser.

## Usage

### Encrypting Files
1. Go to the "Encrypt File" tab
2. Upload your file
3. Enter a strong password (twice)
4. Click "Encrypt File" and download the result

### Decrypting Files
1. Go to the "Decrypt File" tab
2. Upload the encrypted (.enc) file 
3. Enter the password
4. Click "Decrypt File" and download the result

## Dependencies
- streamlit
- cryptography

## Warning
Keep your password safe - files cannot be recovered without it!

## How It Works

This tool uses AES-256-GCM encryption with a key derived from your password using PBKDF2. The encryption process generates a unique salt and nonce for each file, which are stored with the encrypted data.

## License

MIT

## Contributing

Pull requests welcome. For major changes, please open an issue first to discuss what you'd like to change.

## Disclaimer

For personal or educational use only. Always backup important files before encrypting them.

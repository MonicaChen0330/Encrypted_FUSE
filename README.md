# Encrypted FS on FUSE

## Objective🔐

This project is designed to enhance understanding of **file system operations** and **encryption techniques** by implementing a simple **in-memory file system** using the [FUSE (Filesystem in Userspace)](https://github.com/libfuse/libfuse) framework, followed by integrating AES-256 encryption to ensure data security.

## Difference: In-Memory File System vs. Traditional File System

A **traditional file system** (e.g., ext4, NTFS) writes data to persistent storage, ensuring long-term availability. In contrast, an **in-memory file system** stores all data in **RAM**, meaning:

- Data is lost when the system is shut down or unmounted.
- File access is significantly faster.
- Suitable for **temporary storage, caching, or high-speed applications**.

## Features 🛠️

✔ **Basic file operations**: Create, read, write, open, and close files.\
✔ **Directory management**: Create and remove directories, list directory contents.\
✔ **AES-256 encryption**: Data is encrypted before storage and decrypted upon access.\
✔ **Key-based access control**: Each file requires a unique encryption key for decryption.

⚠ **Limitations**:

- Data is **not persistent** (lost after unmounting).
- No support for **symbolic links, hard links, or file permissions**.
- Not optimized for **large-scale file systems**.

## Installation & Usage ⚙️

### Installation & Execution Steps 🚀

Before running the project, ensure that you have compiled the executable from `enfuse.c`. If the `enfuse` executable is missing, compile it using:

```sh
gcc -Wall -D_FILE_OFFSET_BITS=64 -o enfuse enfuse.c -lfuse -v
```

Then, verify that the executable exists and has the correct permissions:

```sh
ls -l enfuse
chmod +x enfuse
```

### Prerequisites

Ensure the following are installed:

- **Linux** (Ubuntu/Debian recommended)
- **FUSE** (`libfuse-dev` package)
- **GCC** (for compiling the file system)
- **OpenSSL** (for AES-256 encryption)

### Installation & Execution Steps

1. **Clone this repository**:
   ```sh
   git clone https://github.com/MonicaChen0330/ENcrypted_FUSE.git
   ```
2. **Compile the File System**:
   ```sh
   gcc -Wall enfuse.c `pkg-config --cflags --libs fuse` -o enfuse -lcrypto
   ```
3. **Create a Mount Point**:
   ```sh
   mkdir ~/mymount
   ```
4. **Mount the File System**:
   ```sh
   ./enfuse -f ~/mymount
   ```
5. **Test Basic Operations**:
   ```sh
   cd ~/mymount
   mkdir secure_folder
   echo "Confidential Data" > securefile.txt
   cat securefile.txt
   ls
   rm securefile.txt
   ```
6. **Unmount the File System**:
   ```sh
   fusermount -u ~/mymount
   ```

### Verifying Execution

After running the project, you can perform the following test operations to verify that everything is working correctly:

```sh
mkdir -p ~/mymount
./enfuse -f ~/mymount
cd ~/mymount
mkdir testdir
echo "Hello, World!" > testfile.txt
cat testfile.txt
ls
rm testfile.txt
cd ..
fusermount -u ~/mymount
```

```sh
fusermount -u ~/mymount
```

### Encryption Handling

This file system integrates **AES-256 encryption**:

- **Encryption occurs upon file writing** (stored securely in memory).
- **Decryption happens upon reading** (accessible only with the correct key).

To test encryption:

```sh
echo "Sensitive Information" > encrypted_file.txt  # Data is encrypted before storage
cat encrypted_file.txt  # Only accessible with the correct decryption key
```

## Implementation Details 

- Built using **FUSE API** to manage user-space file operations.
- Derived from **ENCRYPTED\_FUSE** ([Less Simple, Yet Stupid Filesystem](https://github.com/MaaSTaaR/ENCRYPTED_FUSE)), with enhancements including:
  - **File & directory deletion support**
  - **AES-256 encryption using OpenSSL**
  - **Key-based file access control**
- Stores files in **memory**, making it suitable for fast, temporary storage applications.

## Future Enhancements 

- **Expand file system functionality**, such as symbolic links, file permissions, and access controls.
- **Make encryption optional**, allowing users to enable or disable encryption based on their needs.

## References 📚

1. [Less Simple, Yet Stupid Filesystem (ENCRYPTED\_FUSE)](https://github.com/MaaSTaaR/ENCRYPTED_FUSE)
2. [FUSE Documentation](https://github.com/libfuse/libfuse)
3. [OpenSSL AES-256 Encryption Guide](https://www.openssl.org/docs/man3.0/man7/EVP_EncryptInit.html)
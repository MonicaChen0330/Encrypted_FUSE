/**
 * Encrypted FUSE - In-Memory File System with AES-256 Encryption
 */
 
#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define AES_BLOCK_SIZE 16
#define MAX_FILES 256

char dir_list[ 256 ][ 256 ];
int curr_dir_idx = -1;

char files_list[ 256 ][ 256 ];
int curr_file_idx = -1;

char files_content[ 256 ][ 256 ];
int curr_file_content_idx = -1;

struct file_key_info {
	char key[AES_KEY_LEN];
	char iv[AES_IV_LEN];
};

struct file_key_info *file_keys;

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    //Generate random AES_IV
    int len, ciphertext_len;
    if (!RAND_bytes(iv, AES_IV_LEN)) {
	fprintf(stderr, "Failed to generate AES_IV\n");
	EVP_CIPHER_CTX_free(ctx);
	return -1;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <=0) {
        fprintf(stderr, "Decryption failed: Invalid key or IV.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void add_dir( const char *dir_name )
{
	curr_dir_idx++;
	strcpy( dir_list[ curr_dir_idx ], dir_name );
	printf("Added directory to memory: %s\n", dir_name);
}

int is_dir( const char *path )
{
	path++; // Eliminating "/" in the path

	for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
		if ( strcmp( path, dir_list[ curr_idx ] ) == 0 )
			return 1;

	return 0;
}

void add_file( const char *filename )
{
	curr_file_idx++;
	strcpy( files_list[ curr_file_idx ], filename );

	curr_file_content_idx++;
	strcpy( files_content[ curr_file_content_idx ], "" );
}

int is_file( const char *path )
{
	path++; // Eliminating "/" in the path

	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 )
			return 1;

	return 0;
}

int get_file_index( const char *path )
{
	path++; // Eliminating "/" in the path

	for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ ) {
		if ( strcmp( path, files_list[ curr_idx ] ) == 0 ) {
			printf("File matched: %s\n", path);
			return curr_idx;
		}
	}

	return -1;
}

void write_to_file( const char *path, const char *new_content, const unsigned char *key)
{
	int file_idx = get_file_index( path );

	if ( file_idx == -1 ) {// No such file
		printf("Error: File not found in memory: %s\n", path);
		return;
	}

	printf("Encrypting file %s content: %s\n", path, new_content);

	unsigned char ciphertext[1024];
	unsigned char iv[AES_IV_LEN];

	//generate random IV and encrypt
	memset((void *)(key + strlen((const char *)key)), 0, AES_KEY_LEN - strlen((const char *)key));
	int encrypted_len = aes_encrypt((unsigned char *)new_content, strlen(new_content), key, iv, ciphertext);

	memcpy(files_content[file_idx], ciphertext, encrypted_len);
	memcpy(file_keys[file_idx].iv, iv, AES_IV_LEN);
	memcpy(file_keys[file_idx].key, key, AES_KEY_LEN);

	printf("Encrypted file %s content: %s\n", path, ciphertext);
}

// ... //

static int do_getattr( const char *path, struct stat *st )
{
	st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
	st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
	st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
	st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now

	if ( strcmp( path, "/" ) == 0 || is_dir( path ) == 1 )
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
	}
	else if ( is_file( path ) == 1 )
	{
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = 1024;
	}
	else
	{
		return -ENOENT;
	}

	return 0;
}

static int do_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi )
{
	filler( buffer, ".", NULL, 0 ); // Current Directory
	filler( buffer, "..", NULL, 0 ); // Parent Directory

	if ( strcmp( path, "/" ) == 0 ) // If the user is trying to show the files/directories of the root directory show the following
	{
		for ( int curr_idx = 0; curr_idx <= curr_dir_idx; curr_idx++ )
			filler( buffer, dir_list[ curr_idx ], NULL, 0 );

		for ( int curr_idx = 0; curr_idx <= curr_file_idx; curr_idx++ )
			filler( buffer, files_list[ curr_idx ], NULL, 0 );
	}

	return 0;
}

static int do_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi )
{
	static int read_called[MAX_FILES] = {0};

	int file_idx = get_file_index( path );
	if ( file_idx == -1 ) {
		printf("File not found in memory: %s\n", path);
		return -1;
	}
	if (read_called[file_idx]) return 0;

	//check the key
	static int key_checked[MAX_FILES] = {0};
	static unsigned char user_key[AES_KEY_LEN];

	if (offset == 0 && !key_checked[file_idx]) {
		printf("Enter AES key to read file %s: ", path);
		scanf("%31s", user_key);
		memset((void *)(user_key + strlen((const char *)user_key)), 0, AES_KEY_LEN - strlen((const char *)user_key));
		if (memcmp(user_key, file_keys[file_idx].key, AES_KEY_LEN) != 0) {
			printf("Error: Incorrect key for file %s\n", path);
			return -EACCES;
		}
		key_checked[file_idx] = 1;
	}

	//get encrypted content from memory
	char *encrypted_content = files_content[file_idx];
	size_t encrypted_len = strlen(encrypted_content);
	printf("Reading encrypted file %s content: %s\n", path, encrypted_content);

	//decrypted
	unsigned char plaintext[1024];
	int decrypted_len = aes_decrypt((unsigned char *)encrypted_content, encrypted_len, user_key, (unsigned char *)file_keys[file_idx].iv, plaintext);

	memcpy( buffer, plaintext + offset, size );
	printf("Read operation completed for file %s. Decrypted content: %s\n", path, plaintext);

	read_called[file_idx] = 1;
	return decrypted_len - offset;
}

static int do_mkdir( const char *path, mode_t mode )
{
	path++;
	add_dir( path );

	return 0;
}

static int do_mknod( const char *path, mode_t mode, dev_t rdev )
{
	path++;
	add_file( path );

	return 0;
}

static int do_write( const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *info )
{
	//create a new key
	unsigned char user_key[AES_KEY_LEN];
	printf("Enter AES key for file %s (within 32 characters): ", path);
	scanf("%32s", user_key);

	write_to_file(path, buffer, user_key);

	printf("Write operation completed for file: %s\n", path);
	return size;
}

static int do_unlink(const char *path) {
    int file_idx = get_file_index(path);

    if (file_idx == -1) {
        printf("File not found in memory: %s\n", path);
        return -ENOENT;
    }

    for (int i = file_idx; i < curr_file_idx; i++) {
        strcpy(files_list[i], files_list[i + 1]);
        strcpy(files_content[i], files_content[i + 1]);
    }
    curr_file_idx--;
    curr_file_content_idx--;

    printf("File removed: %s\n", path);
    return 0;
}


static int do_rmdir(const char *path) {
	path++;
	for (int i = 0; i <= curr_dir_idx; i++) {
		if (strcmp(path, dir_list[i]) == 0) {
			for (int j = i; j < curr_dir_idx; j++) {
				strcpy(dir_list[j], dir_list[j+1]);
			}
			curr_dir_idx--;

			printf("Directory removed: %s\n", path);
			return 0;
		}
	}
	printf("Directory not fount: %s\n", path);
	return -ENOENT;
}
static struct fuse_operations operations = {
    .getattr	= do_getattr,
    .readdir	= do_readdir,
    .read		= do_read,
    .mkdir		= do_mkdir,
    .mknod		= do_mknod,
    .write		= do_write,
    .unlink		= do_unlink,
    .rmdir		= do_rmdir,
};

int main( int argc, char *argv[] )
{
	file_keys = malloc(sizeof(struct file_key_info) * MAX_FILES);
	if (!file_keys) {
		fprintf(stderr, "Memory allocation for file keys failed\n");
		exit(EXIT_FAILURE);
	}

	int ret = fuse_main(argc, argv, &operations, NULL);
	free(file_keys);
	return ret;
}


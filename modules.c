/*

Compile:
gcc -Wall -shared -o modules.so -fPIC modules.c -lssl -lcrypto

*/

#define _XOPEN_SOURCE 700
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64 

#ifndef USE_FDS
#define USE_FDS 15
#endif

//#include <unistd.h>
#include <ftw.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
//#include <errno.h>

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} FileList;

typedef struct {
    char **hashes;
    char **paths;
    int count;
} MD5Result;

typedef struct {
    char **hashes;
    char **paths;
    int count;
} SHA256Result;

typedef struct {
    char **hits;
    int count;
} DetectionResult;

static FileList g_list = {NULL, 0, 0};


MD5Result compute_md5_hash(const char **input_arr, int count) {

    MD5Result result;
    result.count = count;

    result.hashes = malloc(count * sizeof(char*));
    result.paths  = malloc(count * sizeof(char*));

    unsigned char digest[MD5_DIGEST_LENGTH];

    for (int i = 0; i < count; i++) {

        result.paths[i] = strdup(input_arr[i]);

        FILE *inFile = fopen(input_arr[i], "rb");
        if (!inFile) {
            result.hashes[i] = strdup("ERROR");
            continue;
        }

        MD5_CTX ctx;
        unsigned char buffer[1024];
        int bytes;

        MD5_Init(&ctx);

        while ((bytes = fread(buffer, 1, sizeof(buffer), inFile)) > 0)
            MD5_Update(&ctx, buffer, bytes);

        MD5_Final(digest, &ctx);
        fclose(inFile);

        // convert digest → hex string
        char *hex = malloc(33);
        for (int j = 0; j < MD5_DIGEST_LENGTH; j++)
            sprintf(hex + j*2, "%02x", digest[j]);

        hex[32] = '\0';

        result.hashes[i] = hex;
    }

    return result;
}

void free_md5_result(MD5Result r) {
    for (int i = 0; i < r.count; i++) {
        free(r.hashes[i]);
        free(r.paths[i]);
    }

    free(r.hashes);
    free(r.paths);
}


// SHA256 version

SHA256Result compute_sha256_hash(const char **input_arr, int count) {

    SHA256Result result;
    result.count = count;

    result.hashes = malloc(count * sizeof(char*));
    result.paths  = malloc(count * sizeof(char*));

    unsigned char digest[SHA256_DIGEST_LENGTH];

    for (int i = 0; i < count; i++) {

        result.paths[i] = strdup(input_arr[i]);

        FILE *inFile = fopen(input_arr[i], "rb");
        if (!inFile) {
            result.hashes[i] = strdup("ERROR");
            continue;
        }

        SHA256_CTX ctx;
        unsigned char buffer[1024];
        int bytes;

        SHA256_Init(&ctx);

        while ((bytes = fread(buffer, 1, sizeof(buffer), inFile)) > 0)
            SHA256_Update(&ctx, buffer, bytes);

        SHA256_Final(digest, &ctx);
        fclose(inFile);

        char *hex = malloc(65);  // 64 chars + null

        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
            sprintf(hex + j*2, "%02x", digest[j]);

        hex[64] = '\0';

        result.hashes[i] = hex;
    }

    return result;
}

void free_sha256_result(SHA256Result r) {
    for (int i = 0; i < r.count; i++) {
        free(r.hashes[i]);
        free(r.paths[i]);
    }
    free(r.hashes);
    free(r.paths);
}



// detect malicious files against a hash file
static char **load_hash_db(const char *path, int *out_count) {

    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    char **list = NULL;
    int count = 0;
    int cap = 0;

    char line[128];

    while (fgets(line, sizeof(line), f)) {

        line[strcspn(line, "\r\n")] = 0;

        if (count == cap) {
            cap = cap ? cap * 2 : 32;
            list = realloc(list, cap * sizeof(char*));
        }

        list[count++] = strdup(line);
    }

    fclose(f);

    *out_count = count;
    return list;
}


DetectionResult detect_malicious(
    char **hashes,
    char **paths,
    int file_count,
    const char *db_path)
{
    DetectionResult result = {0};
    printf("Loading DB: %s\n", db_path);
    int db_count;
    char **db = load_hash_db(db_path, &db_count);
    if (!db) {
        printf("ERROR: Signature file not found! Please re-run the program and make sure the path is correct.");
        return result; 
    } 

    result.hits = NULL;
    int cap = 0;

    for (int i = 0; i < file_count; i++) {

        for (int j = 0; j < db_count; j++) {

            if (strcmp(hashes[i], db[j]) == 0) {

                if (result.count == cap) {
                    cap = cap ? cap * 2 : 16;
                    result.hits =
                        realloc(result.hits, cap * sizeof(char*));
                }

                result.hits[result.count++] =
                    strdup(paths[i]);

                break;
            }
        }
    }
    printf("Loaded %d hashes\n", db_count);
    // cleanup DB
    for (int i = 0; i < db_count; i++)
        free(db[i]);
    free(db);

    return result;
}

// cant forget the free function
void free_detection_result(DetectionResult r) {
    for (int i = 0; i < r.count; i++)
        free(r.hits[i]);
    free(r.hits);
}


// recursively collecting file paths
static int add_path(const char *path) {
    if (g_list.count == g_list.capacity) {
        size_t newcap = g_list.capacity ? g_list.capacity * 2 : 64;

        char **tmp = realloc(g_list.paths, newcap * sizeof(char*));
        if (!tmp) return -1;

        g_list.paths = tmp;
        g_list.capacity = newcap;
    }

    g_list.paths[g_list.count] = strdup(path);
    if (!g_list.paths[g_list.count]) return -1;

    g_list.count++;
    return 0;
}

static int collect_files(
    const char *fpath,
    const struct stat *sb,
    int typeflag,
    struct FTW *ftwbuf)
{
    if (typeflag == FTW_F) {
        if (add_path(fpath) != 0)
            return 1; // stop traversal on failure
    }

    return 0;
}

char **list_files_recursive(const char *dir, int *out_count) {

    // reset global list
    g_list.paths = NULL;
    g_list.count = 0;
    g_list.capacity = 0;

    if (nftw(dir, collect_files, 15, FTW_PHYS) != 0) {
        return NULL;
    }

    *out_count = (int)g_list.count;
    return g_list.paths;
}

void free_file_list(char **list, int count) {
    for (int i = 0; i < count; i++)
        free(list[i]);

    free(list);
}



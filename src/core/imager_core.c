#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_BUFFER (4 * 1024 * 1024)

typedef struct {
    EVP_MD_CTX *md5;
    EVP_MD_CTX *sha1;
    EVP_MD_CTX *sha256;
    EVP_MD_CTX *sha512;
    int use_sha512;
} HashContexts;

static void cleanup_hashes(HashContexts *ctx) {
    if (ctx->md5) EVP_MD_CTX_free(ctx->md5);
    if (ctx->sha1) EVP_MD_CTX_free(ctx->sha1);
    if (ctx->sha256) EVP_MD_CTX_free(ctx->sha256);
    if (ctx->sha512) EVP_MD_CTX_free(ctx->sha512);
}

static int init_hashes(HashContexts *ctx, int use_sha512) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->use_sha512 = use_sha512;

    ctx->md5 = EVP_MD_CTX_new();
    ctx->sha1 = EVP_MD_CTX_new();
    ctx->sha256 = EVP_MD_CTX_new();
    if (use_sha512) ctx->sha512 = EVP_MD_CTX_new();

    if (!ctx->md5 || !ctx->sha1 || !ctx->sha256 || (use_sha512 && !ctx->sha512)) return -1;
    if (EVP_DigestInit_ex(ctx->md5, EVP_md5(), NULL) != 1) return -1;
    if (EVP_DigestInit_ex(ctx->sha1, EVP_sha1(), NULL) != 1) return -1;
    if (EVP_DigestInit_ex(ctx->sha256, EVP_sha256(), NULL) != 1) return -1;
    if (use_sha512 && EVP_DigestInit_ex(ctx->sha512, EVP_sha512(), NULL) != 1) return -1;
    return 0;
}

static int update_hashes(HashContexts *ctx, const unsigned char *buf, size_t n) {
    if (EVP_DigestUpdate(ctx->md5, buf, n) != 1) return -1;
    if (EVP_DigestUpdate(ctx->sha1, buf, n) != 1) return -1;
    if (EVP_DigestUpdate(ctx->sha256, buf, n) != 1) return -1;
    if (ctx->use_sha512 && EVP_DigestUpdate(ctx->sha512, buf, n) != 1) return -1;
    return 0;
}

static void to_hex(const unsigned char *src, unsigned int len, char *dst) {
    static const char *hex = "0123456789abcdef";
    for (unsigned int i = 0; i < len; i++) {
        dst[i * 2] = hex[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex[src[i] & 0xF];
    }
    dst[len * 2] = '\0';
}

static int finalize_hash(EVP_MD_CTX *ctx, char *out_hex, size_t out_len) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) return -1;
    if (out_len < (digest_len * 2 + 1)) return -1;
    to_hex(digest, digest_len, out_hex);
    return 0;
}

static void log_json(FILE *logf, const char *level, const char *message, uint64_t offset, const char *extra_key, const char *extra_value) {
    time_t now = time(NULL);
    struct tm tm_now;
    gmtime_r(&now, &tm_now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_now);

    fprintf(logf, "{\"ts\":\"%s\",\"level\":\"%s\",\"offset\":%llu,\"message\":\"%s\"",
            ts, level, (unsigned long long)offset, message);
    if (extra_key && extra_value) {
        fprintf(logf, ",\"%s\":\"%s\"", extra_key, extra_value);
    }
    fprintf(logf, "}\n");
    fflush(logf);
}

static void emit_progress(uint64_t copied, uint64_t total, double seconds) {
    double speed = (seconds > 0.0) ? ((double)copied / seconds) : 0.0;
    fprintf(stderr,
            "{\"progress_bytes\":%llu,\"total_bytes\":%llu,\"speed_bps\":%.2f}\n",
            (unsigned long long)copied,
            (unsigned long long)total,
            speed);
    fflush(stderr);
}

static int get_source_size(int fd, uint64_t *out) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    if (S_ISREG(st.st_mode)) {
        *out = (uint64_t)st.st_size;
        return 0;
    }

    unsigned long long bytes = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) {
        *out = (uint64_t)bytes;
        return 0;
    }

    return -1;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <source_path> <dest_path> <hash_path> <audit_log_path> [buffer_size] [sha512=0|1] [start_offset] [max_bytes] [append_mode=0|1] [progress_sec]\n",
            prog);
}

int main(int argc, char **argv) {
    if (argc < 5 || argc > 11) {
        usage(argv[0]);
        return 2;
    }

    const char *source = argv[1];
    const char *dest = argv[2];
    const char *hash_path = argv[3];
    const char *log_path = argv[4];
    size_t buffer_size = (argc >= 6) ? (size_t)strtoull(argv[5], NULL, 10) : DEFAULT_BUFFER;
    int use_sha512 = (argc >= 7) ? atoi(argv[6]) : 0;
    uint64_t start_offset = (argc >= 8) ? strtoull(argv[7], NULL, 10) : 0;
    uint64_t max_bytes = (argc >= 9) ? strtoull(argv[8], NULL, 10) : 0;
    int append_mode = (argc >= 10) ? atoi(argv[9]) : 0;
    int progress_sec = (argc >= 11) ? atoi(argv[10]) : 1;

    if (buffer_size < 4096) {
        fprintf(stderr, "buffer_size too small\n");
        return 2;
    }
    if (progress_sec < 0) progress_sec = 0;

    int src_fd = open(source, O_RDONLY | O_CLOEXEC);
    if (src_fd < 0) {
        perror("open source");
        return 1;
    }

    int dst_flags = O_WRONLY | O_CREAT | O_CLOEXEC;
    dst_flags |= append_mode ? O_APPEND : O_TRUNC;
    int dst_fd = open(dest, dst_flags, 0640);
    if (dst_fd < 0) {
        perror("open destination");
        close(src_fd);
        return 1;
    }

    if (start_offset > 0 && lseek(src_fd, (off_t)start_offset, SEEK_SET) == (off_t)-1) {
        perror("lseek source start_offset");
        close(src_fd);
        close(dst_fd);
        return 1;
    }

    if (append_mode && start_offset > 0) {
        struct stat dst_st;
        if (fstat(dst_fd, &dst_st) == 0) {
            uint64_t dst_size = (uint64_t)dst_st.st_size;
            if (dst_size != start_offset) {
                fprintf(stderr, "append_mode size mismatch: dst=%llu start_offset=%llu\n",
                        (unsigned long long)dst_size,
                        (unsigned long long)start_offset);
                close(src_fd);
                close(dst_fd);
                return 1;
            }
        }
    }

    FILE *hashf = fopen(hash_path, "w");
    if (!hashf) {
        perror("open hash output");
        close(src_fd);
        close(dst_fd);
        return 1;
    }

    FILE *logf = fopen(log_path, "a");
    if (!logf) {
        perror("open audit log");
        fclose(hashf);
        close(src_fd);
        close(dst_fd);
        return 1;
    }

    uint64_t source_size = 0;
    int have_source_size = (get_source_size(src_fd, &source_size) == 0);
    uint64_t total_target = 0;
    if (max_bytes > 0) {
        total_target = max_bytes;
    } else if (have_source_size && source_size > start_offset) {
        total_target = source_size - start_offset;
    }

    log_json(logf, "INFO", "acquisition_start", start_offset, "source", source);

    unsigned char *buf = (unsigned char *)malloc(buffer_size);
    if (!buf) {
        log_json(logf, "ERROR", "malloc_failed", start_offset, NULL, NULL);
        fclose(logf);
        fclose(hashf);
        close(src_fd);
        close(dst_fd);
        return 1;
    }

    HashContexts hashes;
    if (init_hashes(&hashes, use_sha512) != 0) {
        log_json(logf, "ERROR", "hash_init_failed", start_offset, NULL, NULL);
        free(buf);
        fclose(logf);
        fclose(hashf);
        close(src_fd);
        close(dst_fd);
        return 1;
    }

    uint64_t absolute_offset = start_offset;
    uint64_t copied = 0;
    uint64_t read_errors = 0;
    int exit_code = 0;

    time_t started = time(NULL);
    time_t last_progress = started;

    for (;;) {
        if (max_bytes > 0 && copied >= max_bytes) break;

        size_t to_read = buffer_size;
        if (max_bytes > 0) {
            uint64_t remain = max_bytes - copied;
            if (remain < to_read) to_read = (size_t)remain;
        }

        ssize_t n = read(src_fd, buf, to_read);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            read_errors++;
            log_json(logf, "WARN", "read_error", absolute_offset, "errno", strerror(errno));

            if (lseek(src_fd, 512, SEEK_CUR) == (off_t)-1) {
                log_json(logf, "ERROR", "lseek_failed_after_read_error", absolute_offset, "errno", strerror(errno));
                exit_code = 1;
                break;
            }

            unsigned char zero[512];
            memset(zero, 0, sizeof(zero));
            if (write(dst_fd, zero, sizeof(zero)) != (ssize_t)sizeof(zero)) {
                log_json(logf, "ERROR", "write_zero_sector_failed", absolute_offset, "errno", strerror(errno));
                exit_code = 1;
                break;
            }
            if (update_hashes(&hashes, zero, sizeof(zero)) != 0) {
                log_json(logf, "ERROR", "hash_update_failed", absolute_offset, NULL, NULL);
                exit_code = 1;
                break;
            }
            copied += 512;
            absolute_offset += 512;
            continue;
        }

        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dst_fd, buf + written, (size_t)(n - written));
            if (w < 0) {
                if (errno == EINTR) continue;
                log_json(logf, "ERROR", "write_error", absolute_offset, "errno", strerror(errno));
                exit_code = 1;
                break;
            }
            written += w;
        }
        if (exit_code != 0) break;

        if (update_hashes(&hashes, buf, (size_t)n) != 0) {
            log_json(logf, "ERROR", "hash_update_failed", absolute_offset, NULL, NULL);
            exit_code = 1;
            break;
        }

        copied += (uint64_t)n;
        absolute_offset += (uint64_t)n;

        if (progress_sec > 0) {
            time_t now = time(NULL);
            if ((now - last_progress) >= progress_sec) {
                double elapsed = difftime(now, started);
                emit_progress(copied, total_target, elapsed);
                last_progress = now;
            }
        }
    }

    if (fsync(dst_fd) != 0) {
        log_json(logf, "ERROR", "fsync_failed", absolute_offset, "errno", strerror(errno));
        exit_code = 1;
    }

    if (exit_code == 0) {
        char md5_hex[EVP_MAX_MD_SIZE * 2 + 1];
        char sha1_hex[EVP_MAX_MD_SIZE * 2 + 1];
        char sha256_hex[EVP_MAX_MD_SIZE * 2 + 1];
        char sha512_hex[EVP_MAX_MD_SIZE * 2 + 1];

        if (finalize_hash(hashes.md5, md5_hex, sizeof(md5_hex)) != 0 ||
            finalize_hash(hashes.sha1, sha1_hex, sizeof(sha1_hex)) != 0 ||
            finalize_hash(hashes.sha256, sha256_hex, sizeof(sha256_hex)) != 0 ||
            (use_sha512 && finalize_hash(hashes.sha512, sha512_hex, sizeof(sha512_hex)) != 0)) {
            log_json(logf, "ERROR", "hash_finalize_failed", absolute_offset, NULL, NULL);
            exit_code = 1;
        } else {
            fprintf(hashf, "start_offset=%llu\n", (unsigned long long)start_offset);
            fprintf(hashf, "copied_bytes=%llu\n", (unsigned long long)copied);
            fprintf(hashf, "absolute_end_offset=%llu\n", (unsigned long long)absolute_offset);
            fprintf(hashf, "md5=%s\n", md5_hex);
            fprintf(hashf, "sha1=%s\n", sha1_hex);
            fprintf(hashf, "sha256=%s\n", sha256_hex);
            if (use_sha512) fprintf(hashf, "sha512=%s\n", sha512_hex);
            fprintf(hashf, "read_errors=%llu\n", (unsigned long long)read_errors);
            fflush(hashf);
            log_json(logf, "INFO", "acquisition_complete", absolute_offset, "dest", dest);
        }
    }

    cleanup_hashes(&hashes);
    free(buf);
    fclose(logf);
    fclose(hashf);
    close(src_fd);
    close(dst_fd);
    return exit_code;
}

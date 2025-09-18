// server.c
// Simple multi-threaded HTTP server with persistent connections + pipelining.
// Build: make
// Run: ./server <port>
// Document root: ./www

#define _POSIX_C_SOURCE 200809L
#include <strings.h>   
#include <ctype.h>     
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#define BACKLOG 128
#define BUF_SIZE 16384
#define SMALL_BUF 1024
#define DOCUMENT_ROOT "./www"
#define KEEP_ALIVE_TIMEOUT_SEC 10

static volatile bool running = true;

void handle_sigint(int signum) {
    (void)signum;
    running = false;
}

ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t left = count;
    const char *p = buf;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= n;
        p += n;
    }
    return (ssize_t)count;
}


const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcasecmp(ext, ".html") == 0 || strcasecmp(ext, ".htm") == 0) return "text/html";
    if (strcasecmp(ext, ".txt") == 0) return "text/plain";
    if (strcasecmp(ext, ".png") == 0) return "image/png";
    if (strcasecmp(ext, ".gif") == 0) return "image/gif";
    if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) return "image/jpg";
    if (strcasecmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcasecmp(ext, ".css") == 0) return "text/css";
    if (strcasecmp(ext, ".js") == 0) return "application/javascript";
    return "application/octet-stream";
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && isxdigit(a) && isxdigit(b)) {
            char hex[3] = {a, b, 0};
            *dst++ = (char) strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// join docroot + requested path safely, prevent directory traversal
// dest must be a buffer of PATH_MAX
// returns true on success, dest contains canonical path, false on error
bool build_safe_path(const char *docroot, const char *req_path, char *dest) {
    char decoded[PATH_MAX];
    url_decode(decoded, req_path);

    // If request begins with '/', skip it
    const char *p = decoded;
    if (*p == '/') p++;

    // make candidate path
    char candidate[PATH_MAX];
    snprintf(candidate, PATH_MAX, "%s/%s", docroot, p);

    // If candidate is a directory, we'll allow it and later look for index.html/htm
    // Use realpath on both docroot and candidate to ensure docroot is prefix
    char real_docroot[PATH_MAX];
    char real_candidate[PATH_MAX];
    if (!realpath(docroot, real_docroot)) return false;
    // realpath may fail for candidate if file doesn't exist; for security, we resolve as much as possible
    if (realpath(candidate, real_candidate) == NULL) {
        // Try to resolve parent directory then append tail
        char parent[PATH_MAX];
        strcpy(parent, candidate);
        char *last_slash = strrchr(parent, '/');
        if (last_slash) {
            *last_slash = '\0';
            if (!realpath(parent, real_candidate)) return false;
            // append tail
            strcat(real_candidate, "/");
            strcat(real_candidate, last_slash + 1);
        } else {
            return false;
        }
    }

    // Ensure real_candidate starts with real_docroot
    size_t len_root = strlen(real_docroot);
    if (strncmp(real_candidate, real_docroot, len_root) != 0) return false;

    // success
    strncpy(dest, real_candidate, PATH_MAX-1);
    dest[PATH_MAX-1] = '\0';
    return true;
}

// Send a formatted response header and optional body
int send_error_response(int client_fd, const char *http_version, int status_code, const char *reason_phrase, const char *extra_body) {
    char header[SMALL_BUF*4];
    char body[SMALL_BUF];
    if (extra_body) {
        snprintf(body, sizeof(body),
                 "<html><head><title>%d %s</title></head>\r\n"
                 "<body><h1>%d %s</h1><p>%s</p></body></html>\r\n",
                 status_code, reason_phrase, status_code, reason_phrase, extra_body);
    } else {
        snprintf(body, sizeof(body),
                 "<html><head><title>%d %s</title></head>\r\n"
                 "<body><h1>%d %s</h1></body></html>\r\n",
                 status_code, reason_phrase, status_code, reason_phrase);
    }
    int body_len = (int)strlen(body);
    snprintf(header, sizeof(header),
             "%s %d %s\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %d\r\n"
             "Connection: Close\r\n"
             "\r\n",
             http_version, status_code, reason_phrase, body_len);
    if (write_all(client_fd, header, strlen(header)) < 0) return -1;
    if (write_all(client_fd, body, body_len) < 0) return -1;
    return 0;
}

// Process a single request (method, path, http_version, headers). Returns:
//  0 = keep serving (connection remains open depending on Connection header and version)
// -1 = error, close socket
int process_request(int client_fd, const char *method, const char *url_path, const char *http_version, const char *headers) {
    // validate method
    bool is_get = (strcmp(method, "GET") == 0);
    bool is_head = (strcmp(method, "HEAD") == 0);
    if (!is_get && !is_head) {
        send_error_response(client_fd, http_version, 405, "Method Not Allowed", "Only GET and HEAD supported.");
        return -1;
    }

    // validate version
    if (!(strcmp(http_version, "HTTP/1.0") == 0 || strcmp(http_version, "HTTP/1.1") == 0)) {
        send_error_response(client_fd, "HTTP/1.1", 505, "HTTP Version Not Supported", "Only HTTP/1.0 and HTTP/1.1 are supported.");
        return -1;
    }

    // Determine if client wants to keep alive
    bool request_keep_alive = false;
    // Per HTTP/1.1 default is persistent unless Connection: close
    if (strcmp(http_version, "HTTP/1.1") == 0) request_keep_alive = true;
    // But check headers explicitly
    const char *h = headers;
    while (h && *h) {
        // find line end
        const char *line_end = strstr(h, "\r\n");
        int line_len = line_end ? (int)(line_end - h) : (int)strlen(h);
        if (line_len <= 0) break;
        // lower-case compare a bit
        char line[SMALL_BUF];
        int copy_len = (line_len < SMALL_BUF-1) ? line_len : SMALL_BUF-1;
        strncpy(line, h, copy_len);
        line[copy_len] = '\0';
        // header name check
        if (strncasecmp(line, "Connection:", 11) == 0) {
            // parse value
            char *val = line + 11;
            while (*val && (*val == ' ' || *val == '\t')) val++;
            if (strncasecmp(val, "close", 5) == 0) request_keep_alive = false;
            if (strncasecmp(val, "keep-alive", 10) == 0) request_keep_alive = true;
        }
        if (!line_end) break;
        h = line_end + 2;
    }

    // Build filesystem path safely
    char safe_path[PATH_MAX];
    if (!build_safe_path(DOCUMENT_ROOT, url_path, safe_path)) {
        // If build failed, treat as 404
        send_error_response(client_fd, http_version, 404, "Not Found", "The requested resource was not found.");
        return request_keep_alive ? 0 : -1;
    }

    // If it's a directory, try index.html or index.htm
    struct stat st;
    if (stat(safe_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        // append slash if not present
        size_t len = strlen(safe_path);
        if (len + 12 < PATH_MAX) {
            char idx1[PATH_MAX], idx2[PATH_MAX];
            snprintf(idx1, PATH_MAX, "%s/index.html", safe_path);
            snprintf(idx2, PATH_MAX, "%s/index.htm", safe_path);
            if (stat(idx1, &st) == 0) {
                strncpy(safe_path, idx1, PATH_MAX-1);
            } else if (stat(idx2, &st) == 0) {
                strncpy(safe_path, idx2, PATH_MAX-1);
            } else {
                // no index; return 403 or 404? Typically 403 Forbidden or 404 Not Found
                // We'll return 403 Forbidden (directory listing not allowed)
                send_error_response(client_fd, http_version, 403, "Forbidden", "Directory listing is not allowed.");
                return request_keep_alive ? 0 : -1;
            }
        }
    }

    // Now open file
    int filefd = open(safe_path, O_RDONLY);
    if (filefd < 0) {
        if (errno == EACCES) {
            send_error_response(client_fd, http_version, 403, "Forbidden", "Permission denied.");
        } else if (errno == ENOENT) {
            send_error_response(client_fd, http_version, 404, "Not Found", "The requested resource was not found.");
        } else {
            send_error_response(client_fd, http_version, 404, "Not Found", "The requested resource was not found.");
        }
        return request_keep_alive ? 0 : -1;
    }
    if (fstat(filefd, &st) < 0) {
        close(filefd);
        send_error_response(client_fd, http_version, 404, "Not Found", "The requested resource was not found.");
        return request_keep_alive ? 0 : -1;
    }

    // Prepare response headers
    const char *ctype = get_mime_type(safe_path);
    char header[SMALL_BUF*4];
    int header_len = snprintf(header, sizeof(header),
                              "%s 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %lld\r\n"
                              "Connection: %s\r\n"
                              "\r\n",
                              http_version,
                              ctype,
                              (long long)st.st_size,
                              request_keep_alive ? "Keep-alive" : "Close");

    // Send headers
    if (write_all(client_fd, header, header_len) < 0) {
        close(filefd);
        return -1;
    }

    // Send body if GET (not HEAD)
    if (is_get) {
        off_t offset = 0;
        ssize_t to_send = st.st_size;
#ifdef __linux__
        // use sendfile for efficiency
        while (to_send > 0) {
            ssize_t sent = sendfile(client_fd, filefd, &offset, (size_t)to_send);
            if (sent <= 0) {
                if (errno == EINTR) continue;
                break;
            }
            to_send -= sent;
        }
#else
        // portable fallback
        char buf[8192];
        ssize_t n;
        while ((n = read(filefd, buf, sizeof(buf))) > 0) {
            if (write_all(client_fd, buf, n) < 0) break;
        }
#endif
    }

    close(filefd);
    return request_keep_alive ? 0 : -1;
}

// Parse single HTTP request from buffer. Returns:
//  1 if a full request was parsed (and consumed `consumed` bytes), otherwise 0 (need more data).
// On success it fills method/url/http_version/headers (all as null-terminated strings).
int parse_http_request(const char *buf, size_t buf_len, size_t *consumed,
                       char *method, size_t method_sz,
                       char *url, size_t url_sz,
                       char *http_version, size_t hv_sz,
                       char *headers, size_t headers_sz) {
    // find end of headers
    const char *hdr_end = NULL;
    for (size_t i = 0; i + 3 < buf_len; ++i) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            hdr_end = buf + i + 4;
            break;
        }
    }
    if (!hdr_end) return 0; // need more data

    size_t header_total_len = hdr_end - buf;
    // copy header block
    if (header_total_len >= headers_sz) return 0; // header too large for our buffer -> treat as bad request
    memcpy(headers, buf, header_total_len);
    headers[header_total_len] = '\0';

    // first line = request line
    const char *line_end = strstr(headers, "\r\n");
    if (!line_end) return 0;
    size_t req_line_len = line_end - headers;
    char req_line[SMALL_BUF];
    if (req_line_len >= sizeof(req_line)) return 0;
    memcpy(req_line, headers, req_line_len);
    req_line[req_line_len] = '\0';

    // parse tokens: METHOD SP URL SP VERSION
    char m[SMALL_BUF], u[SMALL_BUF], v[SMALL_BUF];
    int scanned = sscanf(req_line, "%s %s %s", m, u, v);
    if (scanned != 3) return 0; // malformed
    // copy
    strncpy(method, m, method_sz-1); method[method_sz-1] = '\0';
    strncpy(url, u, url_sz-1); url[url_sz-1] = '\0';
    strncpy(http_version, v, hv_sz-1); http_version[hv_sz-1] = '\0';

    *consumed = header_total_len; // we consumed the entire header block (no body support for GET)
    return 1;
}

// Worker thread: handles a single connection until close or timeout
void *worker_thread(void *arg) {
    int client_fd = *(int*)arg;
    free(arg);

    // set socket non-blocking? We'll use select on it.
    // Keep an input buffer to handle pipelined requests
    char inbuf[BUF_SIZE];
    size_t inbuf_len = 0;

    bool keep_running = true;

    while (keep_running && running) {
        // If there is already data buffered, parse requests without waiting unless no full request yet.
        size_t consumed = 0;
        char method[SMALL_BUF], url[SMALL_BUF], http_version[SMALL_BUF], headers[BUF_SIZE];

        // try to parse existing buffer
        int parsed = parse_http_request(inbuf, inbuf_len, &consumed, method, sizeof(method), url, sizeof(url), http_version, sizeof(http_version), headers, sizeof(headers));
        if (!parsed) {
            // wait for more data with timeout
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(client_fd, &rfds);
            struct timeval tv;
            tv.tv_sec = KEEP_ALIVE_TIMEOUT_SEC;
            tv.tv_usec = 0;
            int rv = select(client_fd + 1, &rfds, NULL, NULL, &tv);
            if (rv < 0) {
                if (errno == EINTR) continue;
                break;
            } else if (rv == 0) {
                // timeout -> close persistent connection
                break;
            } else {
                if (FD_ISSET(client_fd, &rfds)) {
                    ssize_t r = recv(client_fd, inbuf + inbuf_len, sizeof(inbuf) - inbuf_len, 0);
                    if (r <= 0) {
                        // client closed or error
                        break;
                    }
                    inbuf_len += (size_t)r;
                    // loop back to parse
                    continue;
                }
            }
        } else {
            // We have a full request in inbuf (headers in headers variable)
            // We need to respond. Find headers string length (consumed), but headers we extracted includes \r\n\r\n
            // Extract header block for Connection header lookup by passing 'headers'
            // Call process_request
            int pr = process_request(client_fd, method, url, http_version, headers);
            if (pr < 0) {
                // close socket after response or on error
                break;
            } else {

                if (consumed < inbuf_len) {
                    memmove(inbuf, inbuf + consumed, inbuf_len - consumed);
                    inbuf_len -= consumed;
                    continue;
                } else {
                    inbuf_len = 0;
                    continue;
                }
            }
        }
    }

    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 2;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN);

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port\n");
        return 2;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in srvaddr;
    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.s_addr = INADDR_ANY;
    srvaddr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, BACKLOG) < 0) { perror("listen"); return 1; }

    printf("Server listening on port %d, document root: %s\n", port, DOCUMENT_ROOT);

    while (running) {
        struct sockaddr_in cliaddr;
        socklen_t cli_len = sizeof(cliaddr);
        int client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &cli_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(cliaddr.sin_addr), ipstr, sizeof(ipstr));
        printf("Accepted connection from %s:%d\n", ipstr, ntohs(cliaddr.sin_port));

        // create a detached thread for each client
        pthread_t tid;
        int *pclient = malloc(sizeof(int));
        if (!pclient) { close(client_fd); continue; }
        *pclient = client_fd;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, worker_thread, pclient) != 0) {
            perror("pthread_create");
            close(client_fd);
            free(pclient);
        }
        pthread_attr_destroy(&attr);
    }

    close(server_fd);
    printf("Server shutting down.\n");
    return 0;
}

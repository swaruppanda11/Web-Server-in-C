#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BACKLOG 128
#define BUF_SIZE 8192
#define SMALL_BUF 1024
#define DOCUMENT_ROOT "./www"
#define KEEP_ALIVE_TIMEOUT 10

static volatile bool running = true;

void handle_sigint(int s) { (void)s; running = false; }

ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t left = count;
    const char *p = buf;
    while(left > 0){
        ssize_t n = write(fd, p, left);
        if(n <= 0) {
            if(errno == EINTR) continue;
            return -1;
        }
        left -= n;
        p += n;
    }
    return count;
}

const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path,'.');
    if(!ext) return "application/octet-stream";
    if(!strcasecmp(ext,".html") || !strcasecmp(ext,".htm")) return "text/html";
    if(!strcasecmp(ext,".txt")) return "text/plain";
    if(!strcasecmp(ext,".png")) return "image/png";
    if(!strcasecmp(ext,".gif")) return "image/gif";
    if(!strcasecmp(ext,".jpg") || !strcasecmp(ext,".jpeg")) return "image/jpg";
    if(!strcasecmp(ext,".ico")) return "image/x-icon";
    if(!strcasecmp(ext,".css")) return "text/css";
    if(!strcasecmp(ext,".js")) return "application/javascript";
    return "application/octet-stream";
}

// Portable case-insensitive substring search
char *strcasestr_local(const char *haystack, const char *needle) {
    size_t nlen = strlen(needle);
    for(; *haystack; haystack++) {
        if(strncasecmp(haystack, needle, nlen) == 0)
            return (char*)haystack;
    }
    return NULL;
}

void url_decode(char *dst, const char *src) {
    char a,b;
    while(*src){
        if(*src=='%' && ((a=src[1]) && (b=src[2])) && isxdigit(a) && isxdigit(b)){
            char hex[3]={a,b,0};
            *dst++=(char)strtol(hex,NULL,16);
            src+=3;
        } else if(*src=='+'){ *dst++=' '; src++; }
        else *dst++=*src++;
    }
    *dst='\0';
}

bool build_safe_path(const char *docroot, const char *req_path, char *dest) {
    char decoded[BUF_SIZE];
    url_decode(decoded, req_path);
    const char *p = decoded;
    if(*p=='/') p++;
    snprintf(dest, BUF_SIZE, "%s/%s", docroot, p);
    char real_root[BUF_SIZE], real_path[BUF_SIZE];
    if(!realpath(docroot, real_root)) return false;
    if(!realpath(dest, real_path)) return false;
    if(strncmp(real_root, real_path, strlen(real_root)) !=0) return false;
    strncpy(dest, real_path, BUF_SIZE-1);
    dest[BUF_SIZE-1]='\0';
    return true;
}

int send_error(int fd, const char *ver, int code, const char *msg){
    char buf[BUF_SIZE];
    int len = snprintf(buf,sizeof(buf),
        "%s %d %s\r\nContent-Type:text/html\r\nContent-Length:%zu\r\nConnection: Close\r\n\r\n"
        "<html><body><h1>%d %s</h1></body></html>",
        ver, code, msg, strlen(msg)+26, code,msg);
    write_all(fd, buf,len);
    return -1;
}

int handle_request(int fd, char *buf, size_t len){
    char method[SMALL_BUF], path[SMALL_BUF], ver[SMALL_BUF];
    if(sscanf(buf,"%s %s %s",method,path,ver)!=3) return send_error(fd,"HTTP/1.1",400,"Bad Request");
    if(strcmp(method,"GET") && strcmp(method,"HEAD")) return send_error(fd,ver,405,"Method Not Allowed");
    if(strcmp(ver,"HTTP/1.0") && strcmp(ver,"HTTP/1.1")) return send_error(fd,"HTTP/1.1",505,"HTTP Version Not Supported");

    bool keep_alive = (strcmp(ver,"HTTP/1.1")==0);
    char *conn = strcasestr_local(buf,"Connection:");
    if(conn){
        if(strcasestr_local(conn,"close")) keep_alive=false;
        if(strcasestr_local(conn,"keep-alive")) keep_alive=true;
    }

    char full_path[BUF_SIZE];
    if(!build_safe_path(DOCUMENT_ROOT,path,full_path)) return send_error(fd,ver,404,"Not Found");
    struct stat st;
    if(stat(full_path,&st)<0) return send_error(fd,ver,404,"Not Found");
    if(S_ISDIR(st.st_mode)){
        char idx[BUF_SIZE];
        snprintf(idx,sizeof(idx),"%s/index.html",full_path);
        if(stat(idx,&st)==0) strncpy(full_path,idx,sizeof(full_path));
        else { snprintf(idx,sizeof(idx),"%s/index.htm",full_path); if(stat(idx,&st)==0) strncpy(full_path,idx,sizeof(full_path)); else return send_error(fd,ver,403,"Forbidden"); }
    }

    int f=open(full_path,O_RDONLY);
    if(f<0) return send_error(fd,ver,403,"Forbidden");

    char header[BUF_SIZE];
    int header_len = snprintf(header,sizeof(header),
        "%s 200 OK\r\nContent-Type: %s\r\nContent-Length: %lld\r\nConnection: %s\r\n\r\n",
        ver,get_mime_type(full_path),(long long)st.st_size,keep_alive?"Keep-alive":"Close");
    write_all(fd,header,header_len);

    if(strcmp(method,"GET")==0){
        char data[BUF_SIZE];
        ssize_t r;
        while((r=read(f,data,sizeof(data)))>0) write_all(fd,data,r);
    }
    close(f);
    return keep_alive ? 0 : -1;
}

void *worker(void *arg){
    int cfd=*(int*)arg; free(arg);
    char buf[BUF_SIZE]; ssize_t n;
    while((n=recv(cfd,buf,sizeof(buf)-1,0))>0){
        buf[n]='\0';
        if(handle_request(cfd,buf,n)<0) break;
    }
    close(cfd);
    return NULL;
}

int main(int argc,char *argv[]){
    if(argc!=2){ fprintf(stderr,"Usage: %s <port>\n",argv[0]); return 1; }
    signal(SIGINT,handle_sigint);

    int port=atoi(argv[1]);
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    int opt=1; setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family=AF_INET; addr.sin_port=htons(port); addr.sin_addr.s_addr=INADDR_ANY;

    if(bind(sfd,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); return 1; }
    if(listen(sfd,BACKLOG)<0){ perror("listen"); return 1; }

    printf("Server listening on port %d\n",port);

    while(running){
        struct sockaddr_in cli; socklen_t len=sizeof(cli);
        int *cfd=malloc(sizeof(int));
        if(!cfd) continue;
        *cfd=accept(sfd,(struct sockaddr*)&cli,&len);
        if(*cfd<0){ free(cfd); continue; }
        pthread_t tid; pthread_create(&tid,NULL,worker,cfd);
        pthread_detach(tid);
    }

    close(sfd);
    printf("Server shutting down.\n");
    return 0;
}

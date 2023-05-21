
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "util.h"

int connect_to_host(char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Could not create socket");
        return (-1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Error connecting to socket");
        return (-1);
    }

    return sockfd;
}

int make_listen_port(int port) {
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Could not create socket");
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Could not bind socket");
        return 0;
    }

    if (listen(sockfd, 20) < 0) {
        perror("Error listening on socket");
        return 0;
    }

    return sockfd;
}

// 计算一个打开文件的字节数
int file_len(FILE *fp) {
    int sz;
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    rewind(fp);
    return sz;
}

// recvline(int fd, char **line)
// 描述: 从套接字fd接收字符串
// 输入: 套接字描述符fd, 将接收的行数据写入line
// 输出: 读取的字节数
int recvline(int fd, char **line) {
    int retVal;
    int lineIndex = 0;
    int lineSize = 128;

    *line = (char *) malloc(sizeof(char) * lineSize);

    if (*line == NULL) {
        perror("malloc");
        return -1;
    }

    while ((retVal = read(fd, *line + lineIndex, 1)) == 1) {
        if ('\n' == (*line)[lineIndex]) {
            (*line)[lineIndex] = 0;
            break;
        }

        lineIndex += 1;

        /*
          如果获得的字符太多, 就重新分配行缓存.
        */
        if (lineIndex > lineSize) {
            lineSize *= 2;
            char *newLine = realloc(*line, sizeof(char) * lineSize);

            if (newLine == NULL) {
                retVal = -1; /* realloc失败 */
                break;
            }

            *line = newLine;
        }
    }

    if (retVal < 0) {
        free(*line);
        return -1;
    }
#ifdef NDEBUG
    else
    {
      fprintf(stdout, "%03d> %s\n", fd, *line);
    }
#endif

    return lineIndex;
}
/* End recvline */

// recvlinef(int fd, char *format, ...)
// 描述: 从套接字fd接收字符串.这个函数允许你指定一个格式字符串, 并将结果存储在指定的变量中
// 输入: 套接字描述符fd, 格式字符串format, 指向用于存储结果数据的变量的指针
// 输出: 读取的字节数
int recvlinef(int fd, char *format, ...) {
    va_list argv;
    va_start(argv, format);

    int retVal = -1;
    char *line;
    int lineSize = recvline(fd, &line);

    if (lineSize > 0) {
        retVal = vsscanf(line, format, argv);
        free(line);
    }

    va_end(argv);

    return retVal;
}

ssize_t readn(int f, void *av, int n) {
    char *a;
    ssize_t m, t;

    a = av;
    t = 0;
    while (t < n) {
        m = read(f, a + t, n - t);
        if (m <= 0) {
            if (t == 0)
                return m;
            break;
        }
        t += m;
    }
    return t;
}

/* End recvlinef */

int reverse_byte_orderi(int i) {
    unsigned char c1, c2, c3, c4;
    c1 = i & 0xFF;
    c2 = (i >> 8) & 0xFF;
    c3 = (i >> 16) & 0xFF;
    c4 = (i >> 24) & 0xFF;
    return ((int) c1 << 24) + ((int) c2 << 16) + ((int) c3 << 8) + c4;
}

int equal_sha1(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 20) == 0;
}


long now_seconds() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
}
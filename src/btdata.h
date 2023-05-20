
#include <pthread.h>
#include <stdio.h>
#include "bencode.h"
#include "bitfield.h"
#include "pwp.h"

#ifndef BTDATA_H
#define BTDATA_H

/**************************************
 * 一些常量定义
**************************************/

// 用于标识peer的状态
#define BT_STARTED 0
#define BT_STOPPED 1
#define BT_COMPLETED 2

/**************************************
 * 数据结构
**************************************/
// Tracker HTTP响应的数据部分
typedef struct _tracker_response {
    int size;       // B编码字符串的字节数
    char *data;     // B编码的字符串
} tracker_response;

// 元信息文件中包含的数据
typedef struct _torrentmetadata {
    int info_hash[5]; // torrent的info_hash值(info键对应值的SHA1哈希值)
    char *announce; // tracker的URL
    int length;     // 文件长度, 以字节为单位
    char *name;     // 文件名
    int piece_len;  // 每一个分片的字节数
    int num_pieces; // 分片数量
    char *pieces;   // 针对所有分片的20字节长的SHA1哈希值连接而成的字符串
} torrentmetadata_t;

// 包含在announce url中的数据(例如, 主机名和端口号)
typedef struct _announce_url_t {
    char *hostname;
    int port;
} announce_url_t;

// 由tracker返回的响应中peers键的内容
typedef struct _peerdata {
    char id[21]; // id[20]用于null终止符
    int port;
    char *ip; // 15 + 1 byte
} peerdata;

// 包含在tracker响应中的数据
typedef struct _tracker_data {
    int interval;
    int numpeers;
    peerdata *peers;
} tracker_data;

typedef struct _tracker_request {
    int info_hash[5];
    char peer_id[20];
    int port;
    int uploaded;
    int downloaded;
    int left;
    char ip[16]; // 自己的IP地址, 格式为XXX.XXX.XXX.XXX, 最后以'\0'结尾
} tracker_request;

/**************************************
 * 全局变量 
**************************************/
char g_my_ip[128]; // 格式为XXX.XXX.XXX.XXX, null终止
int g_peerport; // peer监听的端口号
int g_infohash[5]; // 要共享或要下载的文件的SHA1哈希值, 每个客户端同时只能处理一个文件
uint8_t g_my_id[20];

// 位域, 用于标记哪些分片已经下载
bitfield_t *g_bitfield;
pthread_mutex_t g_bitfield_lock;
#define LOCK_BITFIELD pthread_mutex_lock(&g_bitfield_lock)
#define UNLOCK_BITFIELD pthread_mutex_unlock(&g_bitfield_lock)

// 用于存储所有peer的数组, 以及对它的访问控制
peer_t *g_peers[MAXPEERS];
pthread_mutex_t g_peers_lock;
#define LOCK_PEERS pthread_mutex_lock(&g_peers_lock)
#define UNLOCK_PEERS pthread_mutex_unlock(&g_peers_lock)


int g_done; // 表明程序是否应该终止

torrentmetadata_t *g_torrentmeta;
FILE *g_file;   // 要下载的文件
int g_filelen;  // 要下载的文件的长度
int g_num_pieces;   // 分片数量
int g_piece_len;    // 每个分片的字节数
char *g_filename;   // 要下载的文件的文件名

char g_tracker_ip[16]; // tracker的IP地址, 格式为XXX.XXX.XXX.XXX(null终止)
int g_tracker_port;
tracker_data *g_tracker_response;

// 这些变量用在函数make_tracker_request中, 它们需要在客户端执行过程中不断更新.
int g_uploaded;    // 已经上传的字节数
int g_downloaded;   // 已经下载的字节数
int g_left; // 还需要下载的字节数
#define is_seed() (g_left == 0)

#endif

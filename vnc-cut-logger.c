#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <err.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/des.h>

#define server_info_size (sizeof(struct server_info)-sizeof(char *))

struct server_info {
    uint16_t width;
    uint16_t height;
    uint8_t pixels[16];
    uint32_t name_length;
    char *name;
};

struct server_cut_text {
    uint8_t message_type;
    uint8_t padding[3];
    uint32_t length;
    char text[];
};

void pretty_print(const char *str, uint32_t len){
    static const char htable[]="0123456789abcdef";

    char timestr[32], buf[80];
    uint32_t offset, count = 0, ch_offset, i, j;
    struct timeval tv;
    struct tm *tm;


    gettimeofday(&tv, NULL);

    tm = gmtime(&tv.tv_sec);

    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm);
    printf("[%s.%06ld] size: %u\n", timestr, tv.tv_usec, len);

    while(len){
        ch_offset = 54;
        offset = 13;
        j = 0;

        sprintf(buf, " 0x%08x: ", count);

        if(len > 16){
            len -= 16;
            i = 16;
        } else {
            i = len;
            len = 0;
        }

        while(j<i){
            char ch = *str++;
            buf[offset++] = htable[ch/16];
            buf[offset++] = htable[ch%16];

            buf[ch_offset++] = isprint(ch) ? ch : '.';
            j++;

            if(!(j%2))
                buf[offset++] = ' ';

        }

        buf[ch_offset] = 0x0;
        memset(buf+offset, ' ', 54-offset);

        puts(buf);
        count += 16;
    }
}

int auth(int fd, const char *password){
    DES_key_schedule schedule;
    char protocolVersion[12];
    char securityType[256];
    char challenge[16];
    char key[16];

    int noauth = 0, vnc_auth = 0;
    int i = 0, n, ret = 1;

    if(password){
        for(i=0; i<8; i++){
            key[i] = password[i];
            if(key[i] == 0x0)
                break;
        }
    }

    while(i<8)
        key[i++] = 0x0;

    if((n = recv(fd, protocolVersion, 12, 0)) != 12)
        goto end;

    send(fd, "RFB 003.008\n", 12, 0);

    n = recv(fd, securityType, sizeof(securityType), 0);
    if(n < 2 || n != securityType[0]+1)
        goto end;


    for(i=1; i<=securityType[0]; i++){
        if(securityType[i] == 0x1)
            noauth++;
        else if(securityType[i] == 0x2)
            vnc_auth++;
    }

    if(vnc_auth){
        send(fd, "\x02", 1, 0);
    }

    else if(noauth){
        send(fd, "\x01", 1, 0);
        goto auth_check;
    }

    else {
        goto end;
    }

    if(recv(fd, challenge, 16, 0) != 16)
        goto end;

    for (i = 0; i < 8; i++) {
        key[i] = (key[i] & 0xf0) >> 4 | (key[i] & 0x0f) << 4;
        key[i] = (key[i] & 0xcc) >> 2 | (key[i] & 0x33) << 2;
        key[i] = (key[i] & 0xaa) >> 1 | (key[i] & 0x55) << 1;
    }

    DES_set_key((const_DES_cblock *)key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)challenge, (const_DES_cblock *)challenge, &schedule, DES_ENCRYPT);
    DES_ecb_encrypt((const_DES_cblock *)(challenge+8), (const_DES_cblock *)(challenge+8), &schedule, DES_ENCRYPT);

    send(fd, challenge, 16, 0);

    auth_check:

    if(recv(fd, &ret, 4, 0) != 4)
        ret = 1;

    end:
    return ret;
}

int server_info(int fd, struct server_info *info){

    send(fd, "\x01", 1, 0);

    if(recv(fd, info, server_info_size, 0) != server_info_size)
        return 1;

    info->name_length = ntohl(info->name_length);

    info->name = malloc(info->name_length+1);
    if(info->name == NULL)
        err(1, "malloc (%u)", info->name_length+1);

    if(recv(fd, info->name, info->name_length, 0) != info->name_length)
        return 1;

    info->height = ntohs(info->height);
    info->width = ntohs(info->width);

    info->name[info->name_length] = 0x0;

    return 0;
}

int main(int argc, char **argv){
    struct sockaddr_in addr;
    struct server_info info;
    struct server_cut_text *cut;

    size_t bsize;
    ssize_t n;
    int fd;

    if(argc < 3){
        printf("vnc-cut-logger ip port [password]\n");
        return 0;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1)
        err(1, "socket");

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    addr.sin_port = htons(atoi(argv[2]));

    printf("connecting ...\n");
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        err(1, "connect");

    printf("authenticating ...\n");
    if(auth(fd, argv[3])){
        printf("auth failed\n");
        return 1;
    }

    printf("retrieving server information ...\n");

    if(server_info(fd, &info)){
        printf("failed to retrieve server information\n");
        return 1;
    }

    printf("--- server info: (%hux%hu) '%s'\n", info.width, info.height, info.name);

    bsize = 512;
    if((cut = malloc(bsize)) == NULL)
        err(1, "malloc");

    printf("waiting for serverCutText events\n");


    while(1){
        if((n = recv(fd, cut, 8, 0)) != 8)
            break;

        cut->length = ntohl(cut->length);
        if(cut->length+8 > bsize){
            bsize = cut->length+8;

            if((cut = realloc(cut, bsize)) == NULL)
                err(1, "realloc");

        }

        if(recv(fd, (char*)cut+8, cut->length, 0) != cut->length)
            break;

        pretty_print(cut->text, cut->length);
    }

    return 0;
}

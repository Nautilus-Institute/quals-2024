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
#include <stdint.h>
#include <string.h>


#include "walk.h"


struct bufData * ringStart;



#define CSTATE_SIZE 2048
    int cStateI = 0;
    int cStateJ = 0;
struct cryptoStruct {
    uint8_t cryptoStateRead[CSTATE_SIZE];
    uint8_t cryptoStateWrite[CSTATE_SIZE];
    uint8_t cryptoKey[KEYSIZE];
    char urandom[64];
};

static struct cryptoStruct globalCrypt;


static int baseFD;
int do_tcp_accept(int lfd);
void handle_sigchld(int sig) ;
int do_tcp_listen(const char *server_ip, uint16_t port);
void pipeHandle(int sig);
void fpeHandle(int sig);
static int writeData(uint8_t * buf, unsigned int length);
static void initPRGA(uint8_t * cryptoState, int tweak);
static char PRGA(uint8_t * cryptoState) ;
void printBlockData(struct bufData * cBlock);
static int readData(uint8_t * buf, unsigned int length);

#ifdef DEBUG
int debugFD;
#endif

void pipeHandle(int sig)
{
    LOGI("I got a pipe\n");
    return ;
}

#ifdef DEBUG
void printBuf(uint8_t * buf, int len)
{
    for(int i = 0; i < len; i++)
    {
        if(i % 64 ==0)
        {
            LOGI("\n%04X: ", i);
        }
        LOGI("%02X", buf[i]);
    }
    LOGI("\n");
}
#endif

static void __attribute__((always_inline)) initPRGA(uint8_t * cryptoState, int tweak)
{
    int j = 0;
    for(int i =0; i < CSTATE_SIZE; i++)
    {
        cryptoState[i] = i%256;
    }

    for(int i = 0; i < CSTATE_SIZE*2; i++)
    {
        unsigned int tmp = globalCrypt.cryptoKey[(i+j) % KEYSIZE];
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

    offset1 = ((cStateI * cStateJ ) ^ 0xfefe) % CSTATE_SIZE;

    tmp = cryptoState[offset1];
    cryptoState[offset1] = cryptoState[(cStateJ + cStateI) % CSTATE_SIZE];
    cryptoState[(cStateJ + cStateI) % CSTATE_SIZE] = tmp;

    return ret;

}



void fpeHandle(int sig)
{

    return ;
}


void handle_sigchld(int sig) {
  int saved_errno = errno;
  while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
  errno = saved_errno;
}


static int __attribute__((always_inline))  readData(uint8_t * buf, unsigned int length)
{
    int readLen = 0;
    while(readLen < length)
    {
        int tempLen = read(STDINFD, &buf[readLen], length - readLen);
        if(tempLen < 0)
        {
            return -1;   
        }
        readLen += tempLen;
    }

    for(int i =0; i < readLen; i++)
    {
        buf[i] = buf[i] ^ PRGA(globalCrypt.cryptoStateRead);
    }

    return readLen;
}

static int __attribute__((always_inline))  writeData(uint8_t * buf, unsigned int length)
{
    int readLen = 0;
    for(int i =0; i < length; i++)
    {
        buf[i] = buf[i] ^ PRGA(globalCrypt.cryptoStateWrite);
    }

    while(readLen < length)
    {
        int tempLen = write(STDOUTFD, &buf[readLen], length - readLen);
        if(tempLen < 0)
        {
            return -1;   
        }
        readLen += tempLen;
    }
    return readLen;
}


int do_tcp_listen(const char *server_ip, uint16_t port)
{
    struct sockaddr_in addr;
    int optval = 1;
    int lfd;
    int ret;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        LOGI("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        LOGI("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
        LOGI("set sock reuseaddr failed\n");
    }
    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        LOGI("bind failed %s:%d\n", server_ip, port);
        goto err_handler;
    }

    LOGI("TCP listening on %s:%d...\n", server_ip, port);
    ret = listen(lfd, TCP_MAX_LISTEN_COUNT);
    if (ret) {
        LOGI("listen failed\n");
        goto err_handler;
    }
    LOGI("TCP listen fd=%d\n", lfd);
    return lfd;
err_handler:
    close(lfd);
    return -1;
}




int do_tcp_accept(int lfd)
{
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int cfd;

    LOGI("\n\n###Waiting for TCP connection from client...\n");
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        LOGI("accept failed, errno=%d\n", errno);
        return -1;
    }

    LOGI("TCP connection accepted fd=%d\n", cfd);
    return cfd;
}

static void __attribute__((always_inline))  coalesceBlocks(void)
{
    struct bufData * cBlock = ringStart;
    while(cBlock && cBlock->next)
    {
        if((cBlock->flags & BLOCK_USED == 0) &&
            (cBlock->flags & BLOCK_USED == 0))
        {
            if(cBlock->next->flags & LAST_BLOCK)
            {
                cBlock->flags = LAST_BLOCK;
            }

            cBlock->size += cBlock->next->size + sizeof(struct bufData);
            cBlock->next=cBlock->next->next;
            if(cBlock->next)
            {
                cBlock->next->prev = cBlock;
            }
        }
        cBlock = cBlock->next;
    }
}


static void __attribute__((always_inline)) doAlloc()
{
    unsigned int size;
    struct bufData * cBlock = ringStart;
    int i = 0;

    if(readData((uint8_t*) &size, sizeof(size)) < 0)
    {
        exit(0);
    }

    LOGI("In alloc block of size %u\n", size);
    while(cBlock)
    {
        i++;

        if(((cBlock->flags & BLOCK_USED) == 0) && ((cBlock->size + sizeof(struct bufData)) > size))
        {

            LOGI("Allocating %p\n", cBlock);
            LOGI("Checking Block %d %d %d %d\n",i++, (cBlock->flags & BLOCK_USED)==0, cBlock->size + sizeof(struct bufData), size );

            struct bufData * nextBlock = cBlock->next;
            cBlock->next = (struct bufData *) (((uintptr_t)cBlock) + sizeof(struct bufData) + size);
            LOGI("CB=%p CBN=%p DIFF = %u %u\n", cBlock, cBlock->next, (uintptr_t)cBlock->next - (uintptr_t)cBlock, size);
            if(nextBlock) {
                nextBlock->prev = cBlock->next;
            }
            
            cBlock->flags = BLOCK_USED;
            cBlock->next->next = nextBlock;
            cBlock->next->flags = BLOCK_FREE;
            cBlock->next->prev = cBlock;

            cBlock->next->size = cBlock->size - size - sizeof(struct bufData);
            cBlock->size = size;
            cBlock->allocFunc = (uintptr_t)doAlloc;
            break;
        }
        cBlock = cBlock->next;   
    }
}

static void __attribute__((always_inline)) innerFree()
{
    unsigned int size;
    struct bufData * cBlock = ringStart;
    int whichBlock = 0;
    int blockCountNum = 0;
    
    if(readData((uint8_t*) &whichBlock, sizeof(whichBlock)) < 0)
    {
        exit(0);
    }

    LOGI("Attempting to freeBlock = %d %d\n", whichBlock, blockCountNum);
    while(cBlock != NULL)
    {
        LOGI("OnBlock %d\n", blockCountNum);
        if(whichBlock == blockCountNum)
        {
            LOGI("Freeing Block %p %p\n", cBlock, cBlock->prev);
            if(cBlock->prev)
            {
                LOGI("Fixing Prev Block\n");
                if(cBlock->next)
                {
                    cBlock->next->prev=cBlock->prev;
                }
                cBlock->prev->next=cBlock->next;
                cBlock->prev->flags = cBlock->prev->flags ^ BLOCK_USED;
                cBlock->prev->size += cBlock->size + sizeof(struct bufData);
            }

            coalesceBlocks();
            break;
        }
        cBlock = cBlock->next;
        blockCountNum++;
    }

    return;
}

void printBlockData(struct bufData * cBlock)
{
    LOGI("CBlock = %p\n", cBlock);
    LOGI("Next = %p\n", cBlock->next);
    LOGI("Prev = %p\n", cBlock->prev);
    LOGI("Size = %ld\n", cBlock->size);
    LOGI("Flags = %ld %d %d\n", cBlock->flags, BLOCK_USED, cBlock->flags & BLOCK_USED);
    LOGI("\n\n");
}

static void __attribute__((always_inline))  doStats()
{

    LOGI("Giving Flags\n");
    int flags = ringStart->flags;
    writeData((void*) &(ringStart->flags), sizeof(ringStart->flags));
    ringStart->flags = flags;

    struct bufData * cBlock = ringStart;
    LOGI("Doing Stats=%p %p\n", cBlock, cBlock->next);
    while(cBlock)
    {
        printBlockData(cBlock);
        cBlock = cBlock->next;
    }
}

static void __attribute__((always_inline))  doBug()
{
    int whichBlock, sizeToWrite;
    struct bufData * cur = ringStart;
    if(readData((uint8_t*) &sizeToWrite, sizeof(sizeToWrite)) < 0)
    {
        exit(0);
    }
    if(readData((uint8_t*) &whichBlock, sizeof(whichBlock)) < 0)
    {
        exit(0);
    }

    for(int i = 0; i < whichBlock; i++)
    {
        if(cur == NULL)
        {
            return;
        }
        cur=cur->next;
    }

    if((cur->flags & BLOCK_USED != 0))
    {
        for(int i = 0; i < sizeToWrite; i++)
        {
            cur->data[i] = cur->data[i] ^ PRGA(globalCrypt.cryptoStateWrite);
        }
    }
}

static void  __attribute__((always_inline)) doPropogateData()
{
    int whichBlock, sizeToWrite;
    struct bufData * cur = ringStart;
    if(readData((uint8_t*) &whichBlock, sizeof(whichBlock)) < 0)
    {
        LOGI("WTF2\n");
        exit(0);
    }
    if(readData((uint8_t*) &sizeToWrite, sizeof(sizeToWrite)) < 0)
    {
        LOGI("WTF1\n");
        exit(0);
    }
    LOGI("WTF3 %d %d\n", whichBlock, sizeToWrite);
    for(int i = 0; i < whichBlock; i++)
    {
        if(cur == NULL)
        {
            return;
        }
        cur=cur->next;
    }
    LOGI("Writing %d into %d(%p) %d %d\n",sizeToWrite, whichBlock, cur, cur->size, cur->flags & BLOCK_USED);
    if((cur->flags & BLOCK_USED != 0) && ( cur->size > sizeToWrite))
    {
        LOGI("Doing write %p %d\n",&cur->data[0], sizeToWrite);
        readData(&cur->data[0], sizeToWrite);
    }    
}

static void __attribute__((always_inline)) processBlocks()
{
    struct bufData * cBlock = ringStart;
    __int128 avg = 0;
    unsigned long long count = 0;
    
    while(cBlock)
    {
        if(cBlock->flags & BLOCK_USED)
        {
            for(int i = 0 ; i < cBlock->size; i+= sizeof(avg))
            {
                avg += *(uint64_t *)&cBlock->data[i];
                count++;
            }
        }
        cBlock = cBlock->next;
    }
    writeData((void*) &avg, sizeof(avg));
    writeData((void*) &count, sizeof(count));
}

static void __attribute__((always_inline)) getBlockData()
{
    struct bufData * cBlock = ringStart;

    unsigned long long count = 0;
    int whichBlock  = 0;
    readData(&whichBlock, sizeof(whichBlock));
    LOGI("Getting block %d\n", whichBlock);
    
    while(cBlock)
    {
        if(whichBlock == 0)
        {
            unsigned int cBlockSize = cBlock->size;
            LOGI("Writing block %p of size %d\n", cBlock, cBlock->size);
            writeData(&cBlock->size, sizeof(cBlock->size));
            LOGI("Wrote Size %d\n", cBlockSize);
            writeData(&cBlock->data[0], cBlockSize);
            LOGI("Wrote Data\n");
            break;
        }
        whichBlock--;
        cBlock = cBlock->next;
    }

}

void rekey(void)
{
    LOGI("Opening URANDOM FD %s\n", globalCrypt.urandom);
    int urandomFd = open(globalCrypt.urandom, O_RDONLY);
    if(read(urandomFd, globalCrypt.cryptoKey, KEYSIZE) <= 0)
    {
        exit(3);
    }
    close(urandomFd);
    if(write(STDOUTFD, globalCrypt.cryptoKey, KEYSIZE) <= 0)
    {
        exit(4);
    }

}
void doChallenge()
{

    int cmd;
    ringStart = malloc(BUCKET_SIZE);
    ringStart->next = NULL;
    ringStart->prev = NULL;
    ringStart->flags =  FIRST_BLOCK | LAST_BLOCK;
    ringStart->size = BUCKET_SIZE;

    strcpy(globalCrypt.urandom, "/dev/urandom");

#ifdef DEBUG
    unlink("blah.log");
    debugFD =  open("blah.log", O_CREAT | O_WRONLY, 0777);
#endif
    LOGI("STARTING\n");
    LOGI("Alloct Ptr = %p CBLOCK = %d %p\n",doAlloc, sizeof(struct bufData), &globalCrypt.urandom);
    rekey();

    initPRGA(globalCrypt.cryptoStateRead,1);
    initPRGA(globalCrypt.cryptoStateWrite,31);


	while(1)
	{
        if(readData((uint8_t*) &cmd, sizeof(cmd)) < 0)
        {
            LOGI("CMD FAILED\n");
            exit(0);
        }
        LOGI("Got CMD = %d\n", cmd);

        switch(cmd)
        {
            case CMD_ALLOC:
                doAlloc();
                break;
            case CMD_STATS:
                LOGI("Stats?\n");
                doStats();
                break;
            case CMD_READINTOBUF:
                doPropogateData();
                break;
            case CMD_REKEY:
                rekey();
                break;
            case CMD_PROCESS:
                processBlocks();
                break;
            case CMD_FREE:
                innerFree();
                break;
            case CMD_BUG:
                doBug();
                break;
            case CMD_NOP:
#ifdef DEBUG
            printBuf(ringStart, BUCKET_SIZE);
#endif
                break;
            case CMD_GETDATA:
                getBlockData();
                break;
            default:
                LOGI("WTF %s\n", globalCrypt.urandom);
                doStats();
                exit(0);

        }

	}
}

int main()
{

    struct sigaction sa;

    sa.sa_handler = &handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, 0) == -1) {
      perror(0);
      exit(1);
    }

    sa.sa_handler = &pipeHandle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGPIPE, &sa, 0) == -1) {
      perror(0);
      exit(1);
    }


    alarm(50);

    doChallenge();
}
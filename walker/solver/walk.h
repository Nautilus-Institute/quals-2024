#ifndef _WALK_H

#ifdef DEBUG
#define DEBUG_PRINT
#endif

#ifdef DEBUG_PRINT
extern int debugFD;
#define LOGI(format, args ...) dprintf(debugFD, format, ## args );
#else
#define LOGI(...)           do { } while(0)
#endif

#define TCP_MAX_LISTEN_COUNT 20
#define WALK_PORT 4444

#define BUCKET_SIZE         (2048*8)
#define CMD_ALLOC           1
#define CMD_FREE            2
#define CMD_STATS			3
#define CMD_REKEY			4
#define CMD_PROCESS			5
#define CMD_GETDATA			6
#define CMD_READINTOBUF		7
#define CMD_BUG				8
#define CMD_NOP				9

#define BLOCK_FREE			0	
#define BLOCK_USED			(1<<0)
#define FIRST_BLOCK			(1<<1)
#define LAST_BLOCK			(1<<2)

#define KEYSIZE				(128)

struct bufData {
	struct bufData * next;
	struct bufData * prev;
	uintptr_t allocFunc;
	int flags;
	unsigned int size;
	uint8_t data[0];
} ;
extern struct bufData * ringStart;


#define STDINFD 0
#define STDOUTFD 1

#endif //walk_h
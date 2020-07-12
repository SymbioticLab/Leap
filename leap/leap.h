#ifndef LEAP_H
#define LEAP_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/fcntl.h>
#include <linux/cpumask.h>
#include <linux/configfs.h>
#include <linux/delay.h>

#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <asm/pci.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

//for stackbd
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <trace/events/block.h>

#define LAST_IN_BATCH sizeof(uint32_t)

#define SUBMIT_HEADER_SIZE (SUBMIT_BLOCK_SIZE +	    \
			    LAST_IN_BATCH +	    \
			    sizeof(struct raio_command))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define MAX_SGL_LEN 1	/* kernel 4.x only supports single page request*/
#else
#define MAX_SGL_LEN 32	/* max pages in a single struct request (swap IO request) */
#endif

// from kernel 
/*  host to network long long
 *  endian dependent
 *  http://www.bruceblinn.com/linuxinfo/ByteOrder.html
 */
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
		    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

#define htonll2(x) cpu_to_be64((x))
#define ntohll2(x) cpu_to_be64((x))


#define MAX_MSG_LEN	    512
#define MAX_PORTAL_NAME	  1024
#define MAX_IS_DEV_NAME   256
#define SUPPORTED_DISKS	    256
#define SUPPORTED_PORTALS   5
#define IS_SECT_SIZE	    512
#define IS_SECT_SHIFT	    ilog2(IS_SECT_SIZE)
#define IS_QUEUE_DEPTH    256
#define QUEUE_NUM_MASK	0x001f	//used in addr->(mapping)-> rdma_queue in IS_main.c

//backup disk / swap space  size (GB)
#define STACKBD_SIZE_G	35
#define BACKUP_DISK	"/dev/sda4"
//how may pages can be added into a single bio (128KB = 32 x 4KB)
#define BIO_PAGE_CAP	32

#define STACKBD_REDIRECT_OFF 0
#define STACKBD_REDIRECT_ON  1
#define STACKBD_BDEV_MODE (FMODE_READ | FMODE_WRITE | FMODE_EXCL)
#define KERNEL_SECTOR_SIZE 512
#define STACKBD_DO_IT _IOW( 0xad, 0, char * )
#define STACKBD_NAME "stackbd"
#define STACKBD_NAME_0 STACKBD_NAME "0"

#define IS_PAGE_SIZE 4096

//bitmap
#define INT_BITS 32
#define IS_PAGE_SHIFT ilog2(IS_PAGE_SIZE)
#define BITMAP_SHIFT 5 // 2^5=32
#define ONE_GB_SHIFT 30
#define BITMAP_MASK 0x1f // 2^5=32
#define ONE_GB_MASK 0x3fffffff
#define ONE_GB 1073741824 //1024*1024*1024 
#define BITMAP_INT_SIZE 8192 //bitmap[], 1GB/4k/32

enum mem_type {
	DMA = 1,
	FASTREG = 2,
	MW = 3,
	MR = 4
};

//max_size from one server or max_size one server can provide
#define MAX_MR_SIZE_GB 32

struct IS_rdma_info {
  	uint64_t buf[MAX_MR_SIZE_GB];
  	uint32_t rkey[MAX_MR_SIZE_GB];
  	int size_gb;	
	enum {
		DONE = 1,
		INFO,
		INFO_SINGLE,
		FREE_SIZE,
		EVICT,
		ACTIVITY,
		STOP,
		BIND,
		BIND_SINGLE,
		QUERY
	} type;
};

enum test_state { 
	IDLE = 1,
	CONNECT_REQUEST,
	ADDR_RESOLVED,
	ROUTE_RESOLVED,
	CONNECTED,		// updated by IS_cma_event_handler()
	FREE_MEM_RECV,
	AFTER_FREE_MEM,
	RDMA_BUF_ADV,   // designed for server
	WAIT_OPS,
	RECV_STOP,
	RECV_EVICT,
	RDMA_WRITE_RUNNING,
	RDMA_READ_RUNNING,
	SEND_DONE,
	RDMA_DONE,
	RDMA_READ_ADV,	// updated by IS_cq_event_handler()
	RDMA_WRITE_ADV,
	CM_DISCONNECT,
	ERROR
};

// 1GB remote chunk struct	("chunk": we use the term "slab" in our paper)
struct remote_chunk_g {
	uint32_t remote_rkey;		/* remote guys RKEY */
	uint64_t remote_addr;		/* remote guys TO */
	int *bitmap_g;	//1GB bitmap
};

#define CHUNK_MAPPED 1
#define CHUNK_UNMAPPED 0

// struct for write operation
struct chunk_write{
	struct kernel_cb *cb;
	int cb_index;
	int chunk_index;
	struct remote_chunk_g *chunk;	
	unsigned long chunk_offset;
	unsigned long len;
	unsigned long req_offset;
};

enum chunk_list_state {
	C_IDLE,
	C_READY,
	C_EVICT,
	C_STOP,
};

struct remote_chunk_g_list {
	struct remote_chunk_g **chunk_list;
	atomic_t *remote_mapped; 
	int chunk_size_g; //size = chunk_num * ONE_GB
	int target_size_g; // == future size of remote
	int shrink_size_g;
	int *chunk_map;	//cb_chunk_index to session_chunk_index
	struct task_struct *evict_handle_thread;
	char *evict_chunk_map;
	wait_queue_head_t sem;      	
	enum chunk_list_state c_state;
};

/*
 *  rdma kernel Control Block struct.
 */
struct kernel_cb {
	int cb_index; //index in IS_sess->cb_list
	struct IS_session *IS_sess;
	int server;			/* 0 iff client */
	struct ib_cq *cq;
	struct ib_pd *pd;
	struct ib_qp *qp;

	enum mem_type mem;
	struct ib_mr *dma_mr;

	// memory region
	struct ib_recv_wr rq_wr;	/* recv work request record */
	struct ib_sge recv_sgl;		/* recv single SGE */
	struct IS_rdma_info recv_buf;/* malloc'd buffer */
	u64 recv_dma_addr;
	DECLARE_PCI_UNMAP_ADDR(recv_mapping)
	struct ib_mr *recv_mr;

	struct ib_send_wr sq_wr;	/* send work requrest record */
	struct ib_sge send_sgl;
	struct IS_rdma_info send_buf;/* single send buf */
	u64 send_dma_addr;
	DECLARE_PCI_UNMAP_ADDR(send_mapping)
	struct ib_mr *send_mr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	struct ib_rdma_wr rdma_sq_wr;	/* rdma work request record */
#else
	struct ib_send_wr rdma_sq_wr;	/* rdma work request record */
#endif
	struct ib_sge rdma_sgl;		/* rdma single SGE */
	char *rdma_buf;			/* used as rdma sink */
	u64  rdma_dma_addr;
	DECLARE_PCI_UNMAP_ADDR(rdma_mapping)
	struct ib_mr *rdma_mr;

	// peer's addr info pay attention
	uint64_t remote_len;		/* remote guys LEN */
	struct remote_chunk_g_list remote_chunk;

	char *start_buf;		/* rdma read src */
	u64  start_dma_addr;
	DECLARE_PCI_UNMAP_ADDR(start_mapping)
	struct ib_mr *start_mr;

	enum test_state state;		/* used for cond/signalling */
	wait_queue_head_t sem;      // semaphore for wait/wakeup

	// from arg
	uint16_t port;			/* dst port in NBO */
	u8 addr[16];			/* dst addr in NBO */
	char *addr_str;			/* dst addr string */
	uint8_t addr_type;		/* ADDR_FAMILY - IPv4/V6 */
	int verbose;			/* verbose logging */
	int size;			/* ping data size */
	int txdepth;			/* SQ depth */
	int local_dma_lkey;		/* use 0 for lkey */

	/* CM stuff  connection management*/
	struct rdma_cm_id *cm_id;	/* connection on client side,*/
	struct rdma_cm_id *child_cm_id;	/* connection on client side,*/
					/* listener on server side. */
	struct list_head list;	
};

#define CTX_IDLE		0
#define CTX_R_IN_FLIGHT	1
#define CTX_W_IN_FLIGHT	2

struct rdma_ctx {
	struct IS_connection *IS_conn;
	struct free_ctx_pool *free_ctxs;  //or this one
	//struct mutex ctx_lock;	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	struct ib_rdma_wr rdma_sq_wr;	/* rdma work request record */
#else
	struct ib_send_wr rdma_sq_wr;	/* rdma work request record */
#endif
	struct ib_sge rdma_sgl;		/* rdma single SGE */
	char *rdma_buf;			/* used as rdma sink */
	u64  rdma_dma_addr;
	DECLARE_PCI_UNMAP_ADDR(rdma_mapping)
	struct ib_mr *rdma_mr;
	struct page *page;
	int chunk_index;
	struct kernel_cb *cb;
	unsigned long offset;
	unsigned long len;
	struct remote_chunk_g *chunk_ptr;
	atomic_t in_flight; //true = 1, false = 0
};

struct free_ctx_pool {
	unsigned int len;
	struct rdma_ctx **ctx_list;
	int head;
	int tail;
	spinlock_t ctx_lock;
};
struct ctx_pool_list {
	struct rdma_ctx 	*ctx_pool;
	struct free_ctx_pool *free_ctxs;
};

/*  connection object
 */
struct IS_connection {
	struct kernel_cb		**cbs;
	struct IS_session    *IS_sess;
	struct task_struct     *conn_th;
	int			cpu_id;
	int			wq_flag;
	wait_queue_head_t	wq;

	struct ctx_pool_list **ctx_pools;
	struct rdma_ctx 	*ctx_pool;
	struct free_ctx_pool *free_ctxs;
};

struct IS_portal {
	uint16_t port;			/* dst port in NBO */
	u8 addr[16];			/* dst addr in NBO */
	char * addr_str;
};
enum cb_state {
	CB_IDLE=0,
	CB_CONNECTED,	//connected but not mapped 
	CB_MAPPED,
	CB_EVICTING,
	CB_FAIL
};

// added for RDMA_CONNECTION failure handling.
#define DEV_RDMA_ON		1
#define DEV_RDMA_OFF	0

//  server selection, call m server each time.
#define SERVER_SELECT_NUM 1

struct IS_session {
	unsigned long int *read_request_count;	//how many requests on each CPU
	unsigned long int *write_request_count;	//how many requests on each CPU

	int mapped_cb_num;	//How many cbs are remote mapped
	struct kernel_cb	**cb_list;	
	struct IS_portal *portal_list;
	int cb_num;	//num of possible servers
	enum cb_state *cb_state_list; //all cbs state: not used, connected, failure

	struct IS_connection	    **IS_conns;

	char			      portal[MAX_PORTAL_NAME];

	struct list_head	      list;
	struct list_head	      devs_list; /* list of struct IS_file */
	spinlock_t		      devs_lock;
	struct config_group	      session_cg;
	struct completion	      conns_wait;
	atomic_t		      conns_count;
	atomic_t		      destroy_conns_count;

	unsigned long long    capacity;
	unsigned long long 	  mapped_capacity;
	int 	capacity_g;

	atomic_t 	*cb_index_map;  //unmapped==-1, this chunk is mapped to which cb
	int *chunk_map_cb_chunk; //sess->chunk map to cb-chunk
	int *unmapped_chunk_list;
	int free_chunk_index; //active header of unmapped_chunk_list
	atomic_t	rdma_on;	//DEV_RDMA_ON/OFF

	struct task_struct     *rdma_trigger_thread; //based on swap rate
	unsigned long write_ops[STACKBD_SIZE_G];
	unsigned long read_ops[STACKBD_SIZE_G];	
	unsigned long last_ops[STACKBD_SIZE_G];
	unsigned long trigger_threshold;
	spinlock_t write_ops_lock[STACKBD_SIZE_G];
	spinlock_t read_ops_lock[STACKBD_SIZE_G];
	int w_weight;
	int cur_weight;
	atomic_t trigger_enable;
};
#define TRIGGER_ON 1
#define TRIGGER_OFF 0

#define RDMA_TRIGGER_PERIOD 1000  //1 second
#define RDMA_TRIGGER_THRESHOLD 0 
#define RDMA_W_WEIGHT 50
#define RDMA_CUR_WEIGHT 80

#define NO_CB_MAPPED -1


struct IS_queue {
	unsigned int		     queue_depth;
	struct IS_connection	    *IS_conn;
};



struct r_stat64 {
    uint64_t     st_size;    /* total size, in bytes */
 };

#define uint64_from_ptr(p)    (uint64_t)(uintptr_t)(p)
#define ptr_from_uint64(p)    (void *)(unsigned long)(p)

static int inet_pton(const char *src, void *dst) {
        int saw_digit, octets, ch;
        u_char tmp[4], *tp;

        saw_digit = 0;
        octets = 0;
        *(tp = tmp) = 0;
        while ((ch = *src++) != '\0') {

                if (ch >= '0' && ch <= '9') {
                        u_int new = *tp * 10 + (ch - '0');

                        if (saw_digit && *tp == 0)
                                return (0);
                        if (new > 255)
                                return (0);
                        *tp = new;
                        if (! saw_digit) {
                                if (++octets > 4)
                                        return (0);
                                saw_digit = 1;
                        }
                } else if (ch == '.' && saw_digit) {
                        if (octets == 4)
                                return (0);
                        *++tp = 0;
                        saw_digit = 0;
                } else
                        return (0);
        }
        if (octets < 4)
                return (0);
        memcpy(dst, tmp, 4);
        return (1);
}
extern struct list_head g_IS_sessions;
extern struct mutex g_lock;
extern int created_portals;
extern int submit_queues;
extern int IS_indexes;

int IS_single_chunk_map(struct IS_session *IS_session, int i);
int IS_transfer_chunk(struct kernel_cb *cb, int cb_index, int chunk_index, struct remote_chunk_g *chunk, unsigned long offset, unsigned long len, int write, struct page *page);
asmlinkage int sys_is_session_create(const char *portal);
asmlinkage int sys_is_request(struct page *page, int is_write);
void IS_session_destroy(struct IS_session *IS_session);

void IS_single_chunk_init(struct kernel_cb *cb);
void IS_chunk_list_init(struct kernel_cb *cb);
void IS_bitmap_set(int *bitmap, int i);
bool IS_bitmap_test(int *bitmap, int i);
void IS_bitmap_clear(int *bitmap, int i);
void IS_bitmap_init(int *bitmap);
void IS_bitmap_group_set(int *bitmap, unsigned long offset, unsigned long len);
void IS_bitmap_group_clear(int *bitmap, unsigned long offset, unsigned long len);
void IS_insert_ctx(struct rdma_ctx *ctx);

struct IS_session *IS_session_find_by_portal(struct list_head *s_data_list, const char *portal);

#endif  /* LEAP_H */


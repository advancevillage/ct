#include <linux/stringify.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


/*
 * u64 bpf_ktime_get_ns(void) 
 *
 * https://github.com/cilium/cilium/blob/master/bpf/lib/time.h
 */
#define NSEC_PER_SEC	        (1000ULL * 1000ULL * 1000UL)
#define bpf_ktime_get_sec()	    ({ __u64 __x = bpf_ktime_get_ns() / NSEC_PER_SEC; __x; })
#define bpf_now()		        bpf_ktime_get_sec()


/*
 *元数据存储:
 * key | value
 * ----------
 *  0  | ktime   系统启动时间s
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,  __u32);           
    __type(value,__u64);          
    __uint(max_entries, 4);
} meta SEC(".maps"); //meta table

struct {
   __uint(type,         BPF_MAP_TYPE_PROG_ARRAY);
   __type(key,          0x04);
   __type(value,        0x04);
   __uint(max_entries,  30);
} jt SEC(".maps");      //jump table

#define PROG(F)             SEC("xdp/"__stringify(F)) int bf_##F

#define ingress             0   //pkt in
#define egress              1   //pkt out
#define prs_end             2   //prs end
#define ct                  3   //pkt ct 
#define acl                 4   //pkt ac l
#define nat                 5   //pkt na t
#define prs_eth             10  //eth 80 2.x
#define prs_ipv4            11  //ipv4
#define prs_icmp            12  //icmp
#define prs_tcp             13  //tcp
#define prs_udp             14  //udp

/*
 * flow 表示报文五元组; 用于构建ct的tuple;
 * 
 * flags:  8bit 注意每个bit的含义
 *        7 6 5 4 3 2 1 0
 *        ---------------
 *        | | | | | | | |
 *        | | | | | | | 表示报文方向 0表示入向 1表示出向
 *        | | | | | | |
 *        | | | | | | 表示是否是related报文
 *        | | | | |FIN           
 *        | | | |SYN 
 *        | | |RST
 *        | |PSH
 *        |ACK
 *       URG
 *       -------------
 *            TCP
 */
struct flow {
    __be32  sip;
    __be32  dip;
    __be32  sport:16,
            dport:16;
    __u32   proto:8,
            delta:8,
            bytes:16;
    __u32   urg:1,       
            ack:1,
            psh:1,
            rst:1,
            syn:1,
            fin:1,
            rel:1,
            dir:1,
            reserved:24;
} __attribute__((packed));

////////////////////////////////////////
//  15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
//  -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
//  |  |  |  |  |  |                  |  |  |  |  |
//  |  |  |  |  |  |                  |  |  |  |  |
//  |  |  |  |  |  |                  |  |  |  |  0x0001 ct_new 
//  |  |  |  |  |  |                  |  |  |  0x0002 ct_rel
//  |  |  |  |  |  |                  |  |  0x0004 ct_rpl
//  |  |  |  |  |  |                  |  0x0008 ct_syn_sent
//  |  |  |  |  |  |                  0x0010 ct_syn_recv                             
//  |  |  |  |  |  |                                                   
//  |  |  |  |  |  |                                                 
//  |  |  |  |  |  |                                                 
//  |  |  |  |  | 0x0400 ct_est                                                 
//  |  |  |  | 0x0800 ct_fin_wait                                                    
//  |  |  | 0x1000 ct_last_ack                                                        
//  |  | 0x2000 ct_last_ack                                                           
//  | 0x4000 ct_time_wait                                                              
//                                                                    

#define ct_null             0x0000
#define ct_new              0x0001
#define ct_rel              0x0002
#define ct_rpl              0x0004
#define ct_syn_sent         0x0008
#define ct_syn_recv         0x0010
#define ct_est              0x0400
#define ct_fin_wait         0x0800
#define ct_close_wait       0x1000
#define ct_last_ack         0x2000
#define ct_time_wait        0x4000



/*
 * ipv4_ct_tuple 表示ct状态表key
 * 
 * flags:  8bit 注意每个bit的含义
 *        7 6 5 4 3 2 1 0
 *        ---------------
 *                    | |
 *                    | 表示CT方向 0表示入向 1表示出向
 *                    |
 *                    表示是否是related报文
 *                  
 * ipv4_ct_entry 表示ct表项
 * 
 * since 从系统启动开始计时
 */
struct ipv4_ct_tuple {
    __u32   sip;
    __u32   dip;
	__u16   sport;
    __u16   dport;
	__u8    nexthdr;
    __u8    rel:1,
            dir:1,
            reserved:6;
};

struct ipv4_ct_entry {
    __u64   bytes;
    __u64   pkts;
    __u64   state:16,
            since:32,
            reserved:16;
};

struct {
   __uint(type,         BPF_MAP_TYPE_LRU_HASH);
   __type(key,          struct ipv4_ct_tuple);
   __type(value,        struct ipv4_ct_entry);
   __uint(max_entries,  1024);
} ctt SEC(".maps");      //conntrack table

static __inline void meta_ktime() {
    __u64 val = bpf_now(); 
    __u32 key = 0;
    bpf_map_update_elem(&meta, &key, &val, BPF_ANY);
}

static __inline __u16 ct_tcp_state(struct ipv4_ct_entry *rentry, struct ipv4_ct_entry *entry, struct flow *f) {
    __u16 next = ct_new; 

    if (!entry || !rentry) {
        return next;
    }
    
    switch (rentry->state) {
        case ct_new:
            {
                switch (entry->state) {
                    case ct_new:
                        {
                            if (f->ack && f->syn) {
                                next = ct_syn_recv; 
                            } else if (f->syn) {
                                next = ct_syn_sent;
                            }
                        }
                        break;
                }
            }
            break;

        case ct_syn_sent|ct_new:
            {
                switch (entry->state) {
                    case ct_new: 
                        {
                            if(f->ack && f->syn) {
                                next = ct_syn_recv;
                            }
                        }
                        break;
                    case ct_syn_recv|ct_new:
                        {
                            if(f->ack && !f->syn) {
                                next = ct_est;
                            }
                        }
                        break;
                }
            }
            break;

        case ct_syn_recv|ct_new:
            {
                switch (entry->state) {
                    case ct_syn_sent|ct_new:
                        {
                            if(f->ack && !f->syn) {
                                next = ct_est;
                            }
                        }
                        break;
                }
            }
            break;

        case ct_syn_sent|ct_est|ct_new:
            {
               switch (entry->state) {
                    case ct_syn_recv|ct_new:
                        {
                            if (f->ack && !f->syn) {
                                next = ct_est;
                            }
                        }
                        break;
                    case ct_syn_recv|ct_est|ct_new:
                        {
                            if (f->fin) {
                                next = ct_close_wait;
                            }
                        }
                        break;
               }
            }
            break;

        case ct_syn_recv|ct_est|ct_new:
            {
                switch (entry->state) {
                    case ct_syn_sent|ct_est|ct_new: 
                        {
                            if (f->fin) {
                                next = ct_fin_wait;
                            }
                        }
                        break;
                }
            }
            break;

        case ct_fin_wait|ct_syn_sent|ct_est|ct_new:
            {
                switch(entry->state) {
                    case ct_syn_recv|ct_est|ct_new: 
                        {
                            if(f->fin && f->ack) {
                                next = ct_last_ack| ct_close_wait;
                            }if(!f->fin && f->ack) {
                                next = ct_close_wait;
                            }
                        }
                        break;
                    case ct_close_wait|ct_syn_recv|ct_est|ct_new:
                        {
                            if(f->fin) {
                                next = ct_last_ack; 
                            }
                        }
                        break;
                }
            }
            break;

        case ct_last_ack|ct_close_wait|ct_syn_recv|ct_est|ct_new:
            {
                switch(entry->state) {
                    case ct_fin_wait|ct_syn_sent|ct_est|ct_new:
                        {
                            if(f->ack) {
                                next = ct_time_wait;
                            }
                        }
                        break;
                }
            }
            break;
    }

    return next;
}

static __inline __u16 ct_state(struct ipv4_ct_entry *rentry, struct ipv4_ct_entry *entry) {
    __u16 next = ct_new; 

    if (!entry || !rentry) {
        return next;
    }

    switch (rentry->state & (~ct_rel)) {
        case ct_new:
            {
                switch(entry->state) {
                case ct_new:
                    next = ct_rpl;
                    break;
                }
            }
            break;

        case ct_rpl|ct_new:
            {
                switch(entry->state) {
                case ct_new:
                    next = ct_rpl;
                    break;

                case ct_rpl|ct_new:
                    next = ct_est;
                    break;
                }
            }
            break;

        case ct_est|ct_rpl|ct_new:
            {
                switch(entry->state) {
                case ct_rpl|ct_new:
                    next = ct_est;
                    break;
                }
            }
            break;
        }

    return next;
}

static __inline void ct_tcp(struct flow *f) {
    struct ipv4_ct_tuple tuple  = {}; 
    struct ipv4_ct_tuple rtuple = {}; 
    
    tuple.sip       = f->sip;       rtuple.sip      = f->dip;
    tuple.dip       = f->dip;       rtuple.dip      = f->sip;
    tuple.dport     = f->dport;     rtuple.dport    = f->sport;
    tuple.sport     = f->sport;     rtuple.sport    = f->dport;
    tuple.nexthdr   = f->proto;     rtuple.nexthdr  = f->proto;
    tuple.rel       = f->rel;       rtuple.rel      = f->rel;
    tuple.dir       = f->dir;       rtuple.dir      = ~f->dir;
    tuple.reserved  = 0;            rtuple.reserved = 0;

    struct ipv4_ct_entry *rentry = (struct ipv4_ct_entry*)bpf_map_lookup_elem(&ctt, &rtuple);
    struct ipv4_ct_entry *entry  = (struct ipv4_ct_entry*)bpf_map_lookup_elem(&ctt, &tuple);

    if(!entry) {
       struct ipv4_ct_entry tentry  = {};
       entry  = &tentry;
       entry->state  = ct_new;
       entry->pkts   = 1;
       entry->bytes  = f->bytes;
       entry->since  = bpf_now();
       bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);
    }

    if (!rentry) {
       struct ipv4_ct_entry trentry = {};
       rentry = &trentry;
       rentry->state  = ct_new;
       rentry->pkts   = 0;
       rentry->bytes  = 0;
       rentry->since  = bpf_now();
       bpf_map_update_elem(&ctt, &rtuple, rentry, BPF_ANY);
    }

    if(entry && rentry) {
        entry->since = bpf_now();
        entry->state |= ct_tcp_state(rentry, entry, f);
        __sync_fetch_and_add(&entry->pkts, 1);
        __sync_fetch_and_add(&entry->bytes,f->bytes);
        bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);
    }

    if(f->rst) {
        bpf_map_delete_elem(&ctt, &tuple);
        bpf_map_delete_elem(&ctt, &rtuple);
    }
}

static __inline void ct_udp(struct flow *f) {
    struct ipv4_ct_tuple tuple  = {}; 
    struct ipv4_ct_tuple rtuple = {}; 
    
    tuple.sip       = f->sip;       rtuple.sip      = f->dip;
    tuple.dip       = f->dip;       rtuple.dip      = f->sip;
    tuple.dport     = f->dport;     rtuple.dport    = f->sport;
    tuple.sport     = f->sport;     rtuple.sport    = f->dport;
    tuple.nexthdr   = f->proto;     rtuple.nexthdr  = f->proto;
    tuple.rel       = f->rel;       rtuple.rel      = f->rel;
    tuple.dir       = f->dir;       rtuple.dir      = ~f->dir;
    tuple.reserved  = 0;            rtuple.reserved = 0;

    struct ipv4_ct_entry *rentry = (struct ipv4_ct_entry*)bpf_map_lookup_elem(&ctt, &rtuple);
    struct ipv4_ct_entry *entry  = (struct ipv4_ct_entry*)bpf_map_lookup_elem(&ctt, &tuple);

    if(entry && rentry) {
        entry->since = bpf_now();
        entry->state |= ct_state(rentry, entry);
        __sync_fetch_and_add(&entry->pkts, 1);
        __sync_fetch_and_add(&entry->bytes,f->bytes);
        bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);
    }
    
    if(!entry) {
       struct ipv4_ct_entry tentry  = {};
       entry  = &tentry;
       entry->state  = tuple.rel ? ct_rel : ct_new;
       entry->pkts   = 1;
       entry->bytes  = f->bytes;
       entry->since  = bpf_now();
       bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);

       tuple.rel    = ~tuple.rel;
       entry->state = tuple.rel ? ct_rel : ct_new;
       entry->pkts  = 0;
       entry->bytes = 0;
       bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);
    }

    if (!rentry) {
       struct ipv4_ct_entry trentry = {};
       rentry = &trentry;
       rentry->state  = rtuple.rel ? ct_rel : ct_new;
       rentry->pkts   = 0;
       rentry->bytes  = 0;
       rentry->since  = bpf_now();
       bpf_map_update_elem(&ctt, &rtuple, rentry, BPF_ANY);

       rtuple.rel    = ~rtuple.rel;
       rentry->state = rtuple.rel ? ct_rel : ct_new;
       bpf_map_update_elem(&ctt, &rtuple, rentry, BPF_ANY);
    }
}

static __inline void ct_icmp(struct flow *f) {
    struct ipv4_ct_tuple tuple  = {}; 
    struct ipv4_ct_tuple rtuple = {}; 
    
    tuple.sip       = f->sip;       rtuple.sip      = f->dip;
    tuple.dip       = f->dip;       rtuple.dip      = f->sip;
    tuple.dport     = f->dport;     rtuple.dport    = f->sport;
    tuple.sport     = f->sport;     rtuple.sport    = f->dport;
    tuple.nexthdr   = f->proto;     rtuple.nexthdr  = f->proto;
    tuple.rel       = f->rel;       rtuple.rel      = f->rel;
    tuple.dir       = f->dir;       rtuple.dir      = ~f->dir;
    tuple.reserved  = 0;            rtuple.reserved = 0;

    struct ipv4_ct_entry *rentry = (struct ipv4_ct_entry*)bpf_map_lookup_elem(&ctt, &rtuple);
    struct ipv4_ct_entry *entry  = (struct ipv4_ct_entry*)bpf_map_lookup_elem(&ctt, &tuple);

    if(entry && rentry) {
        entry->since = bpf_now();
        entry->state |= ct_state(rentry, entry);
        __sync_fetch_and_add(&entry->pkts, 1);
        __sync_fetch_and_add(&entry->bytes,f->bytes);
        bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);
    }

    if(!entry) {
       struct ipv4_ct_entry tentry  = {};
       entry  = &tentry;
       entry->state  = tuple.rel ? ct_rel : ct_new;
       entry->pkts   = 1;
       entry->bytes  = f->bytes;
       entry->since  = bpf_now();
       bpf_map_update_elem(&ctt, &tuple, entry, BPF_ANY);
    }

    if (!rentry) {
       struct ipv4_ct_entry trentry = {};
       rentry = &trentry;
       rentry->state  = rtuple.rel ? ct_rel : ct_new;
       rentry->pkts   = 0;
       rentry->bytes  = 0;
       rentry->since  = bpf_now();
       bpf_map_update_elem(&ctt, &rtuple, rentry, BPF_ANY);
    }
}

// 进入XDP处理程序
/*
 * bpf_xdp_adjust_meta / bpf_xdp_adjust_tail / bpf_xdp_adjust_head
 * SourceCode: https://elixir.bootlin.com/linux/v5.4.153/source/net/core/filter.c#L3429
 *
 *   struct xdp_buff {
 *      void *data;
 *      void *data_end;
 *      void *data_meta;
 *      void *data_hard_start;
 *      struct xdp_rxq_info *rxq;
 *   };
 *
 * 重点一:
 *  data_hard_start <= data_meta <= data < data_end
 * 重点二:
 *  data 和 data_meta 是相对位置，如果data变化，那么data_meta随之改变
 *  eg:
 *  data_meta = db0e4f0 , data = db0e500 
 *                      |
 *  data_meta = db0e4fe , data = db0e50e
 * 重点三:
 *  bpf_xdp_adjust_head 修改ctx地址, 赋值操作必须在其之前
 *
*/
PROG(ingress)(struct xdp_md *ctx) {     
    
    meta_ktime();
    // 封装flow
	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
    int r = bpf_xdp_adjust_meta(ctx, 0 - (int)sizeof(struct flow));
    if (r) {
        bpf_printk("bpf_xdp_adjust_meta errno = %x", r);
        return XDP_DROP;
    }

	/* Notice: Kernel-side verifier requires that loading of
	 * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
	 * as pkt-data pointers are invalidated.  Helpers that require
	 * this are determined/marked by bpf_helper_changes_pkt_data()
	 */
    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    // 初始化Flow
    f->sip      = 0;
    f->dip      = 0;
    f->sport    = 0;
    f->dport    = 0;
    f->proto    = 0;
    f->delta    = 0;
    f->bytes    = data_end - data;
    f->urg      = 0;
    f->ack      = 0;
    f->psh      = 0;
    f->rst      = 0;
    f->syn      = 0;
    f->fin      = 0;
    f->rel      = 0;
    f->dir      = ingress;
    f->reserved = 0;

    // 解析以太网报文
    bpf_tail_call(ctx, &jt, prs_eth);

    // 解封flow 
    bpf_tail_call(ctx, &jt, prs_end);

    return XDP_PASS;
}

PROG(egress)(struct xdp_md *ctx) {     
    
    meta_ktime();
    // 封装flow
	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
    int r = bpf_xdp_adjust_meta(ctx, 0 - (int)sizeof(struct flow));
    if (r) {
        bpf_printk("bpf_xdp_adjust_meta errno = %x", r);
        return XDP_DROP;
    }

	/* Notice: Kernel-side verifier requires that loading of
	 * ctx->data MUST happen _after_ helper bpf_xdp_adjust_meta(),
	 * as pkt-data pointers are invalidated.  Helpers that require
	 * this are determined/marked by bpf_helper_changes_pkt_data()
	 */
    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    // 初始化Flow
    f->sip      = 0;
    f->dip      = 0;
    f->sport    = 0;
    f->dport    = 0;
    f->proto    = 0;
    f->delta    = 0;
    f->bytes    = data_end - data;
    f->urg      = 0;
    f->ack      = 0;
    f->psh      = 0;
    f->rst      = 0;
    f->syn      = 0;
    f->fin      = 0;
    f->rel      = 0;
    f->dir      = egress;
    f->reserved = 0;

    // 解析以太网报文
    bpf_tail_call(ctx, &jt, prs_eth);

    // 解封flow 
    bpf_tail_call(ctx, &jt, prs_end);

    return XDP_PASS;
}

// 连接跟踪处理程序
PROG(ct)(struct xdp_md *ctx) {     

    void *data      = (void *)(unsigned long)ctx->data;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    switch (f->proto) {

    case 0x06:
        ct_tcp(f);
        break;
    
    case 0x11:
        ct_udp(f);
        break;

    case 0x01:
        ct_icmp(f);
        break;

    }

    bpf_tail_call(ctx, &jt, prs_end);
    return XDP_PASS;
}

// 以太网报文处理程序
PROG(prs_eth)(struct xdp_md *ctx) { 

    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    struct ethhdr   *eth = data + f->delta;  
    __u8   nh_off; 

    nh_off = (char*)(eth + 1) - (char*)eth;
    if (data + f->delta + nh_off > data_end) {
        return XDP_DROP;
    }

    f->delta += nh_off;

    __u16 h_proto = eth->h_proto; 

    switch (h_proto) {
    case bpf_htons(ETH_P_IP):
        bpf_tail_call(ctx, &jt, prs_ipv4);
        break;
    }
    
    bpf_tail_call(ctx, &jt, prs_end);
    return XDP_PASS;
}

// IPv4报文处理程序
PROG(prs_ipv4)(struct xdp_md *ctx) { 

    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

	struct iphdr    *iph = data + f->delta; 
    __u8   nh_off; 

    nh_off = (char*)(iph + 1) - (char*)iph;
    if (data + f->delta + nh_off > data_end) {
        return XDP_DROP;
    }

    f->sip    = bpf_ntohl(iph->saddr);
    f->dip    = bpf_ntohl(iph->daddr);
    f->delta += nh_off;
    f->proto  = iph->protocol;

    //分片报文暂不支持
    if (iph->frag_off & 0xff3f) {
        return XDP_PASS;
    }


    switch (iph->protocol) {
    case 0x06: //tcp
        bpf_tail_call(ctx, &jt, prs_tcp);
        break;

    case 0x11: //udp
        bpf_tail_call(ctx, &jt, prs_udp);
        break;

    case 0x01: //icmp
        bpf_tail_call(ctx, &jt, prs_icmp);
        break;
    }

    bpf_tail_call(ctx, &jt, prs_end);
    return XDP_PASS;
}

// ICMP报文处理程序
PROG(prs_icmp)(struct xdp_md *ctx) { 

    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    struct icmphdr  *icmph = data + f->delta;
    __u8   nh_off; 

    nh_off = (char*)(icmph + 1) - (char*)icmph;
    if (data + f->delta + nh_off > data_end) {
        return XDP_DROP;
    }

    f->delta += nh_off;

    switch (icmph->type) {
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETERPROB:
        f->rel = 1;
        f->dir = ~f->dir;
        bpf_tail_call(ctx, &jt, prs_ipv4);
        break;

    case ICMP_ECHOREPLY:
        f->sport  = bpf_ntohs(icmph->un.echo.id);
        break;

    case ICMP_ECHO:
        f->dport  = bpf_ntohs(icmph->un.echo.id);
        break;
    }

    bpf_tail_call(ctx, &jt, ct);

    bpf_tail_call(ctx, &jt, prs_end);
    return XDP_PASS;
}

// TCP报文处理程序
PROG(prs_tcp)(struct xdp_md *ctx) { 

    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    struct tcphdr *tcph = data + f->delta;
    __u8   nh_off; 

    nh_off = (char*)(tcph + 1) - (char*)tcph;
    if (data + f->delta + nh_off > data_end) {
        return XDP_DROP;
    }

    f->sport  = bpf_ntohs(tcph->source);
    f->dport  = bpf_ntohs(tcph->dest);
    f->delta += nh_off;
    f->urg    = tcph->urg;
    f->ack    = tcph->ack;
    f->psh    = tcph->psh;
    f->rst    = tcph->rst;
    f->syn    = tcph->syn;
    f->fin    = tcph->fin;

    bpf_tail_call(ctx, &jt, ct);
    bpf_tail_call(ctx, &jt, prs_end);
    return XDP_PASS;
}

// UDP报文处理程序
PROG(prs_udp) (struct xdp_md *ctx) { 

    void *data      = (void *)(unsigned long)ctx->data;
    void *data_end  = (void *)(unsigned long)ctx->data_end;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    struct udphdr *udph = data + f->delta;
    __u8   nh_off; 

    nh_off = (char*)(udph + 1) - (char*)udph;
    if (data + f->delta + nh_off > data_end) {
        return XDP_DROP;
    }

    f->sport  = bpf_ntohs(udph->source);
    f->dport  = bpf_ntohs(udph->dest);
    f->delta += nh_off;

    bpf_tail_call(ctx, &jt, ct);
    bpf_tail_call(ctx, &jt, prs_end);
    return XDP_PASS;
}

// 离开XDP处理程序 
PROG(prs_end)(struct xdp_md *ctx) {     

    void *data      = (void *)(unsigned long)ctx->data;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license []SEC("license") = "GPL";



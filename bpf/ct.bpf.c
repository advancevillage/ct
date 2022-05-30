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

struct {
   __uint(type,         BPF_MAP_TYPE_PROG_ARRAY);
   __type(key,          0x04);
   __type(value,        0x04);
   __uint(max_entries,  30);
} jt SEC(".maps");      //jump table

#define PROG(F) SEC("xdp/"__stringify(F)) int bf_##F

#define ingress             0   //pkt in
#define egress              1   //pkt out
#define ct                  2   //pkt ct
#define acl                 3   //pkt acl
#define nat                 4   //pkt nat
#define prs_eth             10   //eth 802.x
#define prs_ipv4            11   //ipv4
#define prs_icmp            12   //icmp
#define prs_tcp             13   //tcp
#define prs_udp             14   //udp

struct flow {
	__be32  sip;
    __be32  dip;
    __be32  sport:16,
            dport:16;
    __u32   proto:8,
            delta:8,
            bytes:16;
} __packed;

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

    // 解析以太网报文
    bpf_tail_call(ctx, &jt, prs_eth);

    // 解封flow 
    bpf_tail_call(ctx, &jt, egress);

    return XDP_PASS;
}

// 离开XDP处理程序 
PROG(egress)(struct xdp_md *ctx) {     

    void *data      = (void *)(unsigned long)ctx->data;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    bpf_printk("sip=%x dip=%x", f->sip, f->dip);
    bpf_printk("sport=%x dport=%x", f->sport, f->dport);
    bpf_printk("proto=%x delta=%x bytes=%x", f->proto, f->delta, f->bytes);

    return XDP_PASS;
}

// 连接跟踪处理程序
PROG(ct)(struct xdp_md *ctx) {     

    void *data      = (void *)(unsigned long)ctx->data;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    // 五元组连接跟踪分析





    bpf_tail_call(ctx, &jt, egress);
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
    
    bpf_tail_call(ctx, &jt, egress);
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

    f->sip    = iph->saddr;
    f->dip    = iph->daddr;
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

    bpf_tail_call(ctx, &jt, egress);
    return XDP_PASS;
}

// ICMP报文处理程序
PROG(prs_icmp)(struct xdp_md *ctx) { 

    bpf_printk("enter prs icmp 1 %x %x %x", ctx->data_meta, ctx->data, sizeof(struct flow));

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

    f->sport  = icmph->type;
    f->dport  = icmph->code;
    f->delta += nh_off;

    bpf_tail_call(ctx, &jt, ct);
    bpf_tail_call(ctx, &jt, egress);
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

    f->sport  = tcph->source;
    f->dport  = tcph->dest;
    f->delta += nh_off;

    bpf_tail_call(ctx, &jt, ct);
    bpf_tail_call(ctx, &jt, egress);
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

    f->sport  = udph->source;
    f->dport  = udph->dest;
    f->delta += nh_off;

    bpf_tail_call(ctx, &jt, ct);
    bpf_tail_call(ctx, &jt, egress);
    return XDP_PASS;
}

char _license []SEC("license") = "GPL";



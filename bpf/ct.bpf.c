#include <linux/stringify.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
   __uint(type,         BPF_MAP_TYPE_PROG_ARRAY);
   __type(key,          0x04);
   __type(value,        0x04);
   __uint(max_entries,  30);
} jt SEC(".maps");      //jump table

#define PROG(F) SEC("xdp/"__stringify(F)) int bf_##F

#define ingress       0
#define prs_eth       1
#define prs_ipv4      2
#define egress        29

struct flow {
	__be32  sip;
    __be32  dip;
    __be32  sport:16,
            dport:16;
    __u32   proto:8,
            delta:8,
            bytes:16;
} __packed;

//xdp-0  进入XDP处理程序
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
    
    bpf_printk("enter prs ingress 1 %x %x %x", ctx->data_meta, ctx->data, sizeof(struct flow));
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

//xdp-29 离开XDP处理程序 
PROG(egress)(struct xdp_md *ctx) {     

    bpf_printk("enter prs egress 1 %x %x %x", ctx->data_meta, ctx->data, sizeof(struct flow));

    void *data      = (void *)(unsigned long)ctx->data;
    struct flow *f  = (void *)(unsigned long)ctx->data_meta;

    if ((char*)(f + 1) > (char*)data) {
        return XDP_DROP;
    }

    bpf_printk("sip=%x dip=%x", f->sip, f->dip);
    bpf_printk("sport=%x dport=%x", f->sport, f->dport);
    bpf_printk("proto=%x delta=%x bytes=%x", f->proto, f->delta, f->bytes);

    bpf_printk("enter prs egress 2 %x %x %x", ctx->data_meta, ctx->data, sizeof(struct flow));
    return XDP_PASS;
}

//xdp-1  以太网报文处理程序
PROG(prs_eth)(struct xdp_md *ctx) { 

    bpf_printk("enter prs eth 1 %x %x %x", ctx->data_meta, ctx->data, sizeof(struct flow));

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

//xdp-2 IPv4报文处理程序
PROG(prs_ipv4)(struct xdp_md *ctx) { 

    bpf_printk("enter prs ipv4 1 %x %x %x", ctx->data_meta, ctx->data, sizeof(struct flow));

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

    bpf_tail_call(ctx, &jt, egress);
    return XDP_PASS;
}


char _license []SEC("license") = "GPL";

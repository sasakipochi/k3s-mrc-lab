// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * スイッチのポート (veth の送信側) を模擬する tcx egress プログラム
 *
 *  - 帯域: ポートごとの「次に線が空く時刻」を持ち、skb->tstamp に送信時刻を入れて fq qdisc に送らせる (EDT)
 *  - キュー: その時点の待ち行列の長さ (バイト) を「空く時刻 - 今」×帯域で求める
 *      backlog > ecn_k   … ECT のパケットに CE を付ける (ECN)
 *      backlog > trim_th … MRC のデータパケットはペイロードを切り捨ててヘッダーだけ先に送る (Packet Trimming)
 *      backlog > drop_th … それ以外は捨てる (テールドロップ)
 *  - 障害: down (全部捨てる)・loss_ppm (確率で捨てる)
 *  - カウンタ: 送信数・ECN・トリミング・破棄・キュー長の合計 (平均キュー長 = q_sum / q_cnt)
 *
 * 設定 (port_cfg) と状態 (port_st) は ifindex をキーにした 1 組のマップを全ポートで共有する。
 * ifindex は topo.py が全ネームスペースで重ならない番号を振る。
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MRC_PORT   4791
#define MRC_HDR    32
#define ETH_LEN    14
#define TRIM_LEN   (ETH_LEN + 40 + 8 + MRC_HDR)
#define T_DATA     1
#define F_TRIMMED  0x80
#define NS_BITS    8000000000ULL   /* 1 秒 (ns) × 8 bit */

#ifndef TCX_PASS
#define TCX_PASS 0
#define TCX_DROP 2
#endif

struct port_cfg {
	__u64 rate_bps;   /* 0 = 帯域制限なし (キューも無し) */
	__u32 ecn_k;      /* バイト */
	__u32 trim_th;
	__u32 drop_th;
	__u32 down;       /* 1 = 切断 */
	__u32 loss_ppm;   /* 100 万分率 */
	__u32 trim_on;    /* 1 = Packet Trimming 有効 */
};

struct port_st {
	struct bpf_spin_lock lock;
	__u32 pad;
	__u64 next_free_ns;
	__u64 tx_pkts;
	__u64 tx_bytes;
	__u64 mrc_pkts;
	__u64 ecn_marked;
	__u64 trimmed;
	__u64 drop_queue;
	__u64 drop_fault;
	__u64 q_sum;      /* 到着時のキュー長 (バイト) の合計 */
	__u64 q_cnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, struct port_cfg);
} port_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, struct port_st);
} port_st SEC(".maps");

SEC("tcx/egress")
int mrc_port(struct __sk_buff *skb)
{
	__u32 ifi = skb->ifindex;
	struct port_cfg *cfg = bpf_map_lookup_elem(&port_cfg, &ifi);
	struct port_st *st = bpf_map_lookup_elem(&port_st, &ifi);
	if (!cfg || !st)
		return TCX_PASS;

	__u32 len = skb->len;
	int mrc_data = 0, ect = 0;

	if (len >= TRIM_LEN)
		bpf_skb_pull_data(skb, TRIM_LEN);
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) <= end && eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) <= end) {
			__u8 b1 = ((__u8 *)ip6)[1];
			ect = (b1 >> 4) & 3;
			if (ip6->nexthdr == IPPROTO_UDP) {
				struct udphdr *udp = (void *)(ip6 + 1);
				__u8 *m = (void *)(udp + 1);
				if ((void *)(m + MRC_HDR) <= end && udp->dest == bpf_htons(MRC_PORT)) {
					__sync_fetch_and_add(&st->mrc_pkts, 1);
					if (m[4] == T_DATA && len > TRIM_LEN && !(m[5] & F_TRIMMED))
						mrc_data = 1;
				}
			}
		}
	}

	if (cfg->down || (cfg->loss_ppm && bpf_get_prandom_u32() % 1000000 < cfg->loss_ppm)) {
		__sync_fetch_and_add(&st->drop_fault, 1);
		return TCX_DROP;
	}

	__u64 rate = cfg->rate_bps;
	if (!rate) {
		__sync_fetch_and_add(&st->tx_pkts, 1);
		__sync_fetch_and_add(&st->tx_bytes, len);
		return TCX_PASS;
	}

	__u64 now = bpf_ktime_get_ns();
	int action = 0;            /* 0 送る, 1 捨てる, 2 トリミング, 3 CE を付けて送る */
	__u64 when = now;

	bpf_spin_lock(&st->lock);
	__u64 start = st->next_free_ns > now ? st->next_free_ns : now;
	__u64 backlog = (start - now) * rate / NS_BITS;
	st->q_sum += backlog;
	st->q_cnt += 1;
	if (mrc_data && cfg->trim_on && backlog + len > cfg->trim_th) {
		action = 2;
	} else if (backlog + len > cfg->drop_th) {
		action = 1;
	} else {
		if (ect && backlog > cfg->ecn_k)
			action = 3;
		st->next_free_ns = start + (__u64)len * NS_BITS / rate;
		when = start;
	}
	bpf_spin_unlock(&st->lock);

	if (action == 1) {
		__sync_fetch_and_add(&st->drop_queue, 1);
		return TCX_DROP;
	}
	if (action == 2) {
		/* ペイロードを捨ててヘッダーだけにする。UDP チェックサムは 0 (送信側で無効化) なので直さなくてよい */
		if (bpf_skb_change_tail(skb, TRIM_LEN, 0)) {
			__sync_fetch_and_add(&st->drop_queue, 1);
			return TCX_DROP;
		}
		__be16 plen = bpf_htons(8 + MRC_HDR);
		bpf_skb_store_bytes(skb, ETH_LEN + 4, &plen, 2, 0);       /* IPv6 payload length */
		bpf_skb_store_bytes(skb, ETH_LEN + 40 + 4, &plen, 2, 0);  /* UDP length */
		__u8 fl = 0;
		bpf_skb_load_bytes(skb, ETH_LEN + 40 + 8 + 5, &fl, 1);
		fl |= F_TRIMMED;
		bpf_skb_store_bytes(skb, ETH_LEN + 40 + 8 + 5, &fl, 1, 0);
		__sync_fetch_and_add(&st->trimmed, 1);
		len = TRIM_LEN;
		when = now;            /* ヘッダーは優先キューで先に出す */
	} else if (action == 3) {
		__u8 b1 = 0;
		bpf_skb_load_bytes(skb, ETH_LEN + 1, &b1, 1);
		b1 |= 0x30;            /* ECN = 11 (CE) */
		bpf_skb_store_bytes(skb, ETH_LEN + 1, &b1, 1, 0);
		__sync_fetch_and_add(&st->ecn_marked, 1);
	}
	__sync_fetch_and_add(&st->tx_pkts, 1);
	__sync_fetch_and_add(&st->tx_bytes, len);
	skb->tstamp = when;
	return TCX_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

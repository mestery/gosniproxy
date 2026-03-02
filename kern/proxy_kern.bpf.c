// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// Copyright (c) 2025, Kyle Mestery
//
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // sender socket cookie
    __type(value, __u32); // destination key in sock_map
} cookie2key SEC(".maps");

SEC("sk_msg")
int proxy_redir(struct sk_msg_md *msg)
{
    __u64 c = bpf_get_socket_cookie(msg->sk);
    __u32 *dst = bpf_map_lookup_elem(&cookie2key, &c);
    if (!dst)
        return SK_PASS;

    int ret = bpf_msg_redirect_map(msg, &sock_map, *dst, 0);
    if (ret < 0) {
        // If redirect fails, pass the message through
        return SK_PASS;
    }

    return ret;
}

char _license[] SEC("license") = "Dual BSD/GPL";


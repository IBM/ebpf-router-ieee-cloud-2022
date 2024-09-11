################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

#######################################################################
## router.py
##
## description:
## call BPF module from bcc tools to handle the following systemcall
## - listen listen system call (server)
## - accept: accept system call (server)
## - connect: connect system call (client)
## - poll: poll system call (both)
##
## components:
## - FDHelper: keep server listen fd, addr mapping to accept event
## - ContainerFilter: filter container pid
## - Coordinator: main handler thread
##
## environments: 
## - ROUTER_LOGLEVEL (default: WARNING)
## - OVERLAY_CIDR (default: 10.233.0.0/18)
## - ROUTER_PORT (default: 1234) -> set back for duplication sync
## - OVERLAY_IF (default: vxlan.calico) -> set back for socket_info
##
#######################################################################


WELCOME_TEXT = """
#####################################
##      eBPF-based Router Log      ##
#####################################
"""




import os

def set_or_init(key, value):
    global WELCOME_TEXT
    if key not in os.environ:
        os.environ[key] = value
    WELCOME_TEXT += "{0}={1}\n".format(key, os.environ[key])
    return os.environ[key]

def convert_bool(bool_str):
    if bool_str.lower() == "true":
        return True
    else:
        return False

ROUTER_PORT = int(set_or_init("ROUTER_PORT", "1234"))
OVERLAY_IF = set_or_init("OVERLAY_IF", "vxlan.calico")
TRACE_ALL_THREADS = convert_bool(set_or_init("TRACE_ALL_THREADS", "True"))
NO_INTRA_HOST_DUP = convert_bool(set_or_init("NO_INTRA_HOST_DUP", "True"))
ROUTER_LOGLEVEL = set_or_init("ROUTER_LOGLEVEL", "WARNING")
BPF_SOKCNAME_ENABLE = convert_bool(set_or_init("BPF_SOKCNAME_ENABLE", "False"))
BPF_PEERNAME_ENABLE = convert_bool(set_or_init("BPF_PEERNAME_ENABLE", "False"))
BPF_RW_MEMO_ENABLE = convert_bool(set_or_init("BPF_RW_MEMO_ENABLE", "True"))


from util.logging import getlogger
logger = getlogger(__name__)

import sys
import signal

from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

import socket



CONFIG_FOLDER="/etc/rules"



SOCKET_LISTEN=1
SOCKET_ACCEPT=2
SOCKET_CONNECT=3
SOCKET_CLOSE=4

ROUTER_PID=os.getpid()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/tcp_states.h>
#include <linux/fdtable.h>
#include <linux/net.h>
#include <net/inet_sock.h>
#include <linux/poll.h>

#define SOCKET_LISTEN 1
#define SOCKET_ACCEPT 2
#define SOCKET_CONNECT 3
#define SOCKET_CLOSE 4

#define ROUTER_PID <ROUTER_PID>
#define SSHD_PID <SSHD_PID>
#define HOST_NS <HOST_NS>

BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);

/* Sockname Info */

struct address_info_t {
    u32 saddr;
    u16 port;
    u16 family;
};

struct pid_fd_t {
    u32 pid;
    u32 fd;
}; 

BPF_HASH(address_map, struct pid_fd_t, struct address_info_t);
BPF_HASH(peer_address_map, struct pid_fd_t, struct address_info_t);

/* read write detect */

BPF_HASH(rw_memo, struct pid_fd_t, u32);

/* Event Info */

struct info_t {
    u32 pid;
    u32 fd;
    char task[TASK_COMM_LEN];
    u32 type;
    u32 backlog;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u16 sk_type;
};

struct ipv6_info_t {
    u32 pid;
    u32 fd;
    char task[TASK_COMM_LEN];
    u32 type;
    u32 backlog;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u16 sk_type;
};


/* Utility Function */

static struct socket* get_socket_from_fd(int fdi)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file **fd = NULL;
    struct file *f = NULL;
    struct socket *socket = NULL;
    bpf_probe_read(&files, sizeof(files), &task->files);
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
    bpf_probe_read(&fd, sizeof(fd), &fdt->fd);
    bpf_probe_read(&f, sizeof(f), &fd[fdi]);
    bpf_probe_read(&socket, sizeof(socket), &f->private_data);
    return socket;
}

static bool is_host_process()
{  
    struct task_struct *task;
    u32 ppid;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = task->real_parent->tgid;
    return (ppid == 1) || (ppid == 2) || (ppid == SSHD_PID);
}

static void set_sock_info(struct info_t *info, struct sock* sk)
{
    bpf_probe_read(&info->saddr, sizeof(info->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&info->daddr, sizeof(info->daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&info->lport, sizeof(info->lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&info->dport, sizeof(info->dport), &sk->__sk_common.skc_dport);

    /* Caution: this refers to bitfield address of sk_type in net/sock.h of linux 4.17 */
    bpf_probe_read(&info->sk_type , 2, ((u8*)sk) + offsetof(typeof(struct sock), sk_gso_max_segs) - 2);
    info->dport = ntohs(info->dport);
}

static void set_sock_v6_info(struct ipv6_info_t *info, struct sock* sk)
{
    bpf_probe_read(&info->saddr, sizeof(info->saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read(&info->daddr, sizeof(info->daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    bpf_probe_read(&info->lport, sizeof(info->lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&info->dport, sizeof(info->dport), &sk->__sk_common.skc_dport);

    unsigned int flags = 0;
    size_t flags_offset = offsetof(typeof(struct sock), sk_write_queue) + sizeof(sk->sk_write_queue);
    bpf_probe_read(&flags, sizeof(flags), ((u8*)sk) + flags_offset);

    /* Caution: this refers to bitfield address of sk_type in net/sock.h of linux 4.17 */
    bpf_probe_read(&info->sk_type , 2, ((u8*)sk) + offsetof(typeof(struct sock), sk_gso_max_segs) - 2);
    info->dport = ntohs(info->dport);
}

static void set_address_info(struct address_info_t *info, struct address_info_t *peer_info, struct sock* sk)
{
    bpf_probe_read(&info->family, sizeof(info->family), &sk->__sk_common.skc_family);
    bpf_probe_read(&info->saddr, sizeof(info->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&info->port, sizeof(info->port), &sk->__sk_common.skc_num);

    bpf_probe_read(&peer_info->family, sizeof(peer_info->family), &sk->__sk_common.skc_family); 
    bpf_probe_read(&peer_info->saddr, sizeof(peer_info->saddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&peer_info->port, sizeof(peer_info->port), &sk->__sk_common.skc_dport);
    peer_info->port = ntohs(peer_info->port);
}


static int add_address_map(u32 pid, u32 fd, struct sock* sk)
{
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    struct address_info_t address_info;
    struct address_info_t peer_info;
    __builtin_memset(&address_info, 0, sizeof(address_info));
    __builtin_memset(&peer_info, 0, sizeof(peer_info));
    set_address_info(&address_info, &peer_info, sk);
    address_map.lookup_or_init(&pid_fd, &address_info);
    peer_address_map.lookup_or_init(&pid_fd, &peer_info);
    return 0;
}

/* close: to close dummy socket */


BPF_HASH(active_pid_fd, struct pid_fd_t, u32);

int call_sys_close(struct pt_regs *ctx, u64 fd)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    u32 *val = active_pid_fd.lookup(&pid_fd);
    if (val)
    {  
        struct info_t info = {.pid = pid, .fd=fd};
        info.type = SOCKET_CLOSE;
        ipv4_events.perf_submit(ctx, &info, sizeof(info));
        active_pid_fd.delete(&pid_fd);
        address_map.delete(&pid_fd);
    }
    return 0;
}

/* Server Probe */

int call_sys_listen(struct pt_regs* ctx) 
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == ROUTER_PID)
        return 0;
    u64 fd = PT_REGS_PARM1(ctx);
    int backlog = PT_REGS_PARM2(ctx);
    struct socket* socket = get_socket_from_fd(fd);   

    struct sock* sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &socket->sk);

    possible_net_t netns;
    bpf_probe_read(&netns, sizeof(netns), &sk->__sk_common.skc_net);
    
    u32 netns_inum;
    bpf_probe_read(&netns_inum, sizeof(netns_inum), &netns.net->ns.inum); 
    if (netns_inum == HOST_NS){
        return 0;
    }

    u16 sk_type = 0;
    /* Caution: this refers to bitfield address of sk_type in net/sock.h of linux 4.17 */
    bpf_probe_read(&sk_type , 2, ((u8*)sk) + offsetof(typeof(struct sock), sk_gso_max_segs) - 2);
    if (sk_type != SOCK_STREAM)
        return 0; 

    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    u32 zero = 0;
    active_pid_fd.update(&pid_fd, &zero);

    u16 family;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET) 
    {
        struct info_t info = {.pid = pid, .fd = fd, .backlog = backlog};
        info.type = SOCKET_LISTEN;
        bpf_get_current_comm(&info.task, sizeof(info.task));
        set_sock_info(&info, sk);
        ipv4_events.perf_submit(ctx, &info, sizeof(info));
    }
    else if (family == AF_INET6) 
    {        
        struct ipv6_info_t info = {.pid = pid, .fd = fd, .backlog = backlog};
        info.type = SOCKET_LISTEN;
        bpf_get_current_comm(&info.task, sizeof(info.task));
        set_sock_v6_info(&info, sk);
        ipv6_events.perf_submit(ctx, &info, sizeof(info));
    }
    return 0;
}

int rcall_sys_accept(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == ROUTER_PID)
        return 0;
    u32 ret = PT_REGS_RC(ctx);
    struct socket* socket = get_socket_from_fd(ret);   

    struct sock* sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &socket->sk);

    possible_net_t netns;
    bpf_probe_read(&netns, sizeof(netns), &sk->__sk_common.skc_net);
    
    u32 netns_inum;
    bpf_probe_read(&netns_inum, sizeof(netns_inum), &netns.net->ns.inum); 
    if (netns_inum == HOST_NS){
        return 0;
    }

    u16 sk_type = 0;
    /* Caution: this refers to bitfield address of sk_type in net/sock.h of linux 4.17 */
    bpf_probe_read(&sk_type , 2, ((u8*)sk) + offsetof(typeof(struct sock), sk_gso_max_segs) - 2);
    if (sk_type != SOCK_STREAM)
        return 0; 


    struct pid_fd_t pid_fd = {.pid = pid, .fd=ret};
    u32 zero = 0;
    active_pid_fd.update(&pid_fd, &zero);

    u16 family;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET) 
    {
        struct info_t info = {.pid = pid, .fd = ret};
            
        bpf_get_current_comm(&info.task, sizeof(info.task));
        info.type = SOCKET_ACCEPT;
        set_sock_info(&info, sk);

        add_address_map(pid, ret, sk);
        ipv4_events.perf_submit(ctx, &info, sizeof(info));
    }
    else if (family == AF_INET6) 
    {
        struct ipv6_info_t info = {.pid = pid, .fd = ret};
            
        bpf_get_current_comm(&info.task, sizeof(info.task));
        
        info.type = SOCKET_ACCEPT;
        set_sock_v6_info(&info, sk);

        add_address_map(pid, ret, sk);
        ipv6_events.perf_submit(ctx, &info, sizeof(info));
    }
    return 0;
}

int rcall_sys_accept4(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == ROUTER_PID)
        return 0;
    u32 ret = PT_REGS_RC(ctx);
    struct socket* socket = get_socket_from_fd(ret);

    struct sock* sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &socket->sk);

    possible_net_t netns;
    bpf_probe_read(&netns, sizeof(netns), &sk->__sk_common.skc_net);
    
    u32 netns_inum;
    bpf_probe_read(&netns_inum, sizeof(netns_inum), &netns.net->ns.inum); 
    if (netns_inum == HOST_NS){
        return 0;
    }

    u16 sk_type = 0;
    /* Caution: this refers to bitfield address of sk_type in net/sock.h of linux 4.17 */
    bpf_probe_read(&sk_type , 2, ((u8*)sk) + offsetof(typeof(struct sock), sk_gso_max_segs) - 2);
    if (sk_type != SOCK_STREAM)
        return 0; 

    struct pid_fd_t pid_fd = {.pid = pid, .fd=ret};
    u32 zero = 0;
    active_pid_fd.update(&pid_fd, &zero);

    u16 family;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET) 
    {
        struct info_t info = {.pid = pid, .fd = ret};
            
        bpf_get_current_comm(&info.task, sizeof(info.task));
        info.type = SOCKET_ACCEPT;
        set_sock_info(&info, sk);

        add_address_map(pid, ret, sk);
        ipv4_events.perf_submit(ctx, &info, sizeof(info));
    }
    else if (family == AF_INET6) 
    {
        struct ipv6_info_t info = {.pid = pid, .fd = ret};
            
        bpf_get_current_comm(&info.task, sizeof(info.task));
        info.type = SOCKET_ACCEPT;
        set_sock_v6_info(&info, sk);

        add_address_map(pid, ret, sk);
        ipv6_events.perf_submit(ctx, &info, sizeof(info));
    }
    return 0;
}

/* Client Probe */

BPF_HASH(currconn, u32, u32);

int call_sys_connect(struct pt_regs *ctx)
{
    if(!is_host_process())
    {
        u32 tid = bpf_get_current_pid_tgid();
        if (tid == ROUTER_PID)
            return 0;
        u32 fd = PT_REGS_PARM1(ctx);
        currconn.update(&tid, &fd);
    }
    return 0;
}

int rcall_sys_connect(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    u32 *fd = currconn.lookup(&tid);
    if (!fd){
        currconn.delete(&tid);
        return 0;
    }

    struct socket* socket = get_socket_from_fd(*fd);
            
    struct sock* sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &socket->sk);

    possible_net_t netns;
    bpf_probe_read(&netns, sizeof(netns), &sk->__sk_common.skc_net);
    
    u32 netns_inum;
    bpf_probe_read(&netns_inum, sizeof(netns_inum), &netns.net->ns.inum); 
    if (netns_inum == HOST_NS){
        return 0;
    }

    u16 sk_type = 0;
    /* Caution: this refers to bitfield address of sk_type in net/sock.h of linux 4.17 */
    bpf_probe_read(&sk_type , 2, ((u8*)sk) + offsetof(typeof(struct sock), sk_gso_max_segs) - 2);
    if (sk_type != SOCK_STREAM)
        return 0; 


    u16 family;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    u64 fd_val;
    bpf_probe_read(&fd_val, sizeof(fd_val), fd);
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd_val};
    u32 zero = 0;
    active_pid_fd.update(&pid_fd, &zero);


    if (family == AF_INET) 
    {
        struct info_t info = {.pid = pid};
        bpf_probe_read(&info.fd, sizeof(info.fd), fd);
         
        info.type = SOCKET_CONNECT;
        bpf_get_current_comm(&info.task, sizeof(info.task));
        set_sock_info(&info, sk);

        add_address_map(pid, *fd, sk);
        ipv4_events.perf_submit(ctx, &info, sizeof(info));
    }
    else if (family == AF_INET6) 
    {
        struct ipv6_info_t info = {.pid = pid};
        bpf_probe_read(&info.fd, sizeof(info.fd), fd);
         
        info.type = SOCKET_CONNECT;
        bpf_get_current_comm(&info.task, sizeof(info.task));
        set_sock_v6_info(&info, sk);

        add_address_map(pid, *fd, sk);
        ipv6_events.perf_submit(ctx, &info, sizeof(info));
    }
    currconn.delete(&tid);
    return 0;
}



/* set sockopt */

struct sockopt_index_t {
    u32 pid;
    u32 fd;
    int optname;
};
struct sockopt_val_t {
    int level;
    int optval;
    u32 optlen;
}; 

BPF_HASH(set_opt_index, struct pid_fd_t, struct sockopt_index_t);
BPF_HASH(set_opt_detail, struct sockopt_index_t, struct sockopt_val_t);


int call_sys_setsockopt(struct pt_regs *ctx, int fd, int level, int optname, const void *optval, int _optlen)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    u32 *val = active_pid_fd.lookup(&pid_fd);


    if(val)
    {
        struct sockopt_index_t index = {.pid = pid, .fd = fd, .optname = optname};
        
        struct sockopt_index_t *_index_val = set_opt_index.lookup_or_init(&pid_fd, &index);
        struct sockopt_index_t index_val;
        bpf_probe_read(&index_val, sizeof(index_val), _index_val);
 
        struct sockopt_val_t new_val = {.level = level};
        
        bpf_probe_read(&new_val.optlen, sizeof(new_val.optlen), &_optlen);
        bpf_probe_read(&new_val.optval, sizeof(new_val.optval), optval);

        struct sockopt_val_t* optval_val = set_opt_detail.lookup_or_init(&index_val, &new_val);
        if(optval_val) {
            set_opt_detail.update(&index_val, &new_val);
        }
        
    }
    return 0;
}


/* get_sockname replace */


BPF_HASH(currsock_fd, u32, u32);
BPF_HASH(currsock_addr, struct pid_fd_t, struct sockaddr_in*);
BPF_HASH(currsock_len, struct pid_fd_t, void*);

BPF_HASH(currsock_peer_fd, u32, u32);
BPF_HASH(currsock_peer_addr, struct pid_fd_t, struct sockaddr_in*);
BPF_HASH(currsock_peer_len, struct pid_fd_t, void*);


int call_sys__getsockname(struct pt_regs *ctx, int in_fd, struct sockaddr_in *dst, void *dst_len)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 fd = PT_REGS_PARM1(ctx);
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    u32 *val = active_pid_fd.lookup(&pid_fd);
    if (val)
    {  
        currsock_fd.update(&pid, &fd);
        currsock_addr.update(&pid_fd, &dst);
        currsock_len.update(&pid_fd, &dst_len);
    }
    return 0;
}


int call_sys_getpeername(struct pt_regs *ctx, int in_fd, struct sockaddr_in *dst, void *dst_len)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 fd = PT_REGS_PARM1(ctx);
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    u32 *val = active_pid_fd.lookup(&pid_fd);
    if (val)
    {  
        currsock_peer_fd.update(&pid, &fd);
        currsock_peer_addr.update(&pid_fd, &dst);
        currsock_peer_len.update(&pid_fd, &dst_len);
    }
    return 0;
}

int rcall_sys__getsockname(struct pt_regs* ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *fd = currsock_fd.lookup(&pid);
    if (!fd){
        currsock_fd.delete(&pid);
        return 0;
    }    
    struct pid_fd_t pid_fd = {.pid = pid, .fd=*fd};
    struct sockaddr_in** dst = currsock_addr.lookup(&pid_fd);
    if (!dst){
        currsock_addr.delete(&pid_fd);
        return 0;
    }
    void** dst_len = currsock_len.lookup(&pid_fd);
    if (!dst_len){
        currsock_len.delete(&pid_fd);
        return 0;
    }
    struct address_info_t *address_info = address_map.lookup(&pid_fd);
    if (address_info)
    {  
        struct sockaddr_in src;
        __builtin_memset(&src, 0, sizeof(src));
        src.sin_family = address_info->family;
        src.sin_port = address_info->port;
        src.sin_addr.s_addr = address_info->saddr;
        u32 addrlen = sizeof(src);
        bpf_probe_write_user(*dst, &src, addrlen);
        bpf_probe_write_user(*dst_len, &addrlen, sizeof(addrlen));
    }
    currsock_fd.delete(&pid);
    currsock_addr.delete(&pid_fd);
    currsock_len.delete(&pid_fd);
    return 0;
}


int rcall_sys_getpeername(struct pt_regs* ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 id = bpf_get_current_pid_tgid();
    u32 *fd = currsock_peer_fd.lookup(&pid);
    if (!fd){
        currsock_peer_fd.delete(&pid);
        return 0;
    }
    struct pid_fd_t pid_fd = {.pid = pid, .fd=*fd};
    struct sockaddr_in** dst = currsock_peer_addr.lookup(&pid_fd);
    if (!dst){
        currsock_peer_addr.delete(&pid_fd);
        return 0;
    }
    void** dst_len = currsock_peer_len.lookup(&pid_fd);
    if (!dst_len){
        currsock_peer_len.delete(&pid_fd);
        return 0;
    }

    struct address_info_t *address_info = peer_address_map.lookup(&pid_fd);
    if (address_info)
    {  
        struct sockaddr_in src;
        __builtin_memset(&src, 0, sizeof(src));
        src.sin_family = address_info->family;
        src.sin_port = address_info->port;
        src.sin_addr.s_addr = address_info->saddr;
        u32 addrlen = sizeof(src);
        bpf_probe_write_user(*dst, &src, addrlen);
        bpf_probe_write_user(*dst_len, &addrlen, sizeof(addrlen));
    } 
    currsock_peer_fd.delete(&pid);
    currsock_peer_addr.delete(&pid_fd);
    currsock_peer_len.delete(&pid_fd);
    rw_memo.delete(&pid_fd);
    return 0;
}

/* read write detect */

static void update_rw_memo(struct pt_regs *ctx)
{
    u64 pid_tgid= bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 fd = PT_REGS_PARM1(ctx);
    
    struct pid_fd_t pid_fd = {.pid = pid, .fd=fd};
    u32 *active = active_pid_fd.lookup(&pid_fd);
    u32 *memo = rw_memo.lookup(&pid_fd);
    
    if(active && !memo)
    {
        u32 tid = pid_tgid;
        rw_memo.update(&pid_fd, &tid);
    }
}

int call_sys_write(struct pt_regs *ctx)
{
    update_rw_memo(ctx);
    return 0;
}

int call_sys_read(struct pt_regs *ctx)
{
    update_rw_memo(ctx);
    return 0;
}

int call_sys_writev(struct pt_regs *ctx)
{
    update_rw_memo(ctx);
    return 0;
}

int call_sys_readv(struct pt_regs *ctx)
{
    update_rw_memo(ctx);
    return 0;
}

"""

#############################################################

def get_addr_info(event, protocol):
    if protocol == AF_INET:
        src_addr = inet_ntop(protocol, pack("I", event.saddr))
        dest_addr = inet_ntop(protocol, pack("I", event.daddr))
    else:
        src_addr = inet_ntop(protocol, event.saddr)
        dest_addr = inet_ntop(protocol, event.daddr)
    src_port = event.lport
    dest_port = event.dport
    return (src_addr, src_port), (dest_addr, dest_port)


#######  filter out children of runtime shim and sshd #######

from subprocess import check_output

def get_pid(name):
    return check_output(["pidof",name]).decode().strip()

def set_or_init_pid(pid, tag, default="1"):
    global bpf_text
    if pid == "":
        pid = default
    bpf_text = bpf_text.replace(tag, pid)

SSHD = "sshd"
sshd_pid = get_pid(SSHD).split(" ")[-1]

HOST_NS = os.readlink("/proc/1/ns/net").split("[")[1][0:-1]
set_or_init_pid(sshd_pid, "<SSHD_PID>")
set_or_init_pid(str(ROUTER_PID), "<ROUTER_PID>")
set_or_init_pid(HOST_NS, "<HOST_NS>", default="0")

################ bpf event handler ############################

# define globally
b = None
address_map = None
peer_address_map = None
rw_memo_map = None
tracking_pid_fds = None
server_helper = None
ruler = None
coordinator = None

class FDHelper:
    def __init__(self):
        self.fd_dict = dict()

    def insert(self, pid, fd, addr):
        if pid not in self.fd_dict:
            self.fd_dict[pid] = dict()
        self.fd_dict[pid][addr] = fd
    
    def find(self, pid, addr, protocol):
        if pid not in self.fd_dict:
            return -1
        if addr not in self.fd_dict[pid]:
            if protocol == AF_INET:
                wild_addr = ('0.0.0.0', addr[1])
            elif protocol == AF_INET6:
                wild_addr = ('::', addr[1])
            if wild_addr not in self.fd_dict[pid]:
                return -1
            return self.fd_dict[pid][wild_addr]
        return self.fd_dict[pid][addr]

def handle_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    handle_event(event, AF_INET)

def handle_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    handle_event(event, AF_INET6)
    
def handle_event(event, protocol):
    pid_fd = (event.pid, event.fd)
    
    if event.type == SOCKET_LISTEN:
        server_overlay_addr, _ = get_addr_info(event, protocol)
        if server_overlay_addr == coordinator.ipaddr:
            return
    
        if ruler.filter(event.pid, server_overlay_addr[0], None, protocol):
            server_helper.insert(event.pid, event.fd, server_overlay_addr)
            try:
                coordinator.handle_listen(server_overlay_addr, event.pid, event.fd, event.backlog, protocol)
                if event.pid not in tracking_pid_fds:
                    tracking_pid_fds[event.pid] = []
                tracking_pid_fds[event.pid].append(event.fd)
            except KeyError:
                logger.error("Cannot find information of {}".format(pid_fd))
    elif event.type == SOCKET_ACCEPT:
        if event.fd > 0:
            server_overlay_addr, client_overlay_addr = get_addr_info(event, protocol)
            if ruler.filter(event.pid, server_overlay_addr[0], client_overlay_addr[0], protocol):
                listen_fd = server_helper.find(event.pid, server_overlay_addr, protocol)
                logger.debug("Handle accept with listen fd {0}".format(listen_fd))
                if listen_fd > 0:
                    coordinator.handle_accept(event.pid, listen_fd, event.fd, server_overlay_addr, client_overlay_addr, protocol)
    elif event.type == SOCKET_CONNECT:
        client_overlay_addr, server_overlay_addr = get_addr_info(event, protocol)
        if server_overlay_addr == coordinator.ipaddr or client_overlay_addr == coordinator.ipaddr:
            return
        if ruler.filter(event.pid, server_overlay_addr[0], client_overlay_addr[0], protocol):
            if event.pid not in tracking_pid_fds:
                tracking_pid_fds[event.pid] = []
            tracking_pid_fds[event.pid].append(event.fd)
            coordinator.handle_connect(event.pid, event.fd, client_overlay_addr, server_overlay_addr, protocol)
    elif event.type == SOCKET_CLOSE:
        if event.pid in tracking_pid_fds and event.fd in tracking_pid_fds[event.pid]:
            coordinator.handle_close(event.pid, event.fd)
        return
    else:
        logger.debug("Get other types: {0},{1},{2}".format(event.pid, event.fd, event.type))

def run():
    from component.coordinator import CoordinatorThread
    from component.ruler import Ruler

    global b, tracking_pid_fds, server_helper, ruler, coordinator
    global address_map, peer_address_map, rw_memo_map
    
    b = BPF(text=bpf_text)
    
    tracking_pid_fds = dict()
    server_helper = FDHelper()
    ruler = Ruler(CONFIG_FOLDER)

    logger.info("{}".format(WELCOME_TEXT))
    logger.info("Start Program PID={0}, NS={1}".format(ROUTER_PID, HOST_NS))
    logger.info(ruler.summary())

    b.attach_kprobe(event="sys_listen", fn_name="call_sys_listen")
    b.attach_kprobe(event="sys_close", fn_name="call_sys_close")
    b.attach_kretprobe(event="sys_accept", fn_name="rcall_sys_accept")
    b.attach_kretprobe(event="sys_accept4", fn_name="rcall_sys_accept4")
    b.attach_kprobe(event="sys_connect", fn_name="call_sys_connect")
    b.attach_kretprobe(event="sys_connect", fn_name="rcall_sys_connect")
    b.attach_kprobe(event="sys_setsockopt", fn_name="call_sys_setsockopt")
    if BPF_SOKCNAME_ENABLE:
        logger.info("Attach getsockname")
        b.attach_kprobe(event="sys_getsockname", fn_name="call_sys__getsockname")
        b.attach_kretprobe(event="sys_getsockname", fn_name="rcall_sys__getsockname")
    if BPF_PEERNAME_ENABLE:
        logger.info("Attach getpeername")
        b.attach_kprobe(event="sys_getpeername", fn_name="call_sys_getpeername")
        b.attach_kretprobe(event="sys_getpeername", fn_name="rcall_sys_getpeername")
    if BPF_RW_MEMO_ENABLE:
        b.attach_kprobe(event="sys_write", fn_name="call_sys_write")
        b.attach_kprobe(event="sys_read", fn_name="call_sys_read")
        b.attach_kprobe(event="sys_writev", fn_name="call_sys_writev") # <- need for MPI, confuse memcached
        b.attach_kprobe(event="sys_readv", fn_name="call_sys_readv") # <- need for MPI, confuse memcached

    b["ipv4_events"].open_perf_buffer(handle_ipv4_event)
    b["ipv6_events"].open_perf_buffer(handle_ipv6_event)

    address_map = b.get_table("address_map")
    peer_address_map = b.get_table("peer_address_map")
    rw_memo_map = b.get_table("rw_memo")
    set_opt_detail_map = b.get_table("set_opt_detail")

    coordinator = CoordinatorThread(ROUTER_PORT, OVERLAY_IF, rw_memo_map, set_opt_detail_map)
    coordinator.deamon = True
    coordinator.start()

    def receiveSignal(signalNumber, frame):
        sys.exit(0)

    try:
        # Handle quit signal by detach the kprobe before closing the program
        signal.signal(signal.SIGINT, receiveSignal)
        signal.signal(signal.SIGQUIT, receiveSignal)
        signal.signal(signal.SIGTERM, receiveSignal)

        while True:
            b.perf_buffer_poll()
            
    finally:
        logger.warning("Router closed")

        coordinator.stop()
        address_map.clear()
        peer_address_map.clear()
        rw_memo_map.clear()
        set_opt_detail_map.clear()
        try:
            b.detach_kprobe(event="sys_close")
            b.detach_kprobe(event="sys_listen")
            b.detach_kretprobe(event="sys_accept")
            b.detach_kretprobe(event="sys_accept4")
            b.detach_kprobe(event="sys_connect")
            b.detach_kretprobe(event="sys_connect")
            b.detach_kprobe(event="sys_setsockopt")
            
            if BPF_SOKCNAME_ENABLE:
                b.detach_kprobe(event="sys_getsockname")
                b.detach_kretprobe(event="sys_getsockname")
            if BPF_PEERNAME_ENABLE:
                b.detach_kprobe(event="sys_getpeername")
                b.detach_kretprobe(event="sys_getpeername")
            if BPF_RW_MEMO_ENABLE:
                b.detach_kprobe(event="sys_write")
                b.detach_kprobe(event="sys_writev")
                b.detach_kprobe(event="sys_read")
                b.detach_kprobe(event="sys_readv")
        except Exception as e:
            logger.warning("Router detach error {}".format(e))


if __name__ == "__main__":
    run()
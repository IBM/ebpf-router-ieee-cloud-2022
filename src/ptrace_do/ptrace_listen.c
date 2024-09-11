////////////////////////////////////////////////
// Copyright 2022- IBM Inc. All rights reserved
// SPDX-License-Identifier: Apache-2.0
////////////////////////////////////////////////

////////////////////////////////////////////////////////
// Ptrace Listen is called by forwarder to transfer fd
// usage: ptrace_listen pid listen_fd
// 
// Ptrace inject the following calls:
// 1. connect: to connect to the unix socket listen_fd.sock (created by forwarder)
// 2. recvmsg: to recieve fd
//
//////////////////////////////////////////////////////


#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <string.h>


#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "libptrace_do.h"
#define BUFF_SIZE 50
#define DGRAM_SIZE 1024


// Credit: https://man7.org/tlpi/code/online/dist/sockets/unix_sockets.c.html#unixBuildAddress
int unixBuildAddress(const char *path, struct sockaddr_un *addr)
{
    if (addr == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
    if (strlen(path) < sizeof(addr->sun_path)) {
        strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
        return 0;
    } else {
        errno = ENAMETOOLONG;
        return -1;
    }
}
// Credit: slim
int get_msg_hdr(struct ptrace_do *target, struct msghdr *recv_buffer, struct iovec *iov_buffer, char* control, char* buf)
{
    void *iov_remote_addr;
    void *buf_remote_addr;
    void *control_remote_addr;

    struct msghdr msg;
    struct iovec iov;
    
    memset(buf, 0, 2);
    buf_remote_addr = ptrace_do_push_mem(target, buf);
    iov.iov_base = buf_remote_addr;
    iov.iov_len = 2;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    int control_size = CMSG_SPACE(sizeof (int));
    
    memset(control, 0, control_size);
    control_remote_addr = ptrace_do_push_mem(target, buf);
    msg.msg_iovlen = 1;
    msg.msg_control = control_remote_addr;
    msg.msg_controllen = control_size;

    
    memcpy(iov_buffer, &iov, sizeof(struct iovec));
    iov_remote_addr = ptrace_do_push_mem(target, iov_buffer);

    msg.msg_iov = iov_remote_addr;
    memcpy(recv_buffer, &msg, sizeof(struct msghdr));

    return 0;
}
// Credit: Slim
int get_fd_from_msg(struct msghdr *recv_buffer)
{
    int fd = -1;
    struct cmsghdr *cmsg;
    cmsg = CMSG_FIRSTHDR(recv_buffer);
    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmsg->cmsg_level != SOL_SOCKET) {
            fprintf (stderr, "invalid cmsg_level %d\n",
                    cmsg->cmsg_level);
            return -1;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) {
            fprintf (stderr, "invalid cmsg_type %d\n",
                    cmsg->cmsg_type);
            return -1;
        }
        int *fd_p = (int *)CMSG_DATA(cmsg);
        fd = *fd_p;
    } else {
        fd = -1;
    }

    return(fd);
}

int listen_unix_socket(struct ptrace_do *target, int listen_fd)
{
    struct sockaddr_un saddr;
    struct sockaddr_un* buffer;
    void* remote_addr;

    char path[BUFF_SIZE];
    char* path_buffer;
    unsigned long new_fd;
    int res;
    //int recv_fd;

    struct msghdr *recv_buffer;
    struct iovec *iov_buffer;
    char* control;
    char* buf;

    void* recv_addr;

    char ret_msg[10];
    char* ret_msg_buf;
    void* remote_ret_msg_addr;
    ret_msg_buf = (char*)ptrace_do_malloc(target, sizeof(ret_msg));

    snprintf(path, BUFF_SIZE,"/tmp/listen%d.sock", listen_fd);

    if(unixBuildAddress(path, &saddr) < 0){
        printf("Listen: Error, cannot build unix socket %s\n",path);
        return -1;
    }
    path_buffer = (char *) ptrace_do_malloc(target, BUFF_SIZE);
    memcpy(path_buffer, &path, BUFF_SIZE);
    remote_addr = ptrace_do_push_mem(target, path_buffer);

    buffer = (struct sockaddr_un*) ptrace_do_malloc(target, sizeof(saddr));
    memcpy(buffer, &saddr, sizeof(saddr));
    remote_addr = ptrace_do_push_mem(target, buffer);

    // socket() 
    new_fd = ptrace_do_syscall(target, __NR_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0); 
    printf("Listen: new socket: %ld\n",new_fd);
    // connect()
RECONNECT:
    res = ptrace_do_syscall(target, __NR_connect, new_fd, (unsigned long)(struct sockaddr*)remote_addr, (unsigned long)sizeof(struct sockaddr_un), 0, 0, 0);
    if(res < 0){
        printf("Listen: failed to connect %s by fd:%ld (%d)\n", saddr.sun_path, new_fd, res);
        sleep(1);
        goto RECONNECT;
    }
    printf("Listen: connected\n");
     
    int control_size = CMSG_SPACE(sizeof (int));
    buf = (char*) ptrace_do_malloc(target, sizeof(2));
    control = (char*) ptrace_do_malloc(target, sizeof(control_size));
    iov_buffer = (struct iovec*) ptrace_do_malloc(target, sizeof(struct iovec));
    recv_buffer = (struct msghdr*) ptrace_do_malloc(target, sizeof(struct msghdr));

    get_msg_hdr(target, recv_buffer, iov_buffer, control, buf);
    recv_addr = ptrace_do_push_mem(target, recv_buffer);
RECV:
    res = ptrace_do_syscall(target, __NR_recvmsg, new_fd, (unsigned long)(struct msghdr*)recv_addr, 0, 0, 0, 0);
    if(res < 0){
        printf("Error, failed to recvmsg %s by fd:%ld (%d)\n", saddr.sun_path, new_fd, res);
        sleep(0.5);
        goto RECV;
    } else {
        snprintf(ret_msg_buf, 10, "SUCCESS");
        remote_ret_msg_addr = ptrace_do_push_mem(target, ret_msg_buf);
        ptrace_do_syscall(target, __NR_write, new_fd, (unsigned long)remote_ret_msg_addr, strlen(ret_msg_buf), 0, 0, 0);
        printf("Successfully recvmsg \n");
    }   

    ptrace_do_syscall(target, __NR_close, new_fd, 0, 0, 0, 0, 0);
    ptrace_do_free(target, buf, FREE_BOTH);
    ptrace_do_free(target, control, FREE_BOTH);
    ptrace_do_free(target, iov_buffer, FREE_BOTH);
    ptrace_do_free(target, recv_buffer, FREE_BOTH);

    return 0;
}

int main(int argc, char** argv)
{
    // inputs
    if(argc != 3){
        printf("Error,Wrong arguments %d need 3\n", argc);
        return 0;
    }
    int pid = atoi(argv[1]);
    int listen_fd = atoi(argv[2]);
    struct ptrace_do* target;
    struct stat sts;
    char pid_path[20];
    sprintf(pid_path,"/proc/%d", pid);
    printf("Listen on Pid = %s\n", pid_path);
    // init ptrace
    target = ptrace_do_init(pid);


    while( target== NULL){
        if (stat(pid_path, &sts) == -1) {
            break;
        }
        sleep(2);
        target = ptrace_do_init(pid);
    }

    if(target == NULL)
    {
        printf("Listen: Done\n");
        return 0;
    }
    // listen to unix socket to get accept fd from other process
    listen_unix_socket(target, listen_fd);
    ptrace_do_cleanup(target);    
    printf("Listen: Done\n");

    return 0;
}


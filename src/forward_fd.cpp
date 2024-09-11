#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <errno.h>

#include <fcntl.h>
#include <sched.h>

#include <sys/wait.h>

#include <errno.h>

#include <dirent.h> 

#define BUFF_SIZE 30

/////////////////////////////
//
// To find inode from pid,fd
//
/////////////////////////////
#include<string.h>
#include <dirent.h>

int indexof(const char* buffer, char ch){
    int ci;
    for(ci=0;ci < strlen(buffer);ci++){
        if(buffer[ci] == ch){
            return ci;
        }
    }
    return -1;
}
int get_inode(int pid, int fd){

    char path[30];
    char buffer[30];

    sprintf(path, "/proc/%d/fd/%d", pid, fd);
    if( access( path, F_OK ) == 0 ) {
        int found = readlink(path, buffer, sizeof(buffer));
        int index = indexof(buffer, '[');
        if (index < 0){
            return -1;
        }else{
            char inode_str[20];
            int inode_len = strlen(buffer)-index-2;
            memcpy(inode_str, &buffer[index+1], inode_len);
            inode_str[inode_len] = '\0';
            return atoi(inode_str);
        }

    } else {
        printf("File not found\n");
        return -1;
    }
}

int find_inode(int pid, int target_inode){
    if(target_inode == -1)
        return -1;
    char path[30];
    sprintf(path, "/proc/%d/fd", pid);

    DIR *d;
    struct dirent *dir;
    d = opendir(path);
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if(strstr(dir->d_name,".")){
                continue;
            }
            int fd = atoi(dir->d_name);
            if(fd < 3) // stdin/out/err
                continue;
            int inode = get_inode(pid, fd);
            if(inode == target_inode){
                closedir(d);
                return fd;
            }
        }
        closedir(d);
    }
    return -1;
}


/////////////////////////////

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

// Credit: Slim
int recv_fd(int unix_sock, int &overlay_pid, int &overlay_fd)
{
    ssize_t size;
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr cmsghdr;
        char control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr *cmsg;

    int fd = -1;
    char buf[20];
    iov.iov_base = buf;
    iov.iov_len = 20;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);
    size = recvmsg (unix_sock, &msg, 0);
    if (size < 0) {
        printf("recvmsg error");
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&msg);
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
        // printf ("received fd %d\n", fd);
    } else {
        fd = -1;
    }

    // substring pid, fd
    int index = strcspn(buf, ",");
    int fd_size = strlen(buf)-index;
    char pid_str[index];
    char fd_str[fd_size];
    memcpy(pid_str, buf, index);
    memcpy(fd_str, &buf[index+1], fd_size);
    printf("Get request to send %s to process %s from fd=%d\n", fd_str, pid_str, fd);
    overlay_pid = atoi(pid_str);
    overlay_fd = atoi(fd_str);
    return(fd);
}

// Credit: Slim
int send_fd(int unix_sock, int fd)
{
    ssize_t     size;
    struct msghdr   msg;
    struct iovec    iov;
    union {
        struct cmsghdr  cmsghdr;
        char        control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr  *cmsg;
    char buf[2];

    iov.iov_base = buf;
    iov.iov_len = 2;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (fd != -1) {
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof (int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        int *fd_p = (int *) CMSG_DATA(cmsg);
        *fd_p = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        printf ("Error, not passing fd\n");
        return -1;
    }

    size = sendmsg(unix_sock, &msg, 0);

    if (size < 0) {
        printf("Error, recvmsg error\n");
        return 0;
    }
    return size;
}

int move_ns(int pid){
    char path[BUFF_SIZE] = {'\0'};
    int nsfd;
    snprintf(path, BUFF_SIZE, "/proc/%d/ns/mnt", pid);
    nsfd = open(path, O_RDONLY);
    if(nsfd > 0){
        setns(nsfd, 0);
        return 1;
    }
    printf("Error,Cannot open expected namespace %s\n", path);
    return 0;
}

int call_ptrace_listen(int pid, int accept_fd)
{
    char pid_str[10];
    char accept_fd_str[5];
    sprintf(pid_str, "%d", pid);
    sprintf(accept_fd_str,"%d", accept_fd);
    printf("Call Ptrace Listen %d\n", accept_fd);
    execl("/usr/local/bin/ptrace_listen",  "ptrace_listen", pid_str, accept_fd_str, NULL);
    printf("Call Listen Return\n");
}

int current_unix_listen_fd;

void handle_sigalarm(int sig)
{
   printf("Forwarder: Timeout %d\n", sig);
   shutdown(current_unix_listen_fd, SHUT_RD);
   close(current_unix_listen_fd);
}


int create_socket_and_send(int listen_fd, int accept_fd)
{
    char path[BUFF_SIZE];
    snprintf(path, BUFF_SIZE, "/tmp/listen%d.sock", accept_fd);
    printf("Forwarder: create unix socket to %s (sending %d)\n", path, accept_fd);

    remove(path);
    
    struct sockaddr_un saddr;
    unsigned long unix_listen_fd, unix_accept_fd;
    int res;

    if(unixBuildAddress(path, &saddr) < 0){
        printf("Forwarder: cannot build unix socket %s\n",path);
        return 0;
    }
    unix_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if((res = bind(unix_listen_fd, (struct sockaddr *) &saddr, sizeof(saddr))) < 0){
        printf("Forwarder: failed to bind %s by fd:%ld (%d)\n", saddr.sun_path, unix_listen_fd, res);
        close(unix_listen_fd);
        return 0;
    }

    char mode[] = "0766";
    int mode_int = strtol(mode, 0, 8);
    chmod(path, mode_int);
    
    if((res = listen(unix_listen_fd, 1)) < 0){
        printf("Forwarder: failed to listen %s by fd:%ld (%d)\n", saddr.sun_path, unix_listen_fd, res);
        close(unix_listen_fd);
        return 0;
    }
    printf("Forwarder: listening\n");
    struct sockaddr_in address; 
    int addrlen = sizeof(address); 
    current_unix_listen_fd = unix_listen_fd;
    
    signal(SIGALRM , handle_sigalarm);
    alarm(60);
    unix_accept_fd = accept(unix_listen_fd, (struct sockaddr *)&address,  (socklen_t*)&addrlen);
    alarm(0);
    if(unix_accept_fd > 0)
    {
        char read_buffer[10];
        send_fd(unix_accept_fd, accept_fd);
        read(unix_accept_fd, read_buffer, 10);
        printf("Read %s\n", read_buffer);
        close(unix_accept_fd);
    }

    close(unix_listen_fd);
    return unix_accept_fd;
}

int move_and_send(int pid, int listen_fd, int accept_fd, int main_ns_fd)
{
    if(move_ns(pid))
    {   
        int res = create_socket_and_send(listen_fd, accept_fd);
        printf("Forwarder:  accept fd = %d\n", res);
        close(accept_fd);
        setns(main_ns_fd, 0);
    }
}

int transfer_to_overlay(int pid, int listen_fd, int accept_fd, int main_ns_fd)
{
    pid_t listen_child;
    int status;
    int inode = get_inode(getpid(), accept_fd);
    printf("Inode:%d\n", inode);
    listen_child = fork();
    if(listen_child < 0)
    {   
        printf("Forwarder: failed to fork listen");
        return -1;
    }
    if(listen_child == 0){
        call_ptrace_listen(pid, accept_fd);
        return 0;
    }else {   
        move_and_send(pid, listen_fd, accept_fd, main_ns_fd);
        int target_fd = find_inode(pid, inode);
        return target_fd;
    }
}

int main(int argc, char** argv) 
{ 
    char path[20]="/tmp/transfer.sock";
    struct sockaddr_un saddr;
    unsigned long listen_sock;
    int addr_size = sizeof(struct sockaddr_un);
    int res;

    remove(path);

    if(unixBuildAddress(path, &saddr) < 0){
        printf("Error, cannot build unix socket %s\n",path);
        return 0;
    }

    int mypid = getpid();
    char ns_path[BUFF_SIZE] = {'\0'};
    snprintf(ns_path, BUFF_SIZE, "/proc/%d/ns/mnt", mypid);
    int main_ns_fd = open(ns_path, O_RDONLY);

    if(main_ns_fd < 0)
    {
        printf("Error, cannot open original namespace\n");
        return 0;
    }

    listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if(listen_sock == -1)
    {
        printf("Error, socket\n");
        return 0;        
    }
    res = bind(listen_sock, (struct sockaddr *) &saddr, sizeof(struct sockaddr_un));
    if(res<0)
    {
        printf("Error, bind %d\n", res);
        return 0;
    }

    if(listen(listen_sock, 128) < 0)
    {
        printf("Error, listen %d\n", res);
        return 0;        
    }
    printf("Listening %ld\n", listen_sock);

    struct sockaddr_un accept_addr;
    memset(&accept_addr, 0, sizeof(accept_addr));

    while(1)
    {   
        printf("Wait for next customer\n");
        int accept_sock = accept(listen_sock, (struct sockaddr *) &accept_addr, (socklen_t*) &addr_size);
        char* message;
        int pid, fd;
        int accept_fd = recv_fd(accept_sock, pid, fd);
        // int target_fd = transfer_to_overlay(pid, fd, accept_fd, main_ns_fd);

        pid_t listen_child;
        int status;
        int inode = get_inode(getpid(), accept_fd);
        printf("Inode:%d\n", inode);
        listen_child = fork();
        if(listen_child < 0)
        {   
            printf("Forwarder: failed to fork listen");
            return -1;
        }
        if(listen_child == 0){
            call_ptrace_listen(pid, accept_fd);
            return 0;
        }else {   
            move_and_send(pid, fd, accept_fd, main_ns_fd);
            int target_fd = find_inode(pid, inode);
            printf("Target fd = %d\n", target_fd);
            char sync_buffer[5];
            sprintf(sync_buffer, "%d", target_fd);
            write(accept_sock, sync_buffer, strlen(sync_buffer));
        }
    }
    return 0;
}





   
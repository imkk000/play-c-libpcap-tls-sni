#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <dirent.h>
#include <limits.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define NIC_ANY_HEADER 16
#define MIN_TLS_HEADER 6

unsigned ports_inode_cache[65536];
pthread_rwlock_t cache_lock = PTHREAD_RWLOCK_INITIALIZER;

void dump_hex(int len, const u_char *buf) {
  for (int i = 0; i < len; i++) {
    if (i % 16 == 0)
      printf("\n%04x: ", i);
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

typedef struct connection_info {
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  uint16_t sport;
  uint16_t dport;
  int tls_offset;
} connection_info;

struct connection_info *parse_tcp_header(const u_char *bytes) {
  // skip any interface header
  struct ip *ip = (struct ip *)(bytes + NIC_ANY_HEADER);
  int ip_len = ip->ip_hl * 4;

  connection_info *info = malloc(sizeof(connection_info));
  struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip + ip_len);
  int tcp_len = tcp->th_off * 4;
  inet_ntop(AF_INET, &ip->ip_src, info->saddr, sizeof(info->saddr));
  inet_ntop(AF_INET, &ip->ip_dst, info->daddr, sizeof(info->daddr));
  info->sport = ntohs(tcp->th_sport);
  info->dport = ntohs(tcp->th_dport);
  info->tls_offset = NIC_ANY_HEADER + ip_len + tcp_len;

  return info;
}

typedef struct sni_info {
  const u_char *data;
  uint16_t len;
} sni_info;

sni_info *find_sni(const u_char *tls) {
  uint16_t tls_len = (tls[3] << 8 | tls[4]) + 5;
  const u_char *p = tls + 9;   // skip record header(5) + handshake header(4)
  p += 2;                      // client version
  p += 32;                     // random
  p += 1 + *p;                 // session id (1 byte len + data)
  p += 2 + (p[0] << 8 | p[1]); // cipher suites
  p += 1 + *p;                 // compression methods
  p += 2;                      // extensions length

  // walk extensions
  while (p < tls + tls_len) {
    uint16_t ext_type = p[0] << 8 | p[1];
    uint16_t ext_len = p[2] << 8 | p[3];
    p += 4;
    if (ext_type == 0x0000) {
      uint16_t name_len = p[3] << 8 | p[4];
      sni_info *info = malloc(sizeof(sni_info));
      info->len = name_len;
      info->data = p + 5;
      return info;
    }
    p += ext_len;
  }

  return NULL;
}

typedef struct process {
  char *pid;
  char *name;
} process;

process *find_pid_by_inode(unsigned inode) {
  if (inode == 0)
    return NULL;

  char name[64];
  sprintf(name, "socket:[%d]", inode);

  DIR *proc = opendir("/proc");
  struct dirent *pid_enty;

  while ((pid_enty = readdir(proc))) {
    char fd_path[PATH_MAX];
    sprintf(fd_path, "/proc/%s/fd", pid_enty->d_name);

    DIR *fd_dir = opendir(fd_path);
    if (!fd_dir)
      continue;

    struct dirent *fd_entry;
    while ((fd_entry = readdir(fd_dir))) {
      char full[PATH_MAX], link[PATH_MAX];
      sprintf(full, "%s/%s", fd_path, fd_entry->d_name);
      ssize_t n = readlink(full, link, sizeof(link) - 1);
      if (n < 0)
        continue;
      link[n] = 0;
      if (strcmp(link, name) != 0)
        continue;

      char comm[PATH_MAX];
      sprintf(comm, "/proc/%s/comm", pid_enty->d_name);
      FILE *f = fopen(comm, "r");
      if (f) {
        char proc_name[PATH_MAX];
        fgets(proc_name, sizeof(proc_name), f);
        fclose(f);
        proc_name[strcspn(proc_name, "\n")] = '\0';
        process *p = malloc(sizeof(process));
        p->pid = strdup(pid_enty->d_name);
        p->name = strdup(proc_name);
        closedir(fd_dir);
        closedir(proc);
        return p;
      }
    }
    closedir(fd_dir);
  }
  closedir(proc);

  return NULL;
}

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
  connection_info *info = parse_tcp_header(bytes);
  const u_char *tls = bytes + info->tls_offset;

  // check length include tls handshake type
  if (h->caplen < info->tls_offset + MIN_TLS_HEADER) {
    free(info);
    return;
  }
  // ensure it is client hello
  if (tls[0] != 0x16 || tls[5] != 0x01) {
    free(info);
    return;
  }

  // find sni into extensions
  sni_info *sni = find_sni(tls);
  if (sni == NULL) {
    free(info);
    return;
  }

  printf("[%ld%ld] %s:%d -> %s:%d sni=[%.*s]", h->ts.tv_sec, h->ts.tv_usec,
         info->saddr, info->sport, info->daddr, info->dport, sni->len,
         sni->data);

  pthread_rwlock_rdlock(&cache_lock);
  unsigned inode = ports_inode_cache[info->sport];
  pthread_rwlock_unlock(&cache_lock);
  if (inode == 0) {
    printf("\n");
    return;
  }
  printf(" inode=%d", inode);

  process *proc = find_pid_by_inode(inode);
  if (proc == NULL) {
    free(sni);
    free(info);
    printf("\n");
    return;
  }
  printf(" pid=%s (%s)\n", proc->pid, proc->name);

  free(proc->pid);
  free(proc->name);
  free(proc);
  free(sni);
  free(info);
}

void *sniffer(void *_) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live("any", 65535, 1, 1000, errbuf);
  struct bpf_program fp;
  pcap_compile(handle, &fp, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(handle, &fp);
  pcap_freecode(&fp);
  pcap_loop(handle, -1, handler, NULL);
  pcap_close(handle);

  return NULL;
}

void *read_ports_inode(void *_) {
  while (1) {
    FILE *f = fopen("/proc/net/tcp", "r");
    char line[256];
    fgets(line, sizeof(line), f);

    unsigned port, inode;
    while (fgets(line, sizeof(line), f)) {
      sscanf(line, "%*d: %*8X:%X %*s %*d %*s %*s %*s %*d %*d %d", &port,
             &inode);
      if (port == 0 || inode == 0)
        continue;

      pthread_rwlock_wrlock(&cache_lock);
      ports_inode_cache[port] = inode;
      pthread_rwlock_unlock(&cache_lock);
    }
    fclose(f);
    usleep(100);
  }
}

int main() {
  pthread_t t;
  pthread_create(&t, NULL, read_ports_inode, NULL);
  pthread_detach(t);

  sniffer(NULL);
}

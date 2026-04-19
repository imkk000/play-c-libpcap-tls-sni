#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#define NIC_ANY_HEADER 16
#define MIN_TLS_HEADER 6

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

  printf("[%ld%ld] %s:%d -> %s:%d sni=[%.*s]\n", h->ts.tv_sec, h->ts.tv_usec,
         info->saddr, info->sport, info->daddr, info->dport, sni->len,
         sni->data);

  free(sni);
  free(info);
}

int main() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live("any", 65535, 1, 1000, errbuf);
  struct bpf_program fp;
  pcap_compile(handle, &fp, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(handle, &fp);
  pcap_freecode(&fp);
  pcap_loop(handle, -1, handler, NULL);
  pcap_close(handle);
}

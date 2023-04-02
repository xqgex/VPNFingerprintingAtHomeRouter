#include <linux/if_ether.h> /* ETH_P_IP */
#include <linux/init.h>
#include <linux/ip.h> /* iphdr, ip_hdr() */
#include <linux/kernel.h>
#include <linux/timekeeping.h> /* ktime_get_boottime_seconds() */
#include <linux/module.h> /* MODULE_LICENSE(), module_init(), module_exit() */
#include <linux/netfilter.h> /* NF_ACCEPT, NF_INET_FORWARD, NFPROTO_IPV4, nf_hook_ops,
                              * nf_hook_state, nf_register_net_hook(), nf_unregister_net_hook()
                              */
#include <linux/netfilter_ipv4.h> /* NF_IP_PRI_LAST */

#include "analyze_packet.h"
#include "parse_packet.h"

static const unsigned short protocol_ip = htons(ETH_P_IP);

static struct nf_hook_ops nfho;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  if (protocol_ip == skb->protocol) {
    struct iphdr const *const ip_header = ip_hdr(skb);
    ip_type source_ip = ntohl(ip_header->saddr);
    ip_type destination_ip = ntohl(ip_header->daddr);
    time64_t timestamp = ktime_get_boottime_seconds();
    printk
    (
      KERN_INFO "[Debug] Packet from %pI4 to %pI4 timestamp %llu\n",
      &ip_header->saddr,
      &ip_header->daddr,
      timestamp
    ); /* XXX */
    if (RET_ANALYZE == check_connection(&source_ip, &destination_ip)) {
      analyze(source_ip, destination_ip, timestamp);
    }
  }
  return NF_ACCEPT;
}

/**************************************************************************************************/
/**** Entry and exit points                                                                    ****/
/**************************************************************************************************/

static int __init vpn_fingerprinting_init(void) {
  printk(KERN_INFO "VPN fingerprinting module loaded.\n");
  nfho.hook = hook_funcion;
  nfho.hooknum = NF_INET_PRE_ROUTING;
  nfho.pf = NFPROTO_IPV4;
  nfho.priority = NF_IP_PRI_LAST;
  nf_register_net_hook(&init_net, &nfho);
  return 0;
}

static void __exit vpn_fingerprinting_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);
  printk(KERN_INFO "VPN fingerprinting module was removed.\n");
}

module_init(vpn_fingerprinting_init);
module_exit(vpn_fingerprinting_exit);

MODULE_LICENSE("GPL");

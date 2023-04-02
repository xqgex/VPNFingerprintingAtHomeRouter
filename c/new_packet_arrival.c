#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h> /* MODULE_LICENSE(), module_init(), module_exit() */

#include "analyze_packet.h"

static struct nf_hook_ops nfho;

/**************************************************************************************************/
/**** Entry and exit points                                                                    ****/
/**************************************************************************************************/

static int __init hello_init(void) {
  printk(KERN_INFO "Hello, world\n");
  /* Initial */
  printk(KERN_INFO "Initial list\n");
  debug_print_all_hosts();
  /* Insert 4 numbers */
  printk(KERN_INFO "Insert `8`, `1000`, `30` and then `2`\n");
  analyze(8, 0, 0);
  analyze(1000, 0, 0);
  analyze(30, 0, 0);
  analyze(2, 0, 0);
  debug_print_all_hosts();
  /* Remove tail */
  printk(KERN_INFO "Remove the tail\n");
  remove_node(hosts_tail);
  debug_print_all_hosts();
  /* Remove head */
  printk(KERN_INFO "Remove the head\n");
  remove_node(hosts_head);
  debug_print_all_hosts();
  /* Insert and then remove */
  printk(KERN_INFO "Insert `15`\n");
  analyze(15, 0, 0);
  debug_print_all_hosts();
  printk(KERN_INFO "Remove `15`\n");
  remove_node(search_node(15));
  debug_print_all_hosts();
  printk(KERN_INFO "Check the reporter for IP `8`\n");
  printk(KERN_INFO "Second packet from `8`\n");
  analyze(8, 0, 0);
  printk(KERN_INFO "Third packet from `8`\n");
  analyze(8, 0, 0);
  printk(KERN_INFO "Fourth packet from `8`\n");
  analyze(8, 0, 21U * 60U);
  printk(KERN_INFO "Fifth packet from `8`\n");
  analyze(8, 0, 0);
  /* Done */
  printk(KERN_INFO "Done\n");
  return 0;
}

static void __exit hello_exit(void) {
  printk(KERN_INFO "Goodbye, world\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");

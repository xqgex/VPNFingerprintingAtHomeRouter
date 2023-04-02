#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h> /* MODULE_LICENSE() */
#include <linux/slab.h> /* kmalloc(), kfree() */

#include "analyze_packet.h"

/**************************************************************************************************/
/**** Macros                                                                                   ****/
/**************************************************************************************************/

#define RET_FAILURE 0U
#define RET_SUCCESS 1U

/**************************************************************************************************/
/**** Typedefs                                                                                 ****/
/**************************************************************************************************/

typedef unsigned int function_ret_type;

/**
 * A data structure for an internal endpoint, that is used to track
 * the latest connection the endpoint have with the "outside world".
 */
typedef struct TrackedConnection {
  ip_type        ip_destination;
  timestamp_type timestamp;
  unsigned int   count_this; /* Note, Vulnerable for overflow */
  unsigned int   count_prev; /* Note, Vulnerable for overflow */
} TrackedConnection_type;

/**
 * A data structure for an endpoint in the internal network.
 * The endpoints are stored in a sorted doubly linked list.
 */
typedef struct hosts_node {
  ip_type                 ip;
  TrackedConnection_type  connection;
  struct hosts_node      *next;
  struct hosts_node      *prev;
} hosts_node_type;

typedef struct {
    uint32_t address;
    uint32_t mask;
} PrivateAddress;
/**************************************************************************************************/
/**** Static variables                                                                         ****/
/**************************************************************************************************/

static unsigned int    const  count_packets            = METRIC_COUNT_PACKETS;
static timestamp_type  const  time_window_sec          = METRIC_TIME_WINDOW_SEC;
static timestamp_type  const  window_overlap_threshold = METRIC_WINDOW_OVERLAP_THRESHOLD;
static hosts_node_type       *hosts_head               = NULL;
static hosts_node_type       *hosts_tail               = NULL;
const PrivateAddress privateAddresses[] = {
    {0x0A000000, 0xFF000000},          // 10.0.0.0/8
    {0xAC100000, 0xFFF00000},          // 172.16.0.0/12
    {0xC0A80000, 0xFFFF0000},          // 192.168.0.0/16
    {0xA9FE0000, 0xFFFF0000},          // 169.254.0.0/16
    {0xE0000000, 0xF0000000},          // 224.0.0.0/4
    {0xFFFFFFFF, 0xFFFFFFFF}           // broadcast address
};

/**************************************************************************************************/
/**** Private functions prototype                                                              ****/
/**************************************************************************************************/

hosts_node_type   *create_empty_node(ip_type value);
function_ret_type  insert_node(hosts_node_type *const new_node);
function_ret_type  is_suspected_vpn(ip_type ip_source);
void               remove_node(hosts_node_type *node_to_remove);
void               report(ip_type ip_source, ip_type ip_destination, timestamp_type timestamp);
hosts_node_type   *search_node(ip_type ip_source);
int is_private_ip(uint32_t address);

/**************************************************************************************************/
/**** Private functions                                                                        ****/
/**************************************************************************************************/

int is_private_ip(uint32_t address){
    int i =0 ;
    while(i < sizeof(privateAddresses)/sizeof(PrivateAddress)){
        if ((address & privateAddresses[i].mask) == privateAddresses[i].address) {
            return 1;
        }
        i++;
    }

    return 0;
}  
hosts_node_type *create_empty_node(ip_type value) {
  hosts_node_type *new_node = (hosts_node_type *)kmalloc(sizeof(hosts_node_type), GFP_KERNEL);
  new_node->ip                        = value;
  new_node->connection.ip_destination = 0U;
  new_node->connection.timestamp      = 0U;
  new_node->connection.count_this     = 0U;
  new_node->connection.count_prev     = 0U;
  new_node->prev                      = NULL;
  new_node->next                      = NULL;
  return new_node;
}

function_ret_type insert_node(hosts_node_type *const new_node) {
  function_ret_type ret = RET_SUCCESS;
  if (NULL == new_node) {
    /* To be safe */
    ret = RET_FAILURE;
  } else if (NULL == hosts_head) {
    /* First node. */
    hosts_head = new_node;
    hosts_tail = new_node;
  } else if ((new_node->ip == hosts_head->ip) || (new_node->ip == hosts_tail->ip)) {
    /* Already exists at the head or at the tail */
    ret = RET_FAILURE;
  } else if (new_node->ip < hosts_head->ip) {
    /* The node should be inserted at the beginning of the doubly linked list */
    new_node->next = hosts_head;
    hosts_head->prev = new_node;
    hosts_head = new_node;
  } else if (hosts_tail->ip < new_node->ip) {
    /* The node should be inserted at the end of the doubly linked list */
    hosts_tail->next = new_node;
    new_node->prev = hosts_tail;
    hosts_tail = new_node;
  } else {
    hosts_node_type *before_node = hosts_head;
    while ((before_node->next != NULL) && (before_node->next->ip <= new_node->ip)) {
      before_node = before_node->next;
      /**
       * Note, for optimization purposes, while going through the endpoints, we can
       * remove nodes that their connection timestamp is older than some constant.
       * Doing in once for every search should reduce the overhead.
       * Code for example:
       * ```C
       * if (0 == SOMETHING_WAS_REMOVED) {
       *   if (CURRENT_TIMESTAMP - before_node->prev->connection.timestamp < CONSTANT_VALUE) {
       *     remove_node(before_node->prev);
       *     SOMETHING_WAS_REMOVED = 1;
       *   }
       * }
       * ```
       */
    }
    if (new_node->ip == before_node->ip) {
      /* Already exists */
      ret = RET_FAILURE;
    } else {
      /**
       * We would like to insert a node between `before` and `after`:
       * ```
       * *--------*     *----------*     *-------*
       * | before | <-> | new node | <-> | after |
       * *--------*     *----------*     *-------*
       * ```
       * 1. Set the new node’s next pointer to `after` and `after`’s prev pointer to the new node.
       * 2. Set `before`'s next pointer to the new node and new node’s prev pointer to `before`.
       */
      if (before_node->next != NULL) {
        new_node->next = before_node->next;
        before_node->next->prev = new_node;
      } else {
        hosts_tail = new_node;
      }
      before_node->next = new_node;
      new_node->prev = before_node;
    }
  }
  return ret;
}

function_ret_type is_suspected_vpn(ip_type ip_source) {
  function_ret_type  ret  = RET_FAILURE;
  hosts_node_type   *node = search_node(ip_source);
  /* Note, The `if` was broken into two "parts" just to increase the readability. */
  if (node != NULL) {
    if
    (
         (count_packets < node->connection.count_this)
      || (window_overlap_threshold < (node->connection.count_prev + node->connection.count_this))
    ) {
      ret = RET_SUCCESS;
    }
  } else {
    u32 const printable_ip_source = htonl(ip_source);
    printk(KERN_INFO "[Error] Reporter failed to find IP `%pI4`\n", &printable_ip_source);
  }
  return ret;
}

void remove_node(hosts_node_type *node_to_remove) {
  if (node_to_remove != NULL) {
    if (node_to_remove == hosts_head) {
      if (hosts_head->next != NULL) {
        hosts_head->next->prev = NULL;
      }
      hosts_head = hosts_head->next;
    } else if (node_to_remove == hosts_tail) {
      if (hosts_tail->prev != NULL) { /* Just to be safe */
        hosts_tail->prev->next = NULL;
      }
      hosts_tail = hosts_tail->prev;
    } else {
      node_to_remove->next->prev = node_to_remove->prev;
      node_to_remove->prev->next = node_to_remove->next;
    }
    node_to_remove->next = NULL;
    node_to_remove->prev = NULL;
    kfree(node_to_remove);
    node_to_remove = NULL;
  }
}

void report(ip_type ip_source, ip_type ip_destination, timestamp_type timestamp) {
  u32 const printable_ip_source = htonl(ip_source);
  u32 const printable_ip_destination = htonl(ip_destination);
  (void)ip_source;
  (void)ip_destination;
  (void)timestamp;
  printk
  (
    KERN_INFO "[Reporter] source `%pI4` destination `%pI4` timestamp `%llu`\n",
    &printable_ip_source,
    &printable_ip_destination,
    timestamp
  );
}

hosts_node_type *search_node(ip_type ip_source) {
  hosts_node_type *loop_node = hosts_head;
  while ((loop_node != NULL) && (loop_node->ip < ip_source)) {
    loop_node = loop_node->next;
  }
  if ((loop_node != NULL) && (ip_source != loop_node->ip)) {
    loop_node = NULL;
  }
  return loop_node;
}

/**************************************************************************************************/
/**** Public functions                                                                         ****/
/**************************************************************************************************/
int is_tracked_connection(ip_type ip_source, ip_type ip_destination, timestamp_type timestamp){
  if(is_private_ip(ip_source)&&is_private_ip(ip_destination)){
    /*Both ip are private*/
    return 0;
  }
  else if(is_private_ip(ip_source) && (is_private_ip(ip_destination)==0)){
    /*src is private
      dst is public
      no flip is needed*/
    analyze(ip_source,ip_destination, timestamp)
    return 1;
  }
  else if(is_private_ip(ip_destination) && (is_private_ip(ip_source)==0)){
    /*src is public 
      dst is private
      flip is needed*/
    analyze(ip_destination, ip_source, timestamp)
      return 1;

  }
}
void analyze(ip_type ip_source, ip_type ip_destination, timestamp_type timestamp) {
  function_ret_type  ret  = RET_SUCCESS;
  hosts_node_type   *node = search_node(ip_source);
  if (node == NULL)) { /* Initial record */
    printk(KERN_INFO "[Debug] analyze() - Initial record\n"); /* XXX */
    node = create_empty_node(ip_source);
    ret = insert_node(node);
  }
  if (RET_SUCCESS == ret) {
    if (ip_destination != node->connection.ip_destination) { /* New connection */
      printk(KERN_INFO "[Debug] analyze() - New connection\n"); /* XXX */
      node->connection.ip_destination = ip_destination;
      node->connection.timestamp      = timestamp;
      node->connection.count_this     = 1U;
    } else {
      node->connection.count_this += 1;
    }
    if (time_window_sec < timestamp - node->connection.timestamp) { /* Start a new window */
      printk(KERN_INFO "[Debug] analyze() - Start a new window\n"); /* XXX */
      if (RET_SUCCESS == is_suspected_vpn(ip_source)) {
        report(ip_source, ip_destination, timestamp);
      }
      node->connection.timestamp  = timestamp;
      node->connection.count_prev = node->connection.count_this;
      node->connection.count_this = 0;
    }
  } else {
    u32 const printable_ip_source = htonl(ip_source);
    printk(KERN_INFO "[Error] Failed to insert a new node with IP `%pI4`\n", &printable_ip_source);
  }
}

void debug_print_all_hosts(void) {
  hosts_node_type const *loop_node = hosts_head;
  printk(KERN_INFO "List of hosts: [");
  while (loop_node != NULL) {
    printk(KERN_CONT "%d, ", loop_node->ip);
    loop_node = loop_node->next;
  }
  printk(KERN_CONT "NULL]\n");
}

MODULE_LICENSE("GPL");

#include <linux/init.h> 
#include <linux/kernel.h>
#include <linux/module.h> 
#include <linux/slab.h>

#define RET_FAILURE 0U
#define RET_SUCCESS 1U

static unsigned int const count_packets            = 10000U;
static unsigned int const time_window_sec          = 20 * 60U; /* 20 minutes */
static float        const window_overlap_threshold = 0.75f * count_packets;

/**
 * A data structure for an internal endpoint, that is used to track
 * the latest connection the endpoint have with the "outside world".
 */
typedef struct TrackedConnection {
  unsigned int ip_destination;
  float        timestamp;
  unsigned int count_this_window;
  unsigned int count_prev_window;
} TrackedConnection_type;

/**
 * A data structure for an endpoint in the internal network.
 * The endpoints are stored in a sorted doubly linked list.
 */
typedef struct hosts_node {
  unsigned int            ip;
  TrackedConnection_type  connection;
  struct hosts_node      *next;
  struct hosts_node      *prev;
} hosts_node_type;

/* The head and tail of the list of endpoints in the network. */
hosts_node_type *hosts_head = NULL;
hosts_node_type *hosts_tail = NULL;

hosts_node_type* create_empty_node(unsigned int value) {
  hosts_node_type *new_node = (hosts_node_type *)kmalloc(sizeof(hosts_node_type), GFP_KERNEL);
  new_node->ip                           = value;
  new_node->connection.ip_destination    = 0U;
  new_node->connection.timestamp         = 0.0f;
  new_node->connection.count_this_window = 0U;
  new_node->connection.count_prev_window = 0U;
  new_node->prev                         = NULL;
  new_node->next                         = NULL;
  return new_node;
}

unsigned int insert_node(hosts_node_type *const new_node) {
  unsigned int ret = RET_SUCCESS;
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
    hosts_node_type* before_node = hosts_head;
    while ((before_node->next != NULL) && (before_node->next->ip <= new_node->ip)) {
      before_node = before_node->next;
      /**
       * Note, for optimization purposes, while going through the endpoints, we can
       * remove nodes that their connection timestamp is older than some constant.
       * Doing in once for every search should reduce the overhead.
       * Code for example:
       * ```C
       * if (0 == SOMETHING_WAS_REMOVED) {
       *   if (CURRENT_TIMESTAMP - before_node->prev.connection.timestamp < CONSTANT_VALUE) {
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

void remove_node(hosts_node_type *node_to_remove) {
  if (NULL != node_to_remove) {
    if (hosts_head == node_to_remove) {
      if (hosts_head->next != NULL) {
        hosts_head->next->prev = NULL;
      }
      hosts_head = hosts_head->next;
    } else if (hosts_tail == node_to_remove) {
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

void debug_print_all_hosts(void) {
  hosts_node_type* loop_node = hosts_head;
  printk(KERN_INFO "List of hosts: [");
  while (loop_node != NULL) {
    printk(KERN_CONT "%d, ", loop_node->ip);
    loop_node = loop_node->next;
  }
  printk(KERN_CONT "NULL]\n");
}

void report(unsigned int ip_source, unsigned int ip_destination, float timestamp) {
  (void)ip_source;
  (void)ip_destination;
  (void)timestamp;
}

static int __init hello_init(void) {
  hosts_node_type *new_node;
  printk(KERN_INFO "Hello, world\n");
  /* Initial */
  printk(KERN_INFO "Initial list\n");
  debug_print_all_hosts();
  /* Insert 4 numbers */
  printk(KERN_INFO "Insert `8`, `1000`, `30` and then `2`\n");
  if (RET_FAILURE == insert_node(create_empty_node(8))) {
    printk(KERN_INFO "[Error] Failed to insert the value `8`\n");
  }
  if (RET_FAILURE == insert_node(create_empty_node(1000))) {
    printk(KERN_INFO "[Error] Failed to insert the value `1000`\n");
  }
  if (RET_FAILURE == insert_node(create_empty_node(30))) {
    printk(KERN_INFO "[Error] Failed to insert the value `30`\n");
  }
  if (RET_FAILURE == insert_node(create_empty_node(2))) {
    printk(KERN_INFO "[Error] Failed to insert the value `2`\n");
  }
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
  new_node = create_empty_node(15);
  if (RET_FAILURE == insert_node(new_node)) {
    printk(KERN_INFO "[Error] Failed to insert the value `15`\n");
  }
  debug_print_all_hosts();
  printk(KERN_INFO "Remove `15`\n");
  remove_node(new_node);
  debug_print_all_hosts();
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

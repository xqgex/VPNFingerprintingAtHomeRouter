#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h> /* MODULE_LICENSE() */

#include "parse_packet.h"

/**************************************************************************************************/
/**** Macros                                                                                   ****/
/**************************************************************************************************/

#define PRIVATE_ADDRESSES_LIST_SIZE 8U

/**************************************************************************************************/
/**** Typedefs                                                                                 ****/
/**************************************************************************************************/

typedef struct PrivateAddress {
  ip_type address;
  ip_type mask;
} PrivateAddress_type;

/**************************************************************************************************/
/**** Static variables                                                                         ****/
/**************************************************************************************************/

const PrivateAddress_type privateAddresses[PRIVATE_ADDRESSES_LIST_SIZE] = {
    {0x00000000, 0xFFFFFFFF}, /* 0.0.0.0 */
    {0x0A000000, 0xFF000000}, /* 10.0.0.0/8 */
    {0x7F000000, 0xFF000000}, /* 127.0.0.0/8 */
    {0xA9FE0000, 0xFFFF0000}, /* 169.254.0.0/16 */
    {0xAC100000, 0xFFF00000}, /* 172.16.0.0/12 */
    {0xC0A80000, 0xFFFF0000}, /* 192.168.0.0/16 */
    {0xE0000000, 0xF0000000}, /* 224.0.0.0/4 */
    {0xFFFFFFFF, 0xFFFFFFFF}  /* 255.255.255.255 */
  };

static u16 const filter_internal_communication = FILTER_INTERNAL_COMMUNICATION;
static u16 const internal_as_source            = INTERNAL_AS_SOURCE;

/**************************************************************************************************/
/**** Private functions prototype                                                              ****/
/**************************************************************************************************/

u16 is_private_ip(ip_type ip_address);

/**************************************************************************************************/
/**** Private functions                                                                        ****/
/**************************************************************************************************/

u16 is_private_ip(ip_type ip_address) {
  u16 ret = PARSE_FALSE;
  u16 index = 0U;
  for (; index < PRIVATE_ADDRESSES_LIST_SIZE; ++index) {
    if ((ip_address & privateAddresses[index].mask) == privateAddresses[index].address) {
      ret = PARSE_TRUE;
      break;
    }
  }
  return ret;
}

/**************************************************************************************************/
/**** Public functions                                                                         ****/
/**************************************************************************************************/

u16 check_connection(ip_type *const ip_source, ip_type *const ip_destination) {
  u16 ret = RET_SKIP;
  if ((PARSE_TRUE == internal_as_source) && (PARSE_FALSE == is_private_ip(*ip_source))) { /* Flip */
    ip_type temp_swap = *ip_source;
    *ip_source = *ip_destination;
    *ip_destination = temp_swap;
  }
  if
  (
       (PARSE_FALSE == filter_internal_communication)
    || (PARSE_FALSE == is_private_ip(*ip_source))
    || (PARSE_FALSE == is_private_ip(*ip_destination))
  ) {
    ret = RET_ANALYZE;
  }
  return ret;
}

MODULE_LICENSE("GPL");

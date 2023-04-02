#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h> /* MODULE_LICENSE() */

#include "parse_packet.h"

/**************************************************************************************************/
/**** Typedefs                                                                                 ****/
/**************************************************************************************************/

typedef struct {
  uint32_t address;
  uint32_t mask;
} PrivateAddress;

/**************************************************************************************************/
/**** Static variables                                                                         ****/
/**************************************************************************************************/

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

/**************************************************************************************************/
/**** Public functions                                                                         ****/
/**************************************************************************************************/

u16 is_tracked_connection(ip_type *const ip_source, ip_type *const ip_destination) {
  if(is_private_ip(ip_source)&&is_private_ip(ip_destination)) {
    /*Both ip are private*/
    return 0;
  } else if(is_private_ip(ip_source) && (is_private_ip(ip_destination)==0)) {
    /*src is private
      dst is public
      no flip is needed*/
    analyze(ip_source,ip_destination, timestamp)
    return 1;
  } else if(is_private_ip(ip_destination) && (is_private_ip(ip_source)==0)) {
    /*src is public 
      dst is private
      flip is needed*/
    analyze(ip_destination, ip_source, timestamp)
    return 1;
  }
}

MODULE_LICENSE("GPL");

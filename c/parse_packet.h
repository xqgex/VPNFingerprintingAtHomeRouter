#ifndef PARSE_PACKET_H
#define PARSE_PACKET_H

/**************************************************************************************************/
/**** Macros                                                                                   ****/
/**************************************************************************************************/

#define RET_ANALYZE 1U
#define RET_SKIP    0U

/**************************************************************************************************/
/**** Typedefs                                                                                 ****/
/**************************************************************************************************/

typedef u32      ip_type;

/**************************************************************************************************/
/**** Functions prototype                                                                      ****/
/**************************************************************************************************/

u16 is_tracked_connection(ip_type *const ip_source, ip_type *const ip_destination);

#endif /* PARSE_PACKET_H */

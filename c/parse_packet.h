#ifndef PARSE_PACKET_H
#define PARSE_PACKET_H

/**************************************************************************************************/
/**** Macros                                                                                   ****/
/**************************************************************************************************/

#define PARSE_FALSE 0U
#define PARSE_TRUE  1U

#define RET_ANALYZE PARSE_TRUE
#define RET_SKIP    PARSE_FALSE

#define FILTER_INTERNAL_COMMUNICATION PARSE_TRUE
#define INTERNAL_AS_SOURCE            PARSE_TRUE

/**************************************************************************************************/
/**** Typedefs                                                                                 ****/
/**************************************************************************************************/

typedef u32 ip_type;

/**************************************************************************************************/
/**** Functions prototype                                                                      ****/
/**************************************************************************************************/

u16 check_connection(ip_type *const ip_source, ip_type *const ip_destination);

#endif /* PARSE_PACKET_H */

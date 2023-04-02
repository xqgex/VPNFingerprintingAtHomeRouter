#ifndef ANALYZE_PACKET_H
#define ANALYZE_PACKET_H

/**************************************************************************************************/
/**** Macros                                                                                   ****/
/**************************************************************************************************/

#define METRIC_COUNT_PACKETS            2U /* TODO Restore to 10000U */
#define METRIC_TIME_WINDOW_SEC          20U * 60U /* 20 minutes */
#define METRIC_WINDOW_OVERLAP_THRESHOLD (timestamp_type)(0.75f * (METRIC_COUNT_PACKETS))

/**************************************************************************************************/
/**** Typedefs                                                                                 ****/
/**************************************************************************************************/

typedef u32      ip_type;
typedef time64_t timestamp_type;

/**************************************************************************************************/
/**** Functions prototype                                                                      ****/
/**************************************************************************************************/

void analyze(ip_type ip_source, ip_type ip_destination, timestamp_type timestamp);
void debug_print_all_hosts(void);

#endif /* ANALYZE_PACKET_H */

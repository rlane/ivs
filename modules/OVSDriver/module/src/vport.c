/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include "ovs_driver_int.h"
#include "ovsdriver_log.h"
#include "indigo/forwarding.h"
#include "indigo/port_manager.h"
#include "indigo/of_state_manager.h"
#include "SocketManager/socketmanager.h"
#include <errno.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <linux/ethtool.h>

#ifndef _LINUX_IF_H
/* Some versions of libnetlink include linux/if.h, which conflicts with net/if.h. */
#include <net/if.h>
#endif

struct ind_ovs_port *ind_ovs_ports[IND_OVS_MAX_PORTS];  /**< Table of all ports */

static struct nl_sock *route_cache_sock;
static struct nl_sock *route_cache_refill_sock;
static struct nl_cache_mngr *route_cache_mngr;
static struct nl_cache *link_cache;
static struct nl_cache *qdisc_cache;
static struct nl_cb *netlink_callbacks;

static indigo_error_t port_status_notify(uint32_t port_no, unsigned reason);
static void port_desc_set(of_port_desc_t *of_port_desc, struct ind_ovs_port *port);
static void alloc_port_counters(struct ind_ovs_port_counters *pcounters);
static void free_port_counters(struct ind_ovs_port_counters *pcounters);
static uint64_t get_packet_stats(struct stats_handle *handle);

aim_ratelimiter_t link_cache_refill_limiter;
aim_ratelimiter_t qdisc_cache_refill_limiter;

static struct ind_ovs_port_counters dummy_stats;

DEBUG_COUNTER(add_redundant, "ovsdriver.vport.add_redundant", "Received port add notification for existing port");
DEBUG_COUNTER(add, "ovsdriver.vport.add", "Received port add notification for a new port");
DEBUG_COUNTER(add_notify_failed, "ovsdriver.vport.add_notify_failed", "Failed to notify controller of new port");
DEBUG_COUNTER(add_failed, "ovsdriver.vport.add_failed", "Failed to add port");
DEBUG_COUNTER(add_out_of_range, "ovsdriver.vport.add_out_of_range", "Failed to add port due to too-high port number");
DEBUG_COUNTER(delete_redundant, "ovsdriver.vport.delete_redundant", "Received port delete notification for nonexistent port");
DEBUG_COUNTER(delete, "ovsdriver.vport.delete", "Received port delete notification");
DEBUG_COUNTER(delete_notify_failed, "ovsdriver.vport.delete_notify_failed", "Failed to notify controller of deleted port");
DEBUG_COUNTER(modify_nonexistent, "ovsdriver.vport.modify_nonexistent", "Received port modify notification for nonexistent port");
DEBUG_COUNTER(modify, "ovsdriver.vport.modify", "Received port modify notification");
DEBUG_COUNTER(modify_notify_failed, "ovsdriver.vport.modify_notify_failed", "Failed to notify controller of modified port");
DEBUG_COUNTER(link_change, "ovsdriver.vport.link_change", "Received link change notification");

/*
 * Truncate the object to its initial length.
 *
 * This allows the caller to reuse a single allocated object even if
 * it has been appended to.
 */
static void
truncate_of_object(of_object_t *obj)
{
    of_object_init_map[obj->object_id](obj, obj->version, -1, 0);
    obj->wbuf->current_bytes = obj->length;
}

static void
ind_ovs_update_link_stats()
{
    if (aim_ratelimiter_limit(&link_cache_refill_limiter, monotonic_us()) == 0) {
        /* Refresh statistics */
        nl_cache_refill(route_cache_refill_sock, link_cache);
    }
}

static void
ind_ovs_update_qdisc_stats()
{
    if (aim_ratelimiter_limit(&qdisc_cache_refill_limiter, monotonic_us()) == 0) {
        /* Refresh statistics */
        nl_cache_refill(route_cache_refill_sock, qdisc_cache);
    }
}

struct ind_ovs_port *
ind_ovs_port_lookup(of_port_no_t port_no)
{
    if (port_no == OF_PORT_DEST_LOCAL) {
        return ind_ovs_ports[OVSP_LOCAL];
    }

    if (port_no >= IND_OVS_MAX_PORTS) {
        return NULL;
    }

    return ind_ovs_ports[port_no];
}

struct ind_ovs_port *
ind_ovs_port_lookup_by_name(const char *ifname)
{
    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if (port && !strcmp(port->ifname, ifname)) {
            return port;
        }
    }
    return NULL;
}

static struct ind_ovs_port *
ind_ovs_port_lookup_by_ifindex(int ifindex)
{
    /* Search link cache by interface index */
    struct rtnl_link *link = rtnl_link_get(link_cache, ifindex);
    if (link == NULL) {
        AIM_LOG_ERROR("failed to retrieve link with if_index: %d", ifindex);
        return NULL;
    }

    const char *ifname = rtnl_link_get_name(link);
    rtnl_link_put(link);

    return ind_ovs_port_lookup_by_name(ifname);
}

/* TODO populate more fields of the port desc */
indigo_error_t indigo_port_features_get(
    of_features_reply_t *features)
{
    indigo_error_t      result             = INDIGO_ERROR_NONE;
    of_list_port_desc_t *of_list_port_desc = 0;
    of_port_desc_t      *of_port_desc      = 0;

    if (features->version >= OF_VERSION_1_3) {
        return INDIGO_ERROR_NONE;
    }

    if ((of_port_desc = of_port_desc_new(features->version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    if ((of_list_port_desc = of_list_port_desc_new(features->version)) == 0) {
        LOG_ERROR("of_list_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    int i;
    for (i = 0; i < IND_OVS_MAX_PORTS; i++) {
        if (ind_ovs_ports[i]) {
            truncate_of_object(of_port_desc);
            port_desc_set(of_port_desc, ind_ovs_ports[i]);
            /* TODO error handling */
            of_list_port_desc_append(of_list_port_desc, of_port_desc);
        }
    }

    if (LOXI_FAILURE(of_features_reply_ports_set(features,
                                                 of_list_port_desc
                                                 )
                     )
        ) {
        LOG_ERROR("of_features_reply_ports_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

 done:
    if (of_list_port_desc)  of_list_port_desc_delete(of_list_port_desc);
    if (of_port_desc)       of_port_desc_delete(of_port_desc);

    return (result);
}

/*
 * This function just asks the datapath to add the port. If that succeeds we'll
 * get a OVS_VPORT_CMD_NEW multicast message. At that point ind_ovs_port_added
 * will create our own representation of the port. This is to support using
 * ovs-dpctl to add and remove ports.
 */
indigo_error_t indigo_port_interface_add(
    indigo_port_name_t port_name,
    of_port_no_t of_port,
    indigo_port_config_t *config)
{
    assert(of_port < IND_OVS_MAX_PORTS || of_port == OF_PORT_DEST_NONE);
    assert(strlen(port_name) < 256);

    if (ind_ovs_port_lookup_by_name(port_name)) {
        return INDIGO_ERROR_NONE;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_NEW);
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_NETDEV);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, port_name);
    if (of_port != OF_PORT_DEST_NONE) {
        nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, of_port);
    }
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    return ind_ovs_transact(msg);
}

/* Like indigo_port_interface_add, but creates an internal port */
indigo_error_t
ind_ovs_port_add_internal(const char *port_name)
{
    if (strlen(port_name) >= 256) {
        return INDIGO_ERROR_PARAM;
    }

    if (ind_ovs_port_lookup_by_name(port_name)) {
        return INDIGO_ERROR_NONE;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_NEW);
    nla_put_u32(msg, OVS_VPORT_ATTR_TYPE, OVS_VPORT_TYPE_INTERNAL);
    nla_put_string(msg, OVS_VPORT_ATTR_NAME, port_name);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID, 0);
    return ind_ovs_transact(msg);
}

indigo_error_t
indigo_port_interface_list(indigo_port_info_t** list)
{
    int i;
    indigo_port_info_t* head = NULL;

    if(list == NULL) {
        return INDIGO_ERROR_PARAM;
    }

    for (i = IND_OVS_MAX_PORTS-1; i >= 0; i--) {
        struct ind_ovs_port *port = ind_ovs_ports[i];
        if(port != NULL) {
            indigo_port_info_t* pi = aim_zmalloc(sizeof(*pi));
            strncpy(pi->port_name, port->ifname, sizeof(port->ifname));
            pi->of_port = i;
            pi->next = head;
            head = pi;
        }
    }
    *list = head;
    return 0;
}


void
indigo_port_interface_list_destroy(indigo_port_info_t* list)
{
    while(list) {
        indigo_port_info_t* next = list->next;
        aim_free(list);
        list = next;
    }
}


void
ind_ovs_port_added(uint32_t port_no, const char *ifname,
                   enum ovs_vport_type type)
{
    indigo_error_t err;

    if (port_no >= IND_OVS_MAX_PORTS) {
        AIM_LOG_WARN("Attempted to add port number %u (%s) >= %u", port_no, ifname, IND_OVS_MAX_PORTS);
        debug_counter_inc(&add_out_of_range);

        /* Remove port from kernel datapath */
        struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_DEL);
        nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port_no);
        ind_ovs_transact(msg);

        return;
    }

    if (ind_ovs_ports[port_no]) {
        debug_counter_inc(&add_redundant);
        return;
    }

    debug_counter_inc(&add);

    of_mac_addr_t mac_addr = of_mac_addr_all_zeros;
    struct rtnl_link *link = rtnl_link_get_by_name(link_cache, ifname);
    if (link) {
        struct nl_addr *addr = rtnl_link_get_addr(link);
        void *data = nl_addr_get_binary_addr(addr);
        AIM_ASSERT(nl_addr_get_len(addr) == sizeof(mac_addr));
        memcpy(&mac_addr, data, sizeof(mac_addr));
        rtnl_link_put(link);
    }

    struct ind_ovs_port *port = aim_zmalloc(sizeof(*port));

    if (port_no == OVSP_LOCAL) {
        ifname = "local";
        port->port_no = OF_PORT_DEST_LOCAL;
    } else {
        port->port_no = port_no;
    }

    strncpy(port->ifname, ifname, sizeof(port->ifname));
    port->dp_port_no = port_no;
    port->type = type;
    port->mac_addr = mac_addr;
    aim_ratelimiter_init(&port->upcall_log_limiter, 1000*1000, 5, NULL);
    aim_ratelimiter_init(&port->pktin_limiter, PORT_PKTIN_INTERVAL, PORT_PKTIN_BURST_SIZE, NULL);
    alloc_port_counters(&port->pcounters);

    port->notify_socket = ind_ovs_create_nlsock();
    if (port->notify_socket == NULL) {
        goto cleanup_port;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_SET);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port_no);
    nla_put_u32(msg, OVS_VPORT_ATTR_UPCALL_PID,
                nl_socket_get_local_port(port->notify_socket));
    err = ind_ovs_transact(msg);
    if (err < 0) {
        LOG_ERROR("datapath failed to configure port %s", ifname);
        goto cleanup_port;
    }

    if (!ind_ovs_get_interface_flags(ifname, &port->ifflags)) {
        /* Bring interface up if not already */
        if (!(port->ifflags & IFF_UP)) {
            port->ifflags |= IFF_UP;
            (void) ind_ovs_set_interface_flags(ifname, port->ifflags);
        }
    } else {
        /* Not a netdev, fake the interface flags */
        port->ifflags = IFF_UP;
    }

    if (type == OVS_VPORT_TYPE_NETDEV) {
        /* Disable LRO */
        if (ind_ovs_set_ethtool_flags(port->ifname, 0, ETH_FLAG_LRO) < 0) {
            AIM_LOG_WARN("Failed to disable LRO on interface %s", port->ifname);
        }
    }

    port->is_uplink = ind_ovs_uplink_check_by_name(port->ifname);

    ind_ovs_ports[port_no] = port;

    indigo_core_port_register(port->port_no, &port->register_handle);

    if ((err = port_status_notify(port_no, OF_PORT_CHANGE_REASON_ADD)) < 0) {
        LOG_WARN("failed to notify controller of port addition");
        debug_counter_inc(&add_notify_failed);
    }

    ind_ovs_upcall_register(port);
    LOG_INFO("Added %s %s", port->is_uplink ? "uplink" : "port", port->ifname);
    ind_ovs_barrier_defer_revalidation_internal();

    if (port->is_uplink) {
        ind_ovs_uplink_reselect();
    }
    return;

cleanup_port:
    debug_counter_inc(&add_failed);
    assert(ind_ovs_ports[port_no] == NULL);
    if (port->notify_socket) {
        nl_socket_free(port->notify_socket);
    }
    free_port_counters(&port->pcounters);
    aim_free(port);
}

/*
 * ind_ovs_port_deleted will free the port struct.
 */
indigo_error_t indigo_port_interface_remove(
    indigo_port_name_t port_name)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup_by_name(port_name);
    if (port == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_DEL);
    nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port->dp_port_no);
    return ind_ovs_transact(msg);
}

void
ind_ovs_port_deleted(uint32_t port_no)
{
    assert(port_no < IND_OVS_MAX_PORTS);
    struct ind_ovs_port *port = ind_ovs_ports[port_no];
    if (port == NULL) {
        debug_counter_inc(&delete_redundant);
        return;
    }

    bool was_uplink = port->is_uplink;

    debug_counter_inc(&delete);

    indigo_core_port_unregister(port->register_handle);

    ind_ovs_upcall_unregister(port);

    if (port_status_notify(port_no, OF_PORT_CHANGE_REASON_DELETE) < 0) {
        LOG_ERROR("failed to notify controller of port deletion");
        debug_counter_inc(&delete_notify_failed);
    }

    LOG_INFO("Deleted %s %s", port->is_uplink ? "uplink" : "port", port->ifname);

    nl_socket_free(port->notify_socket);
    free_port_counters(&port->pcounters);
    aim_free(port);
    ind_ovs_ports[port_no] = NULL;

    ind_ovs_barrier_defer_revalidation_internal();

    if (was_uplink) {
        ind_ovs_uplink_reselect();
    }
}

indigo_error_t
indigo_port_modify(of_port_mod_t *port_mod)
{
    of_port_no_t port_no;
    of_port_mod_port_no_get(port_mod, &port_no);
    uint32_t config;
    of_port_mod_config_get(port_mod, &config);
    uint32_t mask;
    of_port_mod_mask_get(port_mod, &mask);

    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        debug_counter_inc(&modify_nonexistent);
        return INDIGO_ERROR_NOT_FOUND;
    }

    debug_counter_inc(&modify);

    if (OF_PORT_CONFIG_FLAG_NO_PACKET_IN_TEST(mask, port_mod->version)) {
        port->no_packet_in = OF_PORT_CONFIG_FLAG_NO_PACKET_IN_TEST(config, port_mod->version);
    }

    if (OF_PORT_CONFIG_FLAG_NO_FLOOD_TEST(mask, port_mod->version)) {
        port->no_flood = OF_PORT_CONFIG_FLAG_NO_FLOOD_TEST(config, port_mod->version);
    }

    if (OF_PORT_CONFIG_FLAG_PORT_DOWN_TEST(mask, port_mod->version)) {
        port->admin_down = OF_PORT_CONFIG_FLAG_PORT_DOWN_TEST(config, port_mod->version);
        if (port->admin_down) {
            port->ifflags &= ~IFF_UP;
        } else {
            port->ifflags |= IFF_UP;
        }
        (void) ind_ovs_set_interface_flags(port->ifname, port->ifflags);
    }

    /* TODO change other configuration? */

    ind_ovs_barrier_defer_revalidation_internal();

    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_port_stats_get_one(
    of_port_no_t port_no,
    of_port_stats_entry_t *port_stats)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    of_port_stats_entry_port_no_set(port_stats, port_no);

    ind_ovs_update_link_stats();

    struct rtnl_link *link;
    if ((port->type == OVS_VPORT_TYPE_NETDEV
        || port->type == OVS_VPORT_TYPE_INTERNAL)
        && (link = rtnl_link_get_by_name(link_cache, port->ifname))) {
        /* Get interface stats from NETLINK_ROUTE */
        of_port_stats_entry_rx_packets_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS));
        of_port_stats_entry_tx_packets_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS));
        of_port_stats_entry_rx_bytes_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES));
        of_port_stats_entry_tx_bytes_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES));
        of_port_stats_entry_rx_dropped_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED));
        of_port_stats_entry_tx_dropped_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED));
        of_port_stats_entry_rx_errors_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS));
        of_port_stats_entry_tx_errors_set(port_stats,
            rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS));

        if (port_stats->version < OF_VERSION_1_4) {
            of_port_stats_entry_rx_frame_err_set(port_stats,
                rtnl_link_get_stat(link, RTNL_LINK_RX_FRAME_ERR));
            of_port_stats_entry_rx_over_err_set(port_stats,
                rtnl_link_get_stat(link, RTNL_LINK_RX_OVER_ERR));
            of_port_stats_entry_rx_crc_err_set(port_stats,
                rtnl_link_get_stat(link, RTNL_LINK_RX_CRC_ERR));
            of_port_stats_entry_collisions_set(port_stats,
                rtnl_link_get_stat(link, RTNL_LINK_COLLISIONS));
        } else {
            of_object_t props;
            of_object_t prop;
            of_port_stats_entry_properties_bind(port_stats, &props);
            of_port_stats_prop_ethernet_init(&prop, props.version, -1, 1);
            if (of_list_port_stats_prop_append_bind(&props, &prop) < 0) {
                AIM_DIE("Unexpected failure appending to port stats");
            }
            of_port_stats_prop_ethernet_rx_frame_err_set(&prop,
                rtnl_link_get_stat(link, RTNL_LINK_RX_FRAME_ERR));
            of_port_stats_prop_ethernet_rx_over_err_set(&prop,
                rtnl_link_get_stat(link, RTNL_LINK_RX_OVER_ERR));
            of_port_stats_prop_ethernet_rx_crc_err_set(&prop,
                rtnl_link_get_stat(link, RTNL_LINK_RX_CRC_ERR));
            of_port_stats_prop_ethernet_collisions_set(&prop,
                rtnl_link_get_stat(link, RTNL_LINK_COLLISIONS));
        }

        rtnl_link_put(link);
    } else {
        /* Use more limited stats from the datapath */
        struct nl_msg *msg = ind_ovs_create_nlmsg(ovs_vport_family, OVS_VPORT_CMD_GET);
        nla_put_u32(msg, OVS_VPORT_ATTR_PORT_NO, port->dp_port_no);

        struct nlmsghdr *reply;
        if (ind_ovs_transact_reply(msg, &reply) < 0) {
            AIM_LOG_ERROR("Failed to retrieve datapath port stats for %s", port->ifname);
            return INDIGO_ERROR_UNKNOWN;
        }

        struct nlattr *attrs[OVS_VPORT_ATTR_MAX+1];
        if (genlmsg_parse(reply, sizeof(struct ovs_header),
                          attrs, OVS_VPORT_ATTR_MAX,
                          NULL) < 0) {
            abort();
        }

        assert(attrs[OVS_VPORT_ATTR_STATS]);
        struct ovs_vport_stats *stats = nla_data(attrs[OVS_VPORT_ATTR_STATS]);

        of_port_stats_entry_rx_packets_set(port_stats, stats->rx_packets);
        of_port_stats_entry_tx_packets_set(port_stats, stats->tx_packets);
        of_port_stats_entry_rx_bytes_set(port_stats, stats->rx_bytes);
        of_port_stats_entry_tx_bytes_set(port_stats, stats->tx_bytes);
        of_port_stats_entry_rx_dropped_set(port_stats, stats->rx_dropped);
        of_port_stats_entry_tx_dropped_set(port_stats, stats->tx_dropped);
        of_port_stats_entry_rx_errors_set(port_stats, stats->rx_errors);
        of_port_stats_entry_tx_errors_set(port_stats, stats->tx_errors);
        if (port_stats->version < OF_VERSION_1_4) {
            of_port_stats_entry_rx_frame_err_set(port_stats, 0);
            of_port_stats_entry_rx_over_err_set(port_stats, 0);
            of_port_stats_entry_rx_crc_err_set(port_stats, 0);
            of_port_stats_entry_collisions_set(port_stats, 0);
        }
    }

    return INDIGO_ERROR_NONE;
}

void
indigo_port_extended_stats_get(
    of_port_no_t port_no,
    indigo_fi_port_stats_t *port_stats)
{
    AIM_ASSERT(port_stats != NULL);

    if (port_no == OF_PORT_DEST_LOCAL) {
        return;
    }

    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return;
    }

    ind_ovs_update_link_stats();

    struct rtnl_link *link;
    if ((link = rtnl_link_get_by_name(link_cache, port->ifname))) {
        port_stats->rx_bytes = rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES);
        port_stats->rx_dropped = rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED);
        port_stats->rx_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS);
        port_stats->tx_bytes = rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES);
        port_stats->tx_dropped = rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED);
        port_stats->tx_errors = rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS);
        port_stats->rx_alignment_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_FRAME_ERR);
        port_stats->rx_crc_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_CRC_ERR);
        port_stats->tx_collisions = rtnl_link_get_stat(link, RTNL_LINK_COLLISIONS);
        port_stats->rx_packets = rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS);
        port_stats->tx_packets = rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS);
        port_stats->rx_length_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_LEN_ERR);
        port_stats->rx_overflow_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_OVER_ERR);
        port_stats->tx_carrier_errors = rtnl_link_get_stat(link, RTNL_LINK_TX_CARRIER_ERR);

        rtnl_link_put(link);

        port_stats->rx_packets_unicast = get_packet_stats(&port->pcounters.rx_unicast_stats_handle);
        port_stats->rx_packets_broadcast = get_packet_stats(&port->pcounters.rx_broadcast_stats_handle);
        port_stats->rx_packets_multicast = get_packet_stats(&port->pcounters.rx_multicast_stats_handle);
        port_stats->tx_packets_unicast = get_packet_stats(&port->pcounters.tx_unicast_stats_handle);
        port_stats->tx_packets_broadcast = get_packet_stats(&port->pcounters.tx_broadcast_stats_handle);
        port_stats->tx_packets_multicast = get_packet_stats(&port->pcounters.tx_multicast_stats_handle);
    }
}

indigo_error_t
indigo_port_desc_stats_get_one(
    of_port_no_t port_no,
    of_port_desc_t *of_port_desc)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    port_desc_set(of_port_desc, port);

    return INDIGO_ERROR_NONE;
}

/* Currently returns an empty reply */
indigo_error_t
indigo_port_queue_config_get(
    of_queue_get_config_request_t *request,
    of_queue_get_config_reply_t **reply_ptr)
{
    of_queue_get_config_reply_t *reply;

    reply = of_queue_get_config_reply_new(request->version);
    if (reply == NULL) {
        LOG_ERROR("Could not allocate queue config reply");
        return INDIGO_ERROR_RESOURCE;
    }

    *reply_ptr = reply;
    return INDIGO_ERROR_NONE;
}

/*
 * queue 0 maps to class 1, queue 1 maps to class 2 and so on.
 * Hence, subtract one from the minor version of parent class
 * and return as the queue_id
 *
 * For Root qdisc return TC_H_ROOT
 */
static uint32_t
qdisc_get_queue_id(struct nl_object *qdisc)
{
    uint32_t parent = rtnl_tc_get_parent(TC_CAST(qdisc));
    if (parent == TC_H_ROOT) {
        return TC_H_ROOT;
    }

    uint32_t minor = TC_H_MIN(parent);
    if (minor > 0) {
        --minor;
    }

    return minor;
}

static void
queue_stats_fill(of_queue_stats_entry_t *list, struct nl_object *qdisc,
                 of_port_no_t port_no, uint32_t queue_id)
{
    of_queue_stats_entry_t entry[1];
    of_queue_stats_entry_init(entry, list->version, -1, 1);

    /* FIXME: This entry didn't fit, send out the current message and
     * allocate a new one. */
    if (of_list_queue_stats_entry_append_bind(list, entry) < 0) {
        return;
    }

    of_queue_stats_entry_port_no_set(entry, port_no);
    of_queue_stats_entry_queue_id_set(entry, queue_id);

    of_queue_stats_entry_tx_packets_set(entry, rtnl_tc_get_stat(TC_CAST(qdisc), RTNL_TC_PACKETS));
    of_queue_stats_entry_tx_bytes_set(entry, rtnl_tc_get_stat(TC_CAST(qdisc), RTNL_TC_BYTES));
    of_queue_stats_entry_tx_errors_set(entry, rtnl_tc_get_stat(TC_CAST(qdisc), RTNL_TC_DROPS));
}

indigo_error_t
indigo_port_queue_stats_get(
    of_queue_stats_request_t *queue_stats_request,
    of_queue_stats_reply_t **queue_stats_reply_ptr)
{
    ind_ovs_update_qdisc_stats();

    of_queue_stats_reply_t *queue_stats_reply = of_queue_stats_reply_new(queue_stats_request->version);
    if (queue_stats_reply == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    uint32_t xid;
    of_queue_stats_request_xid_get(queue_stats_request, &xid);
    of_queue_stats_reply_xid_set(queue_stats_reply, xid);

    of_port_no_t req_of_port_num;
    of_queue_stats_request_port_no_get(queue_stats_request, &req_of_port_num);

    /* For OF 1.0 OFPP_ALL refers to all ports, in later versions it is OFPP_ANY */
    bool dump_all_ports;
    if (queue_stats_request->version == OF_VERSION_1_0) {
        dump_all_ports = req_of_port_num == OF_PORT_DEST_ALL_BY_VERSION(queue_stats_request->version);
    } else {
        dump_all_ports = req_of_port_num == OF_PORT_DEST_NONE_BY_VERSION(queue_stats_request->version);
    }

    /* There are no queue's for local port */
    if (req_of_port_num == OVSP_LOCAL) {
        *queue_stats_reply_ptr = queue_stats_reply;
        return INDIGO_ERROR_NONE;
    }

    uint32_t req_queue_id;
    of_queue_stats_request_queue_id_get(queue_stats_request, &req_queue_id);
    bool dump_all_queues = req_queue_id == OF_QUEUE_ALL_BY_VERSION(queue_id);

    of_queue_stats_entry_t list;
    of_queue_stats_reply_entries_bind(queue_stats_reply, &list);

    struct nl_object *qdisc;
    for (qdisc = nl_cache_get_first(qdisc_cache); qdisc; qdisc = nl_cache_get_next(qdisc)) {
        uint32_t queue_id = qdisc_get_queue_id(qdisc);
        /* Skip the root qdisc */
        if (queue_id == TC_H_ROOT) continue;


        struct ind_ovs_port *port = ind_ovs_port_lookup_by_ifindex(rtnl_tc_get_ifindex(TC_CAST(qdisc)));
        /* It's possible that there are qdiscs on interfaces not attached to IVS */
        if (port == NULL) continue;

        of_port_no_t port_no = port->dp_port_no;
        bool dump_port = dump_all_ports || (req_of_port_num == port_no);
        bool dump_queue = dump_all_queues || (req_queue_id == queue_id);
        if (dump_port && dump_queue) {
            queue_stats_fill(&list, qdisc, port_no, queue_id);
        }
    }

    *queue_stats_reply_ptr = queue_stats_reply;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
port_status_notify(uint32_t port_no, unsigned reason)
{
    indigo_error_t   result = INDIGO_ERROR_NONE;
    of_port_desc_t   *of_port_desc   = 0;
    of_port_status_t *of_port_status = 0;
    of_version_t ctrlr_of_version;

    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    AIM_TRUE_OR_DIE(port != NULL);

    if (indigo_cxn_get_async_version(&ctrlr_of_version) != INDIGO_ERROR_NONE) {
        LOG_TRACE("No active controller connection");
        return INDIGO_ERROR_NONE;
    }

    if ((of_port_desc = of_port_desc_new(ctrlr_of_version)) == 0) {
        LOG_ERROR("of_port_desc_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    port_desc_set(of_port_desc, port);

    if ((of_port_status = of_port_status_new(ctrlr_of_version)) == 0) {
        LOG_ERROR("of_port_status_new() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }

    of_port_status_reason_set(of_port_status, reason);
    if (LOXI_FAILURE(of_port_status_desc_set(of_port_status, of_port_desc))) {
        LOG_ERROR("of_port_status_desc_set() failed");
        result = INDIGO_ERROR_UNKNOWN;
        goto done;
    }
    of_port_desc_delete(of_port_desc);

    indigo_core_port_status_update(of_port_status);

    of_port_desc   = 0;     /* No longer owned */
    of_port_status = 0;     /* No longer owned */

 done:
    if (of_port_desc)    of_port_desc_delete(of_port_desc);
    if (of_port_status)  of_port_status_delete(of_port_status);

    return (result);
}

static void
port_desc_set(of_port_desc_t *of_port_desc, struct ind_ovs_port *port)
{
    of_port_desc_port_no_set(of_port_desc, port->port_no);

    of_port_desc_hw_addr_set(of_port_desc, port->mac_addr);
    of_port_desc_name_set(of_port_desc, port->ifname);

    uint32_t config = 0;
    if (port->no_packet_in) {
        OF_PORT_CONFIG_FLAG_NO_PACKET_IN_SET(config, of_port_desc->version);
    }
    if (port->no_flood) {
        OF_PORT_CONFIG_FLAG_NO_FLOOD_SET(config, of_port_desc->version);
    }
    if (port->admin_down) {
        OF_PORT_CONFIG_FLAG_PORT_DOWN_SET(config, of_port_desc->version);
    }
    of_port_desc_config_set(of_port_desc, config);

    uint32_t state = 0;
    if (!(port->ifflags & IFF_RUNNING)) {
        state |= OF_PORT_STATE_FLAG_LINK_DOWN;
    }
    of_port_desc_state_set(of_port_desc, state);

    uint32_t curr, advertised, supported, peer;

    if (port->type == OVS_VPORT_TYPE_NETDEV) {
        ind_ovs_get_interface_features(port->ifname, &curr, &advertised,
            &supported, &peer, of_port_desc->version);
    } else {
        /* Internal ports do not support ethtool */
        curr = OF_PORT_FEATURE_FLAG_10GB_FD |
               OF_PORT_FEATURE_FLAG_COPPER_BY_VERSION(of_port_desc->version);
        advertised = 0;
        supported = 0;
        peer = 0;
    }

    if (of_port_desc->version < OF_VERSION_1_4) {
        of_port_desc_curr_set(of_port_desc, curr);
        of_port_desc_advertised_set(of_port_desc, advertised);
        of_port_desc_supported_set(of_port_desc, supported);
        of_port_desc_peer_set(of_port_desc, peer);
    } else {
        of_object_t props;
        of_object_t prop;
        of_port_desc_properties_bind(of_port_desc, &props);
        of_port_desc_prop_ethernet_init(&prop, props.version, -1, 1);
        if (of_list_port_desc_prop_append_bind(&props, &prop) < 0) {
            AIM_DIE("unexpected error appending to port_desc");
        }
        of_port_desc_prop_ethernet_curr_set(&prop, curr);
        of_port_desc_prop_ethernet_advertised_set(&prop, advertised);
        of_port_desc_prop_ethernet_supported_set(&prop, supported);
        of_port_desc_prop_ethernet_peer_set(&prop, peer);
        /* TODO curr_speed, max_speed */

        if (port->is_uplink) {
            of_port_desc_prop_bsn_uplink_init(&prop, props.version, -1, 1);
            if (of_list_port_desc_prop_append_bind(&props, &prop) < 0) {
                AIM_DIE("unexpected error appending to port_desc");
            }
        }
    }
}

/*
 * Called by nl_cache_mngr_data_ready if a link object changed.
 *
 * Sends a port status message to the controller.
 */
static void
link_change_cb(struct nl_cache *cache,
               struct nl_object *obj,
               int action,
               void *arg)
{
    struct rtnl_link *link = (struct rtnl_link *) obj;
    const char *ifname = rtnl_link_get_name(link);
    int ifflags = rtnl_link_get_flags(link);

    /* Automatically add uplinks to datapath */
    if (action == 1 /* NL_ACT_NEW */ &&
            ind_ovs_uplink_check_by_name(ifname) &&
            !ind_ovs_port_lookup_by_name(ifname)) {
        AIM_LOG_VERBOSE("Adding uplink %s", ifname);
        if (indigo_port_interface_add((char *)ifname, OF_PORT_DEST_NONE, NULL)) {
            AIM_LOG_ERROR("Failed to add uplink %s", ifname);
        }
        return;
    }

    /* Ignore interfaces not connected to our datapath. */
    struct ind_ovs_port *port = ind_ovs_port_lookup_by_name(ifname);
    if (port == NULL) {
        return;
    }

    debug_counter_inc(&link_change);

    /* Log at INFO only if the interface transitioned between up/down */
    if ((ifflags & IFF_RUNNING) && !(port->ifflags & IFF_RUNNING)) {
        LOG_INFO("Interface %s state changed to up", ifname);
    } else if (!(ifflags & IFF_RUNNING) && (port->ifflags & IFF_RUNNING)) {
        LOG_INFO("Interface %s state changed to down", ifname);
    }

    LOG_VERBOSE("Sending port status change notification for interface %s", ifname);

    port->ifflags = ifflags;
    port->admin_down = !(ifflags & IFF_UP);
    port_status_notify(port->dp_port_no, OF_PORT_CHANGE_REASON_MODIFY);

    ind_ovs_barrier_defer_revalidation_internal();

    if (port->is_uplink) {
        ind_ovs_uplink_reselect();
    }
}

static void
route_cache_mngr_socket_cb(void)
{
    nl_cache_mngr_data_ready(route_cache_mngr);
}

void
ind_ovs_port_init(void)
{
    int nlerr;

    route_cache_sock = nl_socket_alloc();
    if (route_cache_sock == NULL) {
        LOG_ERROR("nl_socket_alloc failed");
        abort();
    }

    route_cache_refill_sock = nl_socket_alloc();
    if (route_cache_refill_sock == NULL) {
        LOG_ERROR("nl_socket_alloc failed");
        abort();
    }

    if ((nlerr = nl_connect(route_cache_refill_sock, NETLINK_ROUTE)) < 0) {
        AIM_DIE("nl_connect failed: %s", nl_geterror(nlerr));
    }

    if ((nlerr = nl_cache_mngr_alloc(route_cache_sock, NETLINK_ROUTE,
                                     0, &route_cache_mngr)) < 0) {
        LOG_ERROR("nl_cache_mngr_alloc failed: %s", nl_geterror(nlerr));
        abort();
    }

    if ((nlerr = nl_cache_mngr_add(route_cache_mngr, "route/link", link_change_cb, NULL, &link_cache)) < 0) {
        LOG_ERROR("nl_cache_mngr_add failed: %s", nl_geterror(nlerr));
        abort();
    }

    if (ind_soc_socket_register(nl_cache_mngr_get_fd(route_cache_mngr),
                                (ind_soc_socket_ready_callback_f)route_cache_mngr_socket_cb,
                                NULL) < 0) {
        LOG_ERROR("failed to register socket");
        abort();
    }

    netlink_callbacks = nl_cb_alloc(NL_CB_DEFAULT);
    if (netlink_callbacks == NULL) {
        LOG_ERROR("failed to allocate netlink callbacks");
        abort();
    }

    if (rtnl_qdisc_alloc_cache(route_cache_refill_sock, &qdisc_cache) < 0) {
        AIM_DIE("rtnl_qdisc_alloc_cache failed: %s", nl_geterror(nlerr));
    }

    aim_ratelimiter_init(&link_cache_refill_limiter, 1000*1000, 0, NULL);
    aim_ratelimiter_init(&qdisc_cache_refill_limiter, 1000*1000, 0, NULL);
}

void
ind_ovs_port_finish(void)
{
        ind_soc_socket_unregister(nl_cache_mngr_get_fd(route_cache_mngr));
        nl_cache_mngr_free(route_cache_mngr);
        nl_socket_free(route_cache_sock);
}

struct ind_ovs_port_counters *
ind_ovs_port_stats_select(of_port_no_t port_no)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    if (port == NULL) {
        return &dummy_stats;
    }

    return &port->pcounters;
}

static void
alloc_port_counters(struct ind_ovs_port_counters *pcounters)
{
    stats_alloc(&pcounters->rx_unicast_stats_handle);
    stats_alloc(&pcounters->tx_unicast_stats_handle);
    stats_alloc(&pcounters->rx_broadcast_stats_handle);
    stats_alloc(&pcounters->tx_broadcast_stats_handle);
    stats_alloc(&pcounters->rx_multicast_stats_handle);
    stats_alloc(&pcounters->tx_multicast_stats_handle);
    stats_alloc(&pcounters->rx_bad_vlan_stats_handle);
}

static void
free_port_counters(struct ind_ovs_port_counters *pcounters)
{
    stats_free(&pcounters->rx_unicast_stats_handle);
    stats_free(&pcounters->tx_unicast_stats_handle);
    stats_free(&pcounters->rx_broadcast_stats_handle);
    stats_free(&pcounters->tx_broadcast_stats_handle);
    stats_free(&pcounters->rx_multicast_stats_handle);
    stats_free(&pcounters->tx_multicast_stats_handle);
    stats_free(&pcounters->rx_bad_vlan_stats_handle);
}

static uint64_t
get_packet_stats(struct stats_handle *handle)
{
    struct stats stats;
    stats_get(handle, &stats);
    return stats.packets;
}

bool
ind_ovs_port_running(of_port_no_t port_no)
{
    struct ind_ovs_port *port = ind_ovs_port_lookup(port_no);
    return port && port->ifflags & IFF_RUNNING;
}

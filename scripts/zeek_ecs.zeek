
 const ecs = table (
       ["id.orig_h"] = "source.ip",
    ["id.orig_p"] = "source.port",
    ["id.resp_h"] = "destination.host",
     ["id.resp_p"] = "destination.port",
     ["type"] = "event.dataset",
     ["_write_ts"] = "event.created",
     ["uid"] = "log.id.uid",
     ["_system_name"] = "observer.hostname",
     ["community_id"] = "network.community_id",
     ["inner_vlan"] = "network.vlan.inner.id",
     ["vlan"] = "network.vlan.id",
     ["vlan_inner"] = "network.vlan.inner.id",
     ["num"] = "event.count",
     ["proto"] = "network.transport",
     ["tunnel_parents"] = "log.id.tunnel_parents",
     ["orig_bytes"] = "source.bytes",
     ["orig_ip_bytes"] = "source.ip_bytes",
     ["resp_ip_bytes"] = "destination.ip_bytes",
     ["orig_l2_addr"] = "source.mac",
     ["local_orig"] = "conn.local_orig",
     ["local_resp"] = "conn.local_resp",
     ["resp_bytes"] = "destination.bytes",
     ["network_bytes"] = "network.bytes",
     ["history"] = "network.connection.history",
     ["network_ip_bytes"] = "network.ip_bytes",
     ["missed_bytes"] = "network.missed_bytes",
     ["orig_pkts"] = "source.packets",
     ["resp_pkts"] = "destination.packets",
     ["network_packets"] = "network.packets",
     ["service"] = "network.protocol",
     ["resp_l2_addr"] = "destination.mac",
     ["cache_add_rx_ev"] = "conn.cache_add_rx_ev",
     ["cache_add_rx_mpg"] = "conn.cache_add_rx_mpg",
     ["cache_add_rx_new"] = "conn.cache_add_rx_new",
     ["cache_add_tx_ev"] = "conn.cache_add_tx_ev",
     ["cache_add_tx_mpg"] = "conn.cache_add_tx_mpg",
     ["cache_del_mpg"] = "conn.cache_del_mpg",
     ["cache_entries"] = "conn.cache_entries",
     ["corelight_shunted"] = "conn.corelight_shunted",
     ["id.orig_h_name.src"] = "conn.id.orig_h_name.src",
     ["id.orig_h_name.vals"] = "conn.id.orig_h_name.vals",
     ["id.resp_h_name.src"] = "conn.id.resp_h_name.src",
     ["id.resp_h_name.vals"] = "conn.id.resp_h_name.vals",
     ["orig_shunted_bytes"] = "conn.orig_shunted_bytes",
     ["orig_shunted_pkts"] = "conn.orig_shunted_pkts",
     ["resp_shunted_bytes"] = "conn.resp_shunted_bytes",
     ["resp_shunted_pkts"] = "conn.resp_shunted_pkts",
     ["resp_cc"] = "destination.geo.country_iso_code",
     ["orig_cc"] = "source.geo.country_iso_code",
     ["spcap.trigger"] = "labels.corelight.spcap_trigger",
     ["spcap.url"] = "labels.corelight.spcap_url",
     ["spcap.rule"] = "labels.corelight.spcap.rule");

 event zeek_init()
{
        Log::add_filter(Conn::LOG, [
                $name = "conn_ecs",
                $path = "conn_ecs",
                $field_name_map = ecs
        ]);
}





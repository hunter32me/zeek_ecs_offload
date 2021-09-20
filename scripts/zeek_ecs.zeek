
global ecs = table (["id.orig_h"] = "source.ip",
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
     ["community_id"] = "network.community_id",
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
    
       local conn = Log::get_filter(Conn::LOG, "ecs_conn");
       conn$path = "conn_ecs";
       conn$field_name_map = ecs;
     
       local dhcp = Log::get_filter(DHCP::LOG, "ecs_dhcp");
       dhcp$path = "dhcp_ecs";
       dhcp$field_name_map = ecs;
     
       local dns = Log::get_filter(DNS::LOG, "ecs_dns");
       dns$path = "dns_ecs";
       dns$field_name_map = ecs;

       local http = Log::get_filter(HTTP::LOG, "ecs_http");
       http$path = "http_ecs";
       http$field_name_map = ecs;

       local dec_rpc = Log::get_filter(DCE_RPC::LOG, "ecs_dec_rpc");
       dec_rpc$path = "dec_rpc_ecs";
       dec_rpc$field_name_map = ecs;

       local dnp3 = Log::get_filter(DNP3::LOG, "ecs_dnp3");
       dnp3$path = "dnp3_ecs";
       dnp3$field_name_map = ecs;

       local ftp = Log::get_filter(FTP::LOG, "ecs_ftp");
       ftp$path = "ftp_ecs";
       ftp$field_name_map = ecs;

       local krb = Log::get_filter(KRB::LOG, "ecs_krb");
       krb$path = "krb_ecs";
       krb$field_name_map = ecs;

       local modbus = Log::get_filter(Modbus::LOG, "ecs_modbus");
       modbus$path = "modbus_ecs";
       modbus$field_name_map = ecs;

 #      local mysql = Log::get_filter(MySQL::LOG, "ecs_mysql");
 #      mysql$path = "mysql_ecs";
 #      mysql$field_name_map = ecs;

       local ntlm = Log::get_filter(NTLM::LOG, "ecs_ntlm");
       ntlm$path = "ntlm_ecs";
       ntlm$field_name_map = ecs;

       local ntp = Log::get_filter(NTP::LOG, "ecs_ntp");
       ntp$path = "ntp_ecs";
       ntp$field_name_map = ecs;

       local radius = Log::get_filter(RADIUS::LOG, "ecs_radius");
       radius$path = "radius_ecs";
       radius$field_name_map = ecs;

       local rdp = Log::get_filter(RDP::LOG, "ecs_rdp");
       rdp$path = "rdp_ecs";
       rdp$field_name_map = ecs;

       local rfb = Log::get_filter(RFB::LOG, "ecs_rfb");
       rfb$path = "rfb_ecs";
       rfb$field_name_map = ecs;

       local  sip = Log::get_filter(SIP::LOG, "ecs_sip");
       sip$path = "sip_ecs";
       sip$field_name_map = ecs;

#       local smb = Log::get_filter(SMB::LOG, "ecs_smb");
#       smb$path = "smb_ecs";
#       smb$field_name_map = ecs;

       local smtp = Log::get_filter(SMTP::LOG, "ecs_smtp");
       smtp$path = "smtp_ecs";
       smtp$field_name_map = ecs;

       local snmp = Log::get_filter(SNMP::LOG, "ecs_snmp");
       snmp$path = "snmp_ecs";
       snmp$field_name_map = ecs;

       local scoks = Log::get_filter(SOCKS::LOG, "ecs_scoks");
       scoks$path = "scoks_ecs";
       scoks$field_name_map = ecs;

       local ssh = Log::get_filter(SSH::LOG, "ecs_ssh");
       ssh$path = "ssh_ecs";
       ssh$field_name_map = ecs;

       local ssl = Log::get_filter(SSL::LOG, "ecs_ssl");
       ssl$path = "ssl_ecs";
       ssl$field_name_map = ecs;

       local syslogecs = Log::get_filter(Syslog::LOG, "ecs_syslog");
       syslogecs$path = "syslog_ecs";
       syslogecs$field_name_map = ecs;

       local tunnel = Log::get_filter(Tunnel::LOG, "ecs_tunnel");
       tunnel$path = "tunnel_ecs";
       tunnel$field_name_map = ecs;

       local pe = Log::get_filter(PE::LOG, "ecs_pe");
       pe$path = "pe_ecs";
       pe$field_name_map = ecs;

       local notice = Log::get_filter(Notice::LOG, "ecs_notice");
       notice$path = "notice_ecs";
       notice$field_name_map = ecs;

       local software = Log::get_filter(Software::LOG, "ecs_software");
       software$path = "software_ecs";
       software$field_name_map = ecs;

       Log::add_filter(Conn::LOG,conn);
       Log::add_filter(DNS::LOG,dns);
       Log::add_filter(DHCP::LOG, dhcp);
       Log::add_filter(HTTP::LOG, http);
       Log::add_filter(DCE_RPC::LOG, dec_rpc);
       Log::add_filter(DNP3::LOG, dnp3);
       Log::add_filter(FTP::LOG, ftp);
       Log::add_filter(KRB::LOG, krb);
       Log::add_filter(Modbus::LOG, modbus);
#       Log::add_filter(MySQL::LOG, mysql);
       Log::add_filter(NTLM::LOG, ntlm);
       Log::add_filter(NTP::LOG, ntp);
       Log::add_filter(RADIUS::LOG, radius);
       Log::add_filter(RDP::LOG, rdp);
       Log::add_filter(RFB::LOG, rfb);
       Log::add_filter(SIP::LOG, sip);
#       Log::add_filter(SMB::LOG, smb);
       Log::add_filter(SMTP::LOG, smtp);
       Log::add_filter(SNMP::LOG, snmp);
       Log::add_filter(SOCKS::LOG, scoks);
       Log::add_filter(SSH::LOG, ssh);
       Log::add_filter(SSL::LOG, ssl);
       Log::add_filter(Syslog::LOG, syslogecs);
       Log::add_filter(Tunnel::LOG, tunnel);
       Log::add_filter(PE::LOG, pe);
       Log::add_filter(Notice::LOG, notice);
       Log::add_filter(Software::LOG, software);
    }

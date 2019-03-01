/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_IPV4 = 0x800;
register< bit<32> >(64) count;
/*
   
*/
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
/*ADD*/
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/*header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
}*/
/*add*/
header ipv6_t {
    bit<4>    version;
    bit<8>    trafclass;
    bit<20>   flowlabel;
    bit<16>   payloadlen;
    bit<8>    nextheader;
    bit<8>    hoplimit;
    ip6Addr_t scrAddr;
    ip6Addr_t dstAddr;
}
    


header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    ipv4_t       ipv4_tunnel;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            TYPE_IPV4: parse_select;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextheader) {
            0x41: parse_ipv4;
            default: accept;
        }

    }

    state parse_select {
	transition select(standard_metadata.ingress_port) {
	    1: parse_ipv4;
	    2: parse_myTunnel;
	    default: accept;
	  
	}
    }

    state parse_myTunnel {
	packet.extract(hdr.ipv4_tunnel);
	transition select(hdr.ipv4_tunnel.protocol) {
	    0x41: parse_ipv4;
	    default: accept;
	}
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action mytunnel_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4_tunnel.ttl = hdr.ipv4_tunnel.ttl - 1;
    }
    
    table mytunnel_lpm {
        key = {
            hdr.ipv4_tunnel.dstAddr: lpm;
        }
        actions = {
            mytunnel_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    
    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hoplimit = hdr.ipv6.hoplimit - 1;
    }

    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
	    NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action creatipv6(){
	hdr.ipv6.setValid();
	hdr.ipv6.version = 6;
	hdr.ipv6.payloadlen = hdr.ipv4.totalLen;
	hdr.ipv6.nextheader = 0x41;
	//hdr.ipv6.hoplimit = hdr.ipv4.ttl;
	hdr.ipv6.dstAddr = 0xfe800000000000000000000000005678;
	hdr.ipv6.scrAddr = 0xfe800000000000000000000000001234;
	hdr.ethernet.etherType = TYPE_IPV6;
    }

    action creatmytunnel() {
	hdr.ipv4_tunnel.setValid();
	hdr.ipv4_tunnel.version = hdr.ipv4.version;
	hdr.ipv4_tunnel.ihl = 5;
	hdr.ipv4_tunnel.diffserv = hdr.ipv4.diffserv;
	hdr.ipv4_tunnel.totalLen = hdr.ipv4.totalLen+20;
	hdr.ipv4_tunnel.identification = hdr.ipv4.identification;
	hdr.ipv4_tunnel.flags = hdr.ipv4.flags;
	hdr.ipv4_tunnel.fragOffset = hdr.ipv4.fragOffset;
	hdr.ipv4_tunnel.ttl = hdr.ipv4.ttl;
	hdr.ipv4_tunnel.protocol = 0x41;
	hdr.ipv4_tunnel.srcAddr = 0x0a0a0101;
	hdr.ipv4_tunnel.dstAddr = 0x0a0a0202;	
    }

    bit<32> temp = 0;
    action do_read_count() {
	count.read(temp,(bit<32>)0);
    }
    action do_add_count() {
        count.write((bit<32>)0, temp+(bit<32>)1);
    }

    apply {
	//do_read_count();
	if (standard_metadata.ingress_port == 1){
	    do_read_count();
	    if(temp%2 == 1){
		creatmytunnel();
		mytunnel_lpm.apply();
	    }
	    if(temp%2 == 0){
		creatipv6();
		ipv6_lpm.apply();
	    }
	    do_add_count();
            	
	}
	else{
		hdr.ethernet.etherType = TYPE_IPV4;
		ipv4_lpm.apply();
		hdr.ipv6.setInvalid();
		hdr.ipv4_tunnel.setInvalid();
        }
	//do_add_count();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { 
	 }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

	update_checksum(
	    hdr.ipv4_tunnel.isValid(),
            { hdr.ipv4_tunnel.version,
	      hdr.ipv4_tunnel.ihl,
              hdr.ipv4_tunnel.diffserv,
              hdr.ipv4_tunnel.totalLen,
              hdr.ipv4_tunnel.identification,
              hdr.ipv4_tunnel.flags,
              hdr.ipv4_tunnel.fragOffset,
              hdr.ipv4_tunnel.ttl,
              hdr.ipv4_tunnel.protocol,
              hdr.ipv4_tunnel.srcAddr,
              hdr.ipv4_tunnel.dstAddr },
            hdr.ipv4_tunnel.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
	packet.emit(hdr.ipv4_tunnel);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

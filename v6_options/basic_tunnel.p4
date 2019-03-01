/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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

header sourceip_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr; 
}

header fragmentexte_t{
    bit<8>    nextheader;
    bit<8>    useless1;
    bit<13>   fragOffset;
    bit<2>    useless2;
    bit<1>    flag_m;
    bit<32>   identification;
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
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    ipv4_t       ipv4;
    sourceip_t   sourceip;
    fragmentexte_t    fragmentexte;
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
            TYPE_MYTUNNEL: parse_myTunnel;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_myTunnel {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextheader) {
            0x44: parse_fragmentexte;
	    0xFF: parse_sourceip;
            default: accept;
        }
    }

    state parse_fragmentexte {
	packet.extract(hdr.fragmentexte);
	transition select(hdr.fragmentexte.nextheader) {
		0xFF: parse_sourceip;
		default: accept;
	}
    }

    state parse_sourceip {
	packet.extract(hdr.sourceip);
	transition accept;
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
    

    action myTunnel_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hoplimit = hdr.ipv6.hoplimit - 1;
    }

    table myTunnel_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            myTunnel_forward;
            drop;
	    NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    action addtunnel() {
	hdr.ipv6.setValid();
	hdr.ipv6.nextheader = 0x44;
	hdr.ipv6.dstAddr = 0xfe800000000000000000000000005678;
	hdr.ethernet.etherType = TYPE_MYTUNNEL;
	hdr.fragmentexte.setValid();
	hdr.fragmentexte.nextheader = 0xFF;
	hdr.fragmentexte.fragOffset = hdr.ipv4.fragOffset;
	hdr.fragmentexte.flag_m = hdr.ipv4.flags[0:0];
	hdr.fragmentexte.identification[15:0] = hdr.ipv4.identification;
	hdr.sourceip.setValid();
	hdr.sourceip.srcAddr = hdr.ipv4.srcAddr;
	hdr.sourceip.dstAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.setInvalid();
    }

    action removetunnel() {
	hdr.ethernet.etherType = TYPE_IPV4;
	hdr.ipv4.setValid();
	hdr.ipv4.fragOffset = hdr.fragmentexte.fragOffset;
	hdr.ipv4.flags[0:0] = hdr.fragmentexte.flag_m;
	hdr.ipv4.identification = hdr.fragmentexte.identification[15:0];
	hdr.ipv4.version = 4;
	hdr.ipv4.ihl = 5;
	hdr.ipv4.totalLen = 50;
	hdr.ipv4.protocol = 7;
	hdr.ipv4.srcAddr = hdr.sourceip.srcAddr;
	hdr.ipv4.dstAddr = hdr.sourceip.dstAddr;
	hdr.fragmentexte.setInvalid();
	hdr.sourceip.setInvalid();
	hdr.ipv6.setInvalid();
    }




    apply {

	if (!hdr.ipv6.isValid()){
		addtunnel();
            	myTunnel_lpm.apply();
		}
	else{
		removetunnel();
		ipv4_lpm.apply();
        }
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
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
	packet.emit(hdr.fragmentexte);
	packet.emit(hdr.sourceip);
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

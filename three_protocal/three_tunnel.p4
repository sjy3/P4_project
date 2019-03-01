/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SINET = 0x9999;
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
typedef bit<8> sinetAddrLength_t;
typedef bit<256> sinetAddr_t;

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

//the template of sinet header.
header sinet_t {
    bit<4> version;
    bit<8> slicing_id;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> srcAddr_length;
    bit<8> dstAddr_length;
    bit<8> hop_limit;
    bit<16> extra_state_info;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

//the template of sinet extend header --- srcAddr graft 0x80
header sinet_extend_src_graft_t {
    bit<8> next_header;
    bit<24> srcAddr;
}

//the template of sinet extend header --- dstAddr graft 0x90
header sinet_extend_dst_graft_t {
    bit<8> next_header;
    bit<24> dstAddr;
}


struct metadata {
    bit<256> sinetAddr_src;
    bit<256> sinetAddr_dst;
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    ipv4_t       ipv4_tunnel;
    ipv4_t       ipv4;
    sinet_t sinet;
    sinet_extend_src_graft_t sinet_extend_src_graft0; 
    sinet_extend_src_graft_t sinet_extend_src_graft1;
    sinet_extend_src_graft_t sinet_extend_src_graft2;
    sinet_extend_src_graft_t sinet_extend_src_graft3;
    sinet_extend_src_graft_t sinet_extend_src_graft4;
    sinet_extend_src_graft_t sinet_extend_src_graft5;
    sinet_extend_src_graft_t sinet_extend_src_graft6;
    sinet_extend_src_graft_t sinet_extend_src_graft7;
    sinet_extend_src_graft_t sinet_extend_src_graft8;
    sinet_extend_src_graft_t sinet_extend_src_graft9;
    sinet_extend_dst_graft_t sinet_extend_dst_graft0;
    sinet_extend_dst_graft_t sinet_extend_dst_graft1;
    sinet_extend_dst_graft_t sinet_extend_dst_graft2;
    sinet_extend_dst_graft_t sinet_extend_dst_graft3;
    sinet_extend_dst_graft_t sinet_extend_dst_graft4;
    sinet_extend_dst_graft_t sinet_extend_dst_graft5;
    sinet_extend_dst_graft_t sinet_extend_dst_graft6;
    sinet_extend_dst_graft_t sinet_extend_dst_graft7;
    sinet_extend_dst_graft_t sinet_extend_dst_graft8;
    sinet_extend_dst_graft_t sinet_extend_dst_graft9;
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
            TYPE_SINET: parse_sinet;
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

    state parse_sinet {
        packet.extract(hdr.sinet);
        //32 bits
        meta.sinetAddr_src[255:224] = hdr.sinet.srcAddr;
        meta.sinetAddr_dst[255:224] = hdr.sinet.dstAddr;
        transition select(hdr.sinet.next_header) {
            0x80: parse_sinet_extend_src_graft0;
            0x90: parse_sinet_extend_dst_graft0;
            0x88: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_sinet_extend_src_graft0 {
        packet.extract(hdr.sinet_extend_src_graft0);
        //24 bits
        meta.sinetAddr_src[223:200] = hdr.sinet_extend_src_graft0.srcAddr;
        transition select(hdr.sinet_extend_src_graft0.next_header) {
            0x80: parse_sinet_extend_src_graft1;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft1 {
        packet.extract(hdr.sinet_extend_src_graft1);
        //24 bits 
        meta.sinetAddr_src[199:176] = hdr.sinet_extend_src_graft1.srcAddr;
        transition select(hdr.sinet_extend_src_graft1.next_header) {
            0x80: parse_sinet_extend_src_graft2;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft2 {
        packet.extract(hdr.sinet_extend_src_graft2);
        //24 bits
        meta.sinetAddr_src[175:152] = hdr.sinet_extend_src_graft2.srcAddr;
        transition select(hdr.sinet_extend_src_graft2.next_header) {
            0x80: parse_sinet_extend_src_graft3;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft3 {
        packet.extract(hdr.sinet_extend_src_graft3);
        //24 bits
        meta.sinetAddr_src[151:128] = hdr.sinet_extend_src_graft3.srcAddr;
        transition select(hdr.sinet_extend_src_graft3.next_header) {
            0x80: parse_sinet_extend_src_graft4;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft4 {
        packet.extract(hdr.sinet_extend_src_graft4);
        //24 bits
        meta.sinetAddr_src[127:104] = hdr.sinet_extend_src_graft4.srcAddr;
        transition select(hdr.sinet_extend_src_graft4.next_header) {
            0x80: parse_sinet_extend_src_graft5;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft5 {
        packet.extract(hdr.sinet_extend_src_graft5);
        //24 bits
        meta.sinetAddr_src[103:80] = hdr.sinet_extend_src_graft5.srcAddr;
        transition select(hdr.sinet_extend_src_graft5.next_header) {
            0x80: parse_sinet_extend_src_graft6;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft6 {
        packet.extract(hdr.sinet_extend_src_graft6);
        //24 bits
        meta.sinetAddr_src[79:56] = hdr.sinet_extend_src_graft6.srcAddr;
        transition select(hdr.sinet_extend_src_graft6.next_header) {
            0x80: parse_sinet_extend_src_graft7;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft7 {
        packet.extract(hdr.sinet_extend_src_graft7);
        //24 bits
        meta.sinetAddr_src[55:32] = hdr.sinet_extend_src_graft7.srcAddr;
        transition select(hdr.sinet_extend_src_graft7.next_header) {
            0x80: parse_sinet_extend_src_graft8;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft8 {
        packet.extract(hdr.sinet_extend_src_graft8);
        //24 bits
        meta.sinetAddr_src[31:8] = hdr.sinet_extend_src_graft8.srcAddr;
        transition select(hdr.sinet_extend_src_graft8.next_header) {
            0x80: parse_sinet_extend_src_graft9;
            0x90: parse_sinet_extend_dst_graft0;
            default: accept;
        }
    }

    state parse_sinet_extend_src_graft9 {
        packet.extract(hdr.sinet_extend_src_graft9);
        //24 bits
        meta.sinetAddr_src[7:0] = hdr.sinet_extend_src_graft9.srcAddr[23:16];
        transition select(hdr.sinet_extend_src_graft9.next_header) {
            0x90: parse_sinet_extend_dst_graft0;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft0 {
        packet.extract(hdr.sinet_extend_dst_graft0);
        //24 bits
        meta.sinetAddr_dst[223:200] = hdr.sinet_extend_dst_graft0.dstAddr;
        transition select(hdr.sinet_extend_dst_graft0.next_header) {
            0x90: parse_sinet_extend_dst_graft1;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft1 {
        packet.extract(hdr.sinet_extend_dst_graft1);
        //24 bits 
        meta.sinetAddr_dst[199:176] = hdr.sinet_extend_dst_graft1.dstAddr;
        transition select(hdr.sinet_extend_dst_graft1.next_header) {
            0x90: parse_sinet_extend_dst_graft2;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft2 {
        packet.extract(hdr.sinet_extend_dst_graft2);
        //24 bits
        meta.sinetAddr_dst[175:152] = hdr.sinet_extend_dst_graft2.dstAddr;
        transition select(hdr.sinet_extend_dst_graft2.next_header) {
            0x90: parse_sinet_extend_dst_graft3;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft3 {
        packet.extract(hdr.sinet_extend_dst_graft3);
        //24 bits
        meta.sinetAddr_dst[151:128] = hdr.sinet_extend_dst_graft3.dstAddr;
        transition select(hdr.sinet_extend_dst_graft3.next_header) {
            0x90: parse_sinet_extend_dst_graft4;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft4 {
        packet.extract(hdr.sinet_extend_dst_graft4);
        //24 bits
        meta.sinetAddr_dst[127:104] = hdr.sinet_extend_dst_graft4.dstAddr;
        transition select(hdr.sinet_extend_dst_graft4.next_header) {
            0x90: parse_sinet_extend_dst_graft5;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft5 {
        packet.extract(hdr.sinet_extend_dst_graft5);
        //24 bits
        meta.sinetAddr_dst[103:80] = hdr.sinet_extend_dst_graft5.dstAddr;
        transition select(hdr.sinet_extend_dst_graft5.next_header) {
            0x90: parse_sinet_extend_dst_graft6;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft6 {
        packet.extract(hdr.sinet_extend_dst_graft6);
        //24 bits
        meta.sinetAddr_dst[79:56] = hdr.sinet_extend_dst_graft6.dstAddr;
        transition select(hdr.sinet_extend_dst_graft6.next_header) {
            0x90: parse_sinet_extend_dst_graft7;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft7 {
        packet.extract(hdr.sinet_extend_dst_graft7);
        //24 bits
        meta.sinetAddr_dst[55:32] = hdr.sinet_extend_dst_graft7.dstAddr;
        transition select(hdr.sinet_extend_dst_graft7.next_header) {
            0x90: parse_sinet_extend_dst_graft8;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft8 {
        packet.extract(hdr.sinet_extend_dst_graft8);
        //24 bits
        meta.sinetAddr_dst[31:8] = hdr.sinet_extend_dst_graft8.dstAddr;
        transition select(hdr.sinet_extend_dst_graft8.next_header) {
            0x90: parse_sinet_extend_dst_graft9;
            0x88: parse_ipv4;
            default: accept;
        }
    }

    state parse_sinet_extend_dst_graft9 {
        packet.extract(hdr.sinet_extend_dst_graft9);
        //24 bits
        meta.sinetAddr_dst[7:0] = hdr.sinet_extend_dst_graft9.dstAddr[23:16];
        transition select(hdr.sinet_extend_dst_graft9.next_header) {
            0x88: parse_ipv4;
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

    //para: dst_mac_addr, src_sinet_length, src_sinet_addr, dst_sinet_length, dst_sinet_addr, port(output)
    action sinet_forward(macAddr_t dst_mac_addr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac_addr;
        hdr.sinet.hop_limit = hdr.ipv4.ttl - 1;
    }

   table sinet_lpm {
        key = {
            meta.sinetAddr_dst: lpm;
        }
        actions = {
            sinet_forward;
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

    action creatsinet() {
	hdr.sinet.setValid();
        hdr.sinet.srcAddr_length = 63;
        meta.sinetAddr_src = 0xff00ff00ff00ff00000000000000000000000000000000000000000000000000;
        hdr.sinet.dstAddr_length = 63;
        meta.sinetAddr_dst = 0x0f0f0f0f0f0f0f0f000000000000000000000000000000000000000000000000;
        hdr.ethernet.etherType = TYPE_SINET;
    }

    bit<32> temp = 0;
    action do_read_count() {
	count.read(temp,(bit<32>)0);
    }
    action do_add_count() {
        count.write((bit<32>)0, temp+(bit<32>)1);
    }
    action do_reset() {
	count.write((bit<32>)0, (bit<32>)1);
    }

    apply {
	if (standard_metadata.ingress_port == 1){
	    do_read_count();
	    if(temp%2 == 2){
		creatmytunnel();
		mytunnel_lpm.apply();
//		do_add_count(); 
	    }
	    if(temp%2 == 1){
		creatipv6();
		ipv6_lpm.apply();
//		do_add_count(); 
	    }
	    if(temp%2 == 0){
		creatsinet();
		sinet_lpm.apply();
//		do_reset(); 
	    }
/*	    if(temp%4 == 3){
	        ipv4_lpm.apply();
	    } */
//	    ipv4_lpm.apply();
	    do_add_count();    
	}
	else{
	    hdr.ethernet.etherType = TYPE_IPV4;
	    do_read_count();
	    if(temp%2 == 2){
//		mytunnel_lpm.apply();
		hdr.ipv4_tunnel.setInvalid();
	    }
	    if(temp%2 == 1){
//		ipv6_lpm.apply();
		hdr.ipv6.setInvalid();
	    }
	    if(temp%2 == 0){
//		sinet_lpm.apply();
	    	hdr.sinet.setInvalid();
            	if(hdr.sinet_extend_src_graft0.isValid()) {
                	hdr.sinet_extend_src_graft0.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft1.isValid()) {
                	hdr.sinet_extend_src_graft1.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft2.isValid()) {
                	hdr.sinet_extend_src_graft2.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft3.isValid()) {
                	hdr.sinet_extend_src_graft3.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft4.isValid()) {
                	hdr.sinet_extend_src_graft4.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft5.isValid()) {
                	hdr.sinet_extend_src_graft5.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft6.isValid()) {
                	hdr.sinet_extend_src_graft6.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft7.isValid()) {
                	hdr.sinet_extend_src_graft7.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft8.isValid()) {
                	hdr.sinet_extend_src_graft8.setInvalid();
            	}
            	if(hdr.sinet_extend_src_graft9.isValid()) {
                	hdr.sinet_extend_src_graft9.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft0.isValid()) {
                	hdr.sinet_extend_dst_graft0.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft1.isValid()) {
                	hdr.sinet_extend_dst_graft1.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft2.isValid()) {
                	hdr.sinet_extend_dst_graft2.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft3.isValid()) {
                	hdr.sinet_extend_dst_graft3.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft4.isValid()) {
                	hdr.sinet_extend_dst_graft4.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft5.isValid()) {
                	hdr.sinet_extend_dst_graft5.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft6.isValid()) {
                	hdr.sinet_extend_dst_graft6.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft7.isValid()) {
                	hdr.sinet_extend_dst_graft7.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft8.isValid()) {
                	hdr.sinet_extend_dst_graft8.setInvalid();
            	}
            	if(hdr.sinet_extend_dst_graft9.isValid()) {
                	hdr.sinet_extend_dst_graft9.setInvalid();
            	}
	    }
	    ipv4_lpm.apply();
/*	    if(temp%4 == 3){
		ipv4_lpm.apply();
	    }*/
        }

        if(hdr.sinet.isValid()) {
	    // modify the variable srcAddr length
	    if(hdr.sinet.srcAddr_length >= 239) {
	       hdr.sinet_extend_src_graft9.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft9.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft9.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft9.srcAddr[23:16] = meta.sinetAddr_src[7:0]; 
	       hdr.sinet_extend_src_graft8.setValid();
	       hdr.sinet_extend_src_graft8.next_header = 0x80;
	       hdr.sinet_extend_src_graft8.srcAddr = meta.sinetAddr_src[31:8];
	       hdr.sinet_extend_src_graft7.setValid();
	       hdr.sinet_extend_src_graft7.next_header = 0x80;
	       hdr.sinet_extend_src_graft7.srcAddr = meta.sinetAddr_src[55:32];
	       hdr.sinet_extend_src_graft6.setValid();
	       hdr.sinet_extend_src_graft6.next_header = 0x80;
	       hdr.sinet_extend_src_graft6.srcAddr = meta.sinetAddr_src[79:56];
	       hdr.sinet_extend_src_graft5.setValid();
	       hdr.sinet_extend_src_graft5.next_header = 0x80;
	       hdr.sinet_extend_src_graft5.srcAddr = meta.sinetAddr_src[103:80];
	       hdr.sinet_extend_src_graft4.setValid();
	       hdr.sinet_extend_src_graft4.next_header = 0x80;
	       hdr.sinet_extend_src_graft4.srcAddr = meta.sinetAddr_src[127:104];
	       hdr.sinet_extend_src_graft3.setValid();
	       hdr.sinet_extend_src_graft3.next_header = 0x80;
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 216) {
	       hdr.sinet_extend_src_graft8.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft8.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft8.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft8.srcAddr = meta.sinetAddr_src[31:8];
	       hdr.sinet_extend_src_graft7.setValid();
	       hdr.sinet_extend_src_graft7.next_header = 0x80;
	       hdr.sinet_extend_src_graft7.srcAddr = meta.sinetAddr_src[55:32];
	       hdr.sinet_extend_src_graft6.setValid();
	       hdr.sinet_extend_src_graft6.next_header = 0x80;
	       hdr.sinet_extend_src_graft6.srcAddr = meta.sinetAddr_src[79:56];
	       hdr.sinet_extend_src_graft5.setValid();
	       hdr.sinet_extend_src_graft5.next_header = 0x80;
	       hdr.sinet_extend_src_graft5.srcAddr = meta.sinetAddr_src[103:80];
	       hdr.sinet_extend_src_graft4.setValid();
	       hdr.sinet_extend_src_graft4.next_header = 0x80;
	       hdr.sinet_extend_src_graft4.srcAddr = meta.sinetAddr_src[127:104];
	       hdr.sinet_extend_src_graft3.setValid();
	       hdr.sinet_extend_src_graft3.next_header = 0x80;
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 193) {
	       hdr.sinet_extend_src_graft7.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft7.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft7.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft7.srcAddr = meta.sinetAddr_src[55:32];
	       hdr.sinet_extend_src_graft6.setValid();
	       hdr.sinet_extend_src_graft6.next_header = 0x80;
	       hdr.sinet_extend_src_graft6.srcAddr = meta.sinetAddr_src[79:56];
	       hdr.sinet_extend_src_graft5.setValid();
	       hdr.sinet_extend_src_graft5.next_header = 0x80;
	       hdr.sinet_extend_src_graft5.srcAddr = meta.sinetAddr_src[103:80];
	       hdr.sinet_extend_src_graft4.setValid();
	       hdr.sinet_extend_src_graft4.next_header = 0x80;
	       hdr.sinet_extend_src_graft4.srcAddr = meta.sinetAddr_src[127:104];
	       hdr.sinet_extend_src_graft3.setValid();
	       hdr.sinet_extend_src_graft3.next_header = 0x80;
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 170) {
	       hdr.sinet_extend_src_graft6.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft6.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft6.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft6.srcAddr = meta.sinetAddr_src[79:56];
	       hdr.sinet_extend_src_graft5.setValid();
	       hdr.sinet_extend_src_graft5.next_header = 0x80;
	       hdr.sinet_extend_src_graft5.srcAddr = meta.sinetAddr_src[103:80];
	       hdr.sinet_extend_src_graft4.setValid();
	       hdr.sinet_extend_src_graft4.next_header = 0x80;
	       hdr.sinet_extend_src_graft4.srcAddr = meta.sinetAddr_src[127:104];
	       hdr.sinet_extend_src_graft3.setValid();
	       hdr.sinet_extend_src_graft3.next_header = 0x80;
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 147) {
	       hdr.sinet_extend_src_graft5.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft5.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft5.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft5.srcAddr = meta.sinetAddr_src[103:80];
	       hdr.sinet_extend_src_graft4.setValid();
	       hdr.sinet_extend_src_graft4.next_header = 0x80;
	       hdr.sinet_extend_src_graft4.srcAddr = meta.sinetAddr_src[127:104];
	       hdr.sinet_extend_src_graft3.setValid();
	       hdr.sinet_extend_src_graft3.next_header = 0x80;
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 124) {
	       hdr.sinet_extend_src_graft4.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft4.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft4.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft4.srcAddr = meta.sinetAddr_src[127:104];
	       hdr.sinet_extend_src_graft3.setValid();
	       hdr.sinet_extend_src_graft3.next_header = 0x80;
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 101) {
	       hdr.sinet_extend_src_graft3.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft3.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft3.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft3.srcAddr = meta.sinetAddr_src[151:128];
	       hdr.sinet_extend_src_graft2.setValid();
	       hdr.sinet_extend_src_graft2.next_header = 0x80;
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 78) {
	       hdr.sinet_extend_src_graft2.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft2.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft2.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft2.srcAddr = meta.sinetAddr_src[175:152];
	       hdr.sinet_extend_src_graft1.setValid();
	       hdr.sinet_extend_src_graft1.next_header = 0x80;
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 55) {
	       hdr.sinet_extend_src_graft1.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft1.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft1.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft1.srcAddr = meta.sinetAddr_src[199:176];
	       hdr.sinet_extend_src_graft0.setValid();
	       hdr.sinet_extend_src_graft0.next_header = 0x80;
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else if(hdr.sinet.srcAddr_length >= 32) {
	       hdr.sinet_extend_src_graft0.setValid();
	       if(hdr.sinet.dstAddr_length >= 32) {
		   hdr.sinet_extend_src_graft0.next_header = 0x90;
	       }
	       else {
		   hdr.sinet_extend_src_graft0.next_header = 0x88;
	       }
	       hdr.sinet_extend_src_graft0.srcAddr = meta.sinetAddr_src[223:200];
	       hdr.sinet.next_header = 0x80;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }
	    else {
	       hdr.sinet.next_header = 0x88;
	       hdr.sinet.srcAddr = meta.sinetAddr_src[255:224];
	    }

	    // modify the variable srcAddr length
	    if(hdr.sinet.dstAddr_length >= 239) {
	       hdr.sinet_extend_dst_graft9.setValid();
	       hdr.sinet_extend_dst_graft9.next_header = 0x88;
	       hdr.sinet_extend_dst_graft9.dstAddr[23:16] = meta.sinetAddr_dst[7:0]; 
	       hdr.sinet_extend_dst_graft8.setValid();
	       hdr.sinet_extend_dst_graft8.next_header = 0x90;
	       hdr.sinet_extend_dst_graft8.dstAddr = meta.sinetAddr_dst[31:8];
	       hdr.sinet_extend_dst_graft7.setValid();
	       hdr.sinet_extend_dst_graft7.next_header = 0x90;
	       hdr.sinet_extend_dst_graft7.dstAddr = meta.sinetAddr_dst[55:32];
	       hdr.sinet_extend_dst_graft6.setValid();
	       hdr.sinet_extend_dst_graft6.next_header = 0x90;
	       hdr.sinet_extend_dst_graft6.dstAddr = meta.sinetAddr_dst[79:56];
	       hdr.sinet_extend_dst_graft5.setValid();
	       hdr.sinet_extend_dst_graft5.next_header = 0x90;
	       hdr.sinet_extend_dst_graft5.dstAddr = meta.sinetAddr_dst[103:80];
	       hdr.sinet_extend_dst_graft4.setValid();
	       hdr.sinet_extend_dst_graft4.next_header = 0x90;
	       hdr.sinet_extend_dst_graft4.dstAddr = meta.sinetAddr_dst[127:104];
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x90;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 216) {
	       hdr.sinet_extend_dst_graft8.setValid();
	       hdr.sinet_extend_dst_graft8.next_header = 0x88;
	       hdr.sinet_extend_dst_graft8.dstAddr = meta.sinetAddr_dst[31:8];
	       hdr.sinet_extend_dst_graft7.setValid();
	       hdr.sinet_extend_dst_graft7.next_header = 0x90;
	       hdr.sinet_extend_dst_graft7.dstAddr = meta.sinetAddr_dst[55:32];
	       hdr.sinet_extend_dst_graft6.setValid();
	       hdr.sinet_extend_dst_graft6.next_header = 0x90;
	       hdr.sinet_extend_dst_graft6.dstAddr = meta.sinetAddr_dst[79:56];
	       hdr.sinet_extend_dst_graft5.setValid();
	       hdr.sinet_extend_dst_graft5.next_header = 0x90;
	       hdr.sinet_extend_dst_graft5.dstAddr = meta.sinetAddr_dst[103:80];
	       hdr.sinet_extend_dst_graft4.setValid();
	       hdr.sinet_extend_dst_graft4.next_header = 0x90;
	       hdr.sinet_extend_dst_graft4.dstAddr = meta.sinetAddr_dst[127:104];
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x90;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 193) {
	       hdr.sinet_extend_dst_graft7.setValid();
	       hdr.sinet_extend_dst_graft7.next_header = 0x88;
	       hdr.sinet_extend_dst_graft7.dstAddr = meta.sinetAddr_dst[55:32];
	       hdr.sinet_extend_dst_graft6.setValid();
	       hdr.sinet_extend_dst_graft6.next_header = 0x90;
	       hdr.sinet_extend_dst_graft6.dstAddr = meta.sinetAddr_dst[79:56];
	       hdr.sinet_extend_dst_graft5.setValid();
	       hdr.sinet_extend_dst_graft5.next_header = 0x90;
	       hdr.sinet_extend_dst_graft5.dstAddr = meta.sinetAddr_dst[103:80];
	       hdr.sinet_extend_dst_graft4.setValid();
	       hdr.sinet_extend_dst_graft4.next_header = 0x90;
	       hdr.sinet_extend_dst_graft4.dstAddr = meta.sinetAddr_dst[127:104];
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x90;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 170) {
	       hdr.sinet_extend_dst_graft6.setValid();
	       hdr.sinet_extend_dst_graft6.next_header = 0x88;
	       hdr.sinet_extend_dst_graft6.dstAddr = meta.sinetAddr_dst[79:56];
	       hdr.sinet_extend_dst_graft5.setValid();
	       hdr.sinet_extend_dst_graft5.next_header = 0x90;
	       hdr.sinet_extend_dst_graft5.dstAddr = meta.sinetAddr_dst[103:80];
	       hdr.sinet_extend_dst_graft4.setValid();
	       hdr.sinet_extend_dst_graft4.next_header = 0x90;
	       hdr.sinet_extend_dst_graft4.dstAddr = meta.sinetAddr_dst[127:104];
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x90;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 147) {
	       hdr.sinet_extend_dst_graft5.setValid();
	       hdr.sinet_extend_dst_graft5.next_header = 0x88;
	       hdr.sinet_extend_dst_graft5.dstAddr = meta.sinetAddr_dst[103:80];
	       hdr.sinet_extend_dst_graft4.setValid();
	       hdr.sinet_extend_dst_graft4.next_header = 0x90;
	       hdr.sinet_extend_dst_graft4.dstAddr = meta.sinetAddr_dst[127:104];
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x90;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 124) {
	       hdr.sinet_extend_dst_graft4.setValid();
	       hdr.sinet_extend_dst_graft4.next_header = 0x88;
	       hdr.sinet_extend_dst_graft4.dstAddr = meta.sinetAddr_dst[127:104];
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x90;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 101) {
	       hdr.sinet_extend_dst_graft3.setValid();
	       hdr.sinet_extend_dst_graft3.next_header = 0x88;
	       hdr.sinet_extend_dst_graft3.dstAddr = meta.sinetAddr_dst[151:128];
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x90;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 78) {
	       hdr.sinet_extend_dst_graft2.setValid();
	       hdr.sinet_extend_dst_graft2.next_header = 0x88;
	       hdr.sinet_extend_dst_graft2.dstAddr = meta.sinetAddr_dst[175:152];
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x90;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 55) {
	       hdr.sinet_extend_dst_graft1.setValid();
	       hdr.sinet_extend_dst_graft1.next_header = 0x88;
	       hdr.sinet_extend_dst_graft1.dstAddr = meta.sinetAddr_dst[199:176];
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x90;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else if(hdr.sinet.dstAddr_length >= 32) {
	       hdr.sinet_extend_dst_graft0.setValid();
	       hdr.sinet_extend_dst_graft0.next_header = 0x88;
	       hdr.sinet_extend_dst_graft0.dstAddr = meta.sinetAddr_dst[223:200];
	       //hdr.sinet.next_header = 0x90;
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
	    else {
	       hdr.sinet.dstAddr = meta.sinetAddr_dst[255:224];
	    }
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
        packet.emit(hdr.sinet);
        packet.emit(hdr.sinet_extend_src_graft0);
        packet.emit(hdr.sinet_extend_src_graft1);
        packet.emit(hdr.sinet_extend_src_graft2);
        packet.emit(hdr.sinet_extend_src_graft3);
        packet.emit(hdr.sinet_extend_src_graft4);
        packet.emit(hdr.sinet_extend_src_graft5);
        packet.emit(hdr.sinet_extend_src_graft6);
        packet.emit(hdr.sinet_extend_src_graft7);
        packet.emit(hdr.sinet_extend_src_graft8);
        packet.emit(hdr.sinet_extend_src_graft9);
        packet.emit(hdr.sinet_extend_dst_graft0);
        packet.emit(hdr.sinet_extend_dst_graft1);
        packet.emit(hdr.sinet_extend_dst_graft2);
        packet.emit(hdr.sinet_extend_dst_graft3);
        packet.emit(hdr.sinet_extend_dst_graft4);
        packet.emit(hdr.sinet_extend_dst_graft5);
        packet.emit(hdr.sinet_extend_dst_graft6);
        packet.emit(hdr.sinet_extend_dst_graft7);
        packet.emit(hdr.sinet_extend_dst_graft8);
        packet.emit(hdr.sinet_extend_dst_graft9);
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

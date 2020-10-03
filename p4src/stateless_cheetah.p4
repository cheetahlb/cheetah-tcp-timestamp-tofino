/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

enum bit<16> ether_type_t {
    TPID = 0x8100,
    IPV4 = 0x0800,
    IPV6 = 0x86DD
}

#enum bit<8>  ip_proto_t {
#    ICMP  = 1,
#    IGMP  = 2,
#    TCP   = 6,
#    UDP   = 17
#}

typedef bit<48>   mac_addr_t;
typedef bit<32>   ipv4_addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>   	 protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header tcp_nop_h {
    bit<8>   nop1;
    bit<8>   nop2;
}

header tcp_mss_sack_h {
    bit<32>  mss;
    bit<16>  sack;
}

header tcp_timestamp_h{
    bit<8>   type;
    bit<8>   length;
    bit<16>  tsval_msb;
    bit<16>  tsval_lsb;
    bit<16>  tsecr_msb;
    bit<16>  tsecr_lsb;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h          ethernet;
    ipv4_h              ipv4;
    tcp_h               tcp;
    tcp_nop_h           nop;
    tcp_mss_sack_h      mss_sack;
    tcp_timestamp_h     timestamp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<1>        first_frag;
    bit<1>        ipv4_checksum_err;
    bit<16>       checksum;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;

    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    /* User Metadata Initialization */
    state meta_init {
        meta.first_frag        = 0;
        meta.ipv4_checksum_err = 0;
        meta.checksum = 0;   
        transition parse_ethernet;
    }

    state parse_ethernet {
        meta.ipv4_checksum_err = 0;
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4 :  parse_ipv4;
            default :  accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        tcp_checksum.subtract({hdr.ipv4.src_addr,hdr.ipv4.dst_addr});
        meta.ipv4_checksum_err = (bit<1>)ipv4_checksum.verify();
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            ( 0, 6  ) : parse_tcp;
            ( 0, _               ) : parse_first_fragment;
            default : accept;
        }              
    }

    state parse_first_fragment {
        meta.first_frag = 1;
        transition accept;
    }
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        tcp_checksum.subtract({hdr.tcp.checksum});
        //tcp_checksum.subtract({hdr.tcp.src_port,hdr.tcp.dst_port});
        
        transition select(hdr.tcp.data_offset) {
            ( 5 )  : parse_first_fragment;
            ( 8 ) : parse_nop;
            ( 10  ) : parse_mss_sack;
            default : accept;
        }
    }

    state parse_nop{
        pkt.extract(hdr.nop);
        //pkt.extract(hdr.timestamp_non_syn);
        transition parse_timestamp;
    }
    
    state parse_mss_sack{
        pkt.extract(hdr.mss_sack);
        //pkt.extract(hdr.timestamp_syn);
        transition parse_timestamp;
    }

    state parse_timestamp{
        pkt.extract(hdr.timestamp);
        tcp_checksum.subtract({hdr.timestamp.tsecr_msb, hdr.timestamp.tsecr_lsb,hdr.timestamp.tsval_msb,hdr.timestamp.tsval_lsb});
        meta.checksum = tcp_checksum.get();
        //pkt.extract(hdr.timestamp_syn);
        transition accept;
        //transition parse_first_fragment;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control calc_ipv4_hash(
    in bit<32>   ip_one,
    in bit<16>   tcp_port_one,
    in bit<16>   tcp_port_two,
    in bit<8>   ip_protocol,
    out bit<16>		      sel_hash)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash;

    apply {
        sel_hash = hash.get({ip_one, tcp_port_two, tcp_port_two, ip_protocol});
    }
}

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    /* The template type reflects the total width of the counter pair */
    bit<16> sel_hash=0;
    bit<16> cookie; 
    bit<16> cookie2; 
    bit<16> next; 
    bit<16> table_size;
    bit<16> server_id =0;
    bit<1> value_2 = 0;
    bit<1> server_timestamp_state;
    bit<16> server_timestamp;
    bit<32> vip = 0xc0a84001;
 
    Register<bit<32>, bit<32>>(32w1) table_size_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(table_size_reg) table_size_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    action table_size_reg_action(bit<32> idx) {
        table_size_reg_read_action.execute(idx);
    }

    Register<bit<16>, bit<32>>(32w1) test_reg;
    RegisterAction<bit<16>, bit<32>, bit<16>>(test_reg) test_reg_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            if(value >= table_size - 1){
                value = 0;
            }
            else{
                value = value + 1;
            }
            read_value = value;
        }
    };

     action register_action(bit<32> idx) {
        test_reg_action.execute(idx);
    }

    Register<bit<16>, bit<32>>(32w255) server_to_transition_state_reg;
    RegisterAction<bit<1>, bit<32>, bit<1>>(server_to_transition_state_reg) server_to_transition_state_reg_read = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value = value;
        }
    };

    RegisterAction<bit<16>, bit<32>, bit<16>>(server_to_transition_state_reg) server_to_transition_state_reg_write = {
        void apply(inout bit<16> value, out bit<16> read_value){
            value = (bit<16>)value_2;
            read_value=value;
        }
    };

    Register<bit<16>, bit<32>>(32w255) server_timestamps_reg;
    RegisterAction<bit<16>, bit<32>, bit<16>>(server_timestamps_reg) server_timestamps_reg_read = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
        }
    };

    RegisterAction<bit<16>, bit<32>, bit<16>>(server_timestamps_reg) server_timestamps_reg_write = {
        void apply(inout bit<16> value, out bit<16> read_value){
            value = hdr.timestamp.tsval_msb;
            read_value=value;
        }
    };

    Register<bit<16>, bit<32>>(32w1) debug_reg;
    RegisterAction<bit<16>, bit<32>, bit<16>>(debug_reg) debug_reg_write = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
        }
    };

    
    action get_server_id(bit<16> server_id_input){
        server_id = server_id_input;
    }
   

    action set_server(bit<32> server_dip, bit<16> server_id_param, bit<9> egress_port, bit<48> dmac) {
        ig_tm_md.ucast_egress_port = egress_port;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.dst_addr = server_dip;
        server_id = server_id_param;
        ig_tm_md.bypass_egress = (bit<1>)true;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table select_all_server {
        key = { cookie : exact; }
        actions = {
            set_server;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1 << 8;
    }

    table select_active_server {
        key = { next : exact; }
        actions = {
            set_server;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1 << 8;
    }

    table get_server_from_ip {
        key = {
            hdr.ipv4.src_addr: exact;
        }
        actions = {
            get_server_id;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1 << 8;

    }

    apply {
        value_2=0;
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
            bit<32> ip_1 = hdr.ipv4.dst_addr;
            bit<16> tcp_1 = hdr.tcp.dst_port;
            bit<16> tcp_2 = hdr.tcp.src_port;
            if(hdr.ipv4.dst_addr == vip){
                ip_1 = hdr.ipv4.src_addr;
                tcp_1 = hdr.tcp.src_port;
                tcp_2 = hdr.tcp.dst_port;
            }
            calc_ipv4_hash.apply(ip_1,tcp_1,tcp_2,hdr.ipv4.protocol,sel_hash);

            if(hdr.ipv4.dst_addr == vip){

                if(hdr.nop.isValid()){
                    
                    // extract the cookie from the timestamp
                    cookie = hdr.timestamp.tsecr_lsb;

                    // xor the cookie with the hash of the 5-tuple
                    cookie = cookie ^ sel_hash;

                    // send the packet to the server associated with the "decrypted" cookie
                    select_all_server.apply();

                    server_timestamp = server_timestamps_reg_read.execute((bit<32>)server_id); // read in 'server_timestamp'

                    server_timestamp_state = server_to_transition_state_reg_read.execute((bit<32>)server_id); // read in 'server_timestamp_state'

                    if(hdr.timestamp.tsecr_msb >= 32768 && server_timestamp_state == 1){
                        hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                        hdr.timestamp.tsecr_msb = server_timestamp;
                    //If the MSB is 1, but the state is 0, it is the old timestamp
                    }else if(hdr.timestamp.tsecr_msb >= 32768 && server_timestamp_state == 0){
                        hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                        hdr.timestamp.tsecr_msb = server_timestamp -1;
                    }else{ //If the MSB is 0, it is the current timestamp
                        hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                        hdr.timestamp.tsecr_msb = server_timestamp;
                    }
                    
                }
                else if(hdr.mss_sack.isValid()){

                    // extract the table size from the first register
                    table_size = (bit<16>)table_size_reg_read_action.execute(0);

                    // extract the next id the server table where the syn to should sent
                    next = (bit<16>)test_reg_action.execute(0);
               
                    // map the packet to a server and get the server_id
                    select_active_server.apply();

                    // compute the cookie for this mapping assignment
                    //cookie2 = server_id ^ sel_hash;

                    // update the fir 16MSBs of the timestamp ecr
                    //hdr.timestamp_syn.tsecr_cookie = cookie2; 
                }
                else{
                    drop();
                }
            }
            else{
                           
                //We need to find the server id from its IP
                get_server_from_ip.apply();

                //Remember the server's original MSB
                server_timestamps_reg_write.execute((bit<32>)server_id); // hdr.timestamp.tsval_msb);

                // compute the hash of the 5-tuple
                //calc_ipv4_hash.apply(hdr.ipv4.dst_addr,hdr.tcp.dst_port,hdr.tcp.src_port,hdr.ipv4.protocol,sel_hash);

                //Move the LSB to the MSB
                hdr.timestamp.tsval_msb = hdr.timestamp.tsval_lsb;

                //The cookie is the xor of the server and hash
                cookie = server_id ^ sel_hash;

                //Set the cookie in the LSB
                hdr.timestamp.tsval_lsb = cookie;

                if (hdr.timestamp.tsval_msb >= 32768){
                    value_2 = 1;
                    server_to_transition_state_reg_write.execute((bit<32>)server_id); // , 1);
                }else{
                    value_2 = 0;
                    server_to_transition_state_reg_write.execute((bit<32>)server_id); //, 0);
                }

                //send to client interface on port 1
                ig_tm_md.ucast_egress_port = 60;
                //hdr.ethernet.dstAddr = 0x00000a000001;
                hdr.ipv4.src_addr = vip;
                    
            }
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    
    apply {
        
        if(hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        if(hdr.tcp.isValid()){
            hdr.tcp.checksum = tcp_checksum.update({
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.timestamp.tsecr_msb,
                    hdr.timestamp.tsecr_lsb,
                    hdr.timestamp.tsval_msb,
                    hdr.timestamp.tsval_lsb,
                    meta.checksum
            });
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

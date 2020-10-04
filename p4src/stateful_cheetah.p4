/* -*- P4_16 -*- */

/* Start from the "apply" function to read the code with comments */

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
    bit<1>        is_fin;
    bit<1>        is_syn;
    bit<32>     timestamp;
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
        meta.is_fin = 0;   
        meta.is_syn = 0;  
        meta.timestamp=0; 
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
        
        meta.is_fin = (bit<1>)hdr.tcp.flags;
        meta.is_syn = (bit<1>)(hdr.tcp.flags >> 1);

        transition select(hdr.tcp.data_offset) {
            ( 5 )  : parse_first_fragment;
            ( 8 ) : parse_nop;
            ( 10  ) : parse_mss_sack;
            default : accept;
        }
    }

    state parse_nop{
        pkt.extract(hdr.nop);
        transition parse_timestamp;
    }
    
    state parse_mss_sack{
        pkt.extract(hdr.mss_sack);
        transition parse_timestamp;
    }

    state parse_timestamp{
        pkt.extract(hdr.timestamp);
        tcp_checksum.subtract({hdr.timestamp.tsecr_msb, hdr.timestamp.tsecr_lsb,hdr.timestamp.tsval_msb,hdr.timestamp.tsval_lsb});
        meta.checksum = tcp_checksum.get();
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control calc_ipv4_hash(
    in bit<32>   ip_one,
    in bit<16>   tcp_port_one,
    in bit<16>   tcp_port_two,
    in bit<8>   ip_protocol,
    out bit<16>           sel_hash)
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
    bit<16> sel_hash;
    //bit<16> sel_hash_2;
    //bit<16> cookie; 
    //bit<16> next; 
    bit<16> table_size=0;
    bit<16> cookie_stack;
    bit<16> cookie_head;
    bit<16> server_id =0;
    //bit<32> temp;
    bit<32> vip = 0xc0a84001;

    Register<bit<16>, _>(32w10) conn_table;
    RegisterAction<bit<16>, _, bit<16>>(conn_table) conn_table_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(conn_table) conn_table_write_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            value = server_id;
            read_value=value;
        }
    };

    /*Register<bit<16>, _>(0xa) conn_table_hash;
    RegisterAction<bit<16>, _, bit<16>>(conn_table_hash) conn_table_hash_write_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            //value =  entry.conn_hash ++ entry.conn_timestamp; //(sel_hash ++ hdr.timestamp.tsval_lsb);
            value = sel_hash;
            read_value = value;
            
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(conn_table_hash) conn_table_hash_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
        }
    };*/

    Register<bit<16>, _>(0xa) conn_table_client_ts;
    RegisterAction<bit<16>, _, bit<16>>(conn_table_client_ts) conn_table_client_ts_write_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            //value = (value & 0xffff0000);
            value = hdr.timestamp.tsval_lsb;
            read_value = value;
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(conn_table_client_ts) conn_table_client_ts_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
            //value = (value & 0xffff0000); 
        }
    };

    Register<bit<16>, _>(0xa) conn_table_server_ts;
    RegisterAction<bit<16>, _, bit<16>>(conn_table_server_ts) conn_table_server_ts_write_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            value = hdr.timestamp.tsval_lsb;
            read_value = value;
            
        }
    };
    RegisterAction<bit<16>, _, bit<16>>(conn_table_server_ts) conn_table_server_ts_read_action = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
        }
    };

    Register<bit<16>, bit<16>>(32w10) cookie_stack_reg;
    /*RegisterAction<bit<16>, bit<32>, bit<16>>(cookie_stack_reg) stack_push_write = {
        void apply(inout bit<16> value, out bit<16> read_value){
            value = hdr.timestamp.tsecr_lsb;
            #value = cookie_head;
            read_value = value;
        }
    };*/
    RegisterAction<bit<16>, bit<16>, bit<16>>(cookie_stack_reg) stack_pop_read = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value=value;
        }
    };

    Register<bit<16>, bit<16>>(32w1) stack_head;
    /*RegisterAction<bit<16>, bit<32>, bit<16>>(stack_head) stack_head_push= {
        void apply(inout bit<16> value, out bit<16> read_value){
            value = value + 1;
            read_value = value;
        }
    };*/

    RegisterAction<bit<16>, bit<16>, bit<16>>(stack_head) stack_head_pop = {
        void apply(inout bit<16> value, out bit<16> read_value){
            read_value = value;
            value = value - 1;
        }
    };

    Register<bit<32>, bit<32>>(32w1) table_size_reg;
    RegisterAction<bit<32>, bit<32>, bit<32>>(table_size_reg) table_size_reg_read_action = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

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

    action get_server_id(bit<16> server_id_input){
        server_id = server_id_input;
        hdr.ipv4.src_addr = 0xc0a84001;
        ig_tm_md.ucast_egress_port = 60; 
    }

    table select_all_server {
        key = { server_id : exact; }
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
        if (hdr.ipv4.isValid()) {
            if(hdr.tcp.isValid()){
                // prepare the input to the hash function assuming the packets comes from the server
                bit<32> ip_1 = hdr.ipv4.dst_addr;
                bit<16> tcp_1 = hdr.tcp.dst_port;
                bit<16> tcp_2 = hdr.tcp.src_port;

                // if the packet comes from the client we need to swap the connection identifier input
                if(hdr.ipv4.dst_addr == vip){
                    ip_1 = hdr.ipv4.src_addr;
                    tcp_1 = hdr.tcp.src_port;
                    tcp_2 = hdr.tcp.dst_port;
                }
                // compute the hash of the connection identifier. Currently not stored
                calc_ipv4_hash.apply(ip_1,tcp_1,tcp_2,hdr.ipv4.protocol,sel_hash);

                // check if it is an incoming or outgoing packet
                if(hdr.ipv4.dst_addr == vip){
                    //it is an incoming packet from a client

                    if(meta.is_syn == 0){
                        //if it is a packet belonging to a connection

                        // extract the cookie from the server 16 LSBs timestamp (ie, tsecr.lsb)
                        cookie_stack = hdr.timestamp.tsecr_lsb;
                        
                        // TODO: drop if the connection hash is wrong

                        @stage(8) { 
                            // write the 16 LSBs of the client timestamp (ie, tsval.msb) into the client register
                            conn_table_client_ts_write_action.execute(cookie_stack);
                        }
                        @stage(9) {
                            // restore the server 16 LSBs of the timestamp
                            hdr.timestamp.tsecr_lsb = conn_table_server_ts_read_action.execute(cookie_stack);   
                        }
                        @stage(10) {
                            // read the server assigned to this connection
                            server_id = conn_table_read_action.execute(cookie_stack);
                        }
                        // update the 16 LSBs of the client timestamp with the cookie
                        hdr.timestamp.tsval_lsb = (bit<16>)cookie_stack;

                        //send the packet to the server associated with the cookie
                        select_all_server.apply();

                    }
                    else{

                        // extract the table size from the first register
                        table_size = (bit<16>)table_size_reg_read_action.execute(0);

                        // extract the next id the server table where the syn to should sent
                        server_id = (bit<16>)test_reg_action.execute(0);

                        // get an unused cookie
                        @stage(4) { 
                            // get the pointer to the stack
                            cookie_head = stack_head_pop.execute(0);
                        }
                        @stage(6) { 
                            // get a cookie
                            cookie_stack = stack_pop_read.execute(cookie_head);
                        }

                        @stage(8) { 
                            // store the 16 LSBs of the client timestamp (ie, tsval) into the register at the "cookie" index
                            conn_table_client_ts_write_action.execute(cookie_stack);   
                        }
                        @stage(10) {
                            // store the selected server in the register at the "cookie" index
                            conn_table_write_action.execute(cookie_stack);
                        }

                        // sto the cookie into the 16 LSBs of the client timestamp (ie, tsval)
                        hdr.timestamp.tsval_lsb = cookie_stack;

                        // map the packet to the server pointed by the server_id
                        select_all_server.apply();

                    }
                }else{
                    // packet from the server
                    get_server_from_ip.apply();

                    // extract the "cookie" from the 16 LSBs of the client timestamp (ie, tsecr) 
                    cookie_stack = hdr.timestamp.tsecr_lsb; // 0x0009

                    /* FIN to be realized in coordination with the server
                    if(meta.is_fin == 0x01){ //currently not supported
                        @stage(4) { 
                            cookie_head = stack_head_push.execute(0);
                        }
                        @stage(6) { 
                            cookie_stack = stack_push_write.execute(((bit<32>)cookie_head));
                        }
                    }*/

                    @stage(8) { 
                        // restore the 16 LSBs of the client timestamp by reading the register at the "cookie" index
                        hdr.timestamp.tsecr_lsb = conn_table_client_ts_read_action.execute(cookie_stack); //abab
                    }
                    @stage(9) {
                        // write the 16 LSBs of the server timestamp into the register at the "cookie" index index
                        conn_table_server_ts_write_action.execute(cookie_stack);//cookie_stack_32); // writes ca82
                    }

                    // rewrite the 16 LSBs of the server timestamp with the cookie
                    hdr.timestamp.tsval_lsb = cookie_stack;
                }
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
            // update the IPv4 checksum
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
            // update the TCP checksum
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

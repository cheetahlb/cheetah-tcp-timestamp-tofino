from ipaddress import ip_address

p4 = bfrt.simple_l3_dir_cntr

select_all_server = p4.Ingress.select_all_server
select_active_server = p4.Ingress.select_active_server
table_size = 10

# populate the all and active servers tables. 
# repeat some servers to implemented weighted load balancing
for x in range(0,256):
    select_all_server.add_with_set_server(x,ip_address('10.200.0.'+str(x)),x)
for x in range(0,256):
    select_active_server.add_with_set_server(x,ip_address('10.200.0.'+str(x)),x)

register_table_size = p4.Ingress.table_size_reg
register_counter = p4.Ingress.test_reg

# set the size of the table
register_table_size.mod(register_index=0,f1=table_size) 
# start from the first server
register_counter.mod(register_index=0,f1=0)

# clean the counters
def clear_counters(table_node):
    for e in table_node.get(regex=True):
        e.data[b'$COUNTER_SPEC_BYTES'] = 0
        e.data[b'$COUNTER_SPEC_PKTS'] = 0
        e.push()

# dump everything
select_all_server.dump(table=True)
select_active_server.dump(table=True)
register_table_size.dump(table=True,from_hw=1)
register_counter.dump(table=True,from_hw=1)


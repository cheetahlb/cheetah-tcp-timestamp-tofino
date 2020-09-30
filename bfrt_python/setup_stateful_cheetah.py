from ipaddress import ip_address

p4 = bfrt.stateful_cheetah

number_of_servers = 256
number_of_connections = 10
table_size = 10

select_all_server = p4.Ingress.select_all_server
select_active_server = p4.Ingress.select_active_server

# populate the all and active server tables 
for x in range(0,number_of_servers):
    select_all_server.add_with_set_server(x,ip_address('10.200.0.'+str(x)),x)
for x in range(0,number_of_servers):
    select_active_server.add_with_set_server(x,ip_address('10.200.0.'+str(x)),x)

register_table_size = p4.Ingress.table_size_reg
register_counter = p4.Ingress.test_reg

# set the size of the table
register_table_size.mod(register_index=0,f1=table_size)
# start from the first server
register_counter.mod(register_index=0,f1=0)


register_conn_table = p4.Ingress.conn_table
register_cookie_stack = p4.Ingress.cookie_stack_reg
register_stack_head = p4.Ingress.stack_head

# add in the stack all the indices to store 'number_of_connections' connections
for x in range(0,number_of_connections):
    register_cookie_stack.mod(register_index=x,f1=x)

# point the stack at the last inserted element
register_stack_head.mod(register_index=0,f1=number_of_connections-1)
    
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
register_conn_table.dump(table=True,from_hw=1)
register_cookie_stack.dump(table=True,from_hw=1)
register_stack_head.dump(table=True,from_hw=1)

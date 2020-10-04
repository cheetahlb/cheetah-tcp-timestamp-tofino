from ipaddress import ip_address

p4 = bfrt.stateful_cheetah.pipe

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    def _clear(table, verbose=False, batching=False):
        if verbose:
            print("Clearing table {:<40} ... ".
                  format(table['full_name']), end='', flush=True)
        try:    
            entries = table['node'].get(regex=True, print_ents=False)
            try:
                if batching:
                    bfrt.batch_begin()
                for entry in entries:
                    entry.remove()
            except Exception as e:
                print("Problem clearing table {}: {}".format(
                    table['name'], e.sts))
            finally:
                if batching:
                    bfrt.batch_end()
        except Exception as e:
            if e.sts == 6:
                if verbose:
                    print('(Empty) ', end='')
        finally:
            if verbose:
                print('Done')

        # Optionally reset the default action, but not all tables
        # have that
        try:
            table['node'].reset_default()
        except:
            pass
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members
    

    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)
            
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            _clear(table, verbose=verbose, batching=batching)
    
clear_all()

number_of_servers = 256
number_of_connections = 10
table_size = 2

select_all_server = p4.Ingress.select_all_server
#select_active_server = p4.Ingress.select_active_server

##select_all_server = p4.Ingress.select_all_server
#select_active_server = p4.Ingress.select_active_server
get_server_from_ip = p4.Ingress.get_server_from_ip
table_size = 2

# populate the all and active servers tables. 
# repeat some servers to implemented weighted load balancing
#for x in range(0,256):
select_all_server.add_with_set_server(0,ip_address('192.168.63.16'),0,52,dmac=0xb883036f4311)
select_all_server.add_with_set_server(1,ip_address('192.168.63.19'),1,20,dmac=0xb883036f43d1)
#select_active_server.add_with_set_server(0,ip_address('192.168.63.16'),0,52,dmac=0xb883036f4311)
#select_active_server.add_with_set_server(1,ip_address('192.168.63.19'),1,20,dmac=0xb883036f43d1)
get_server_from_ip.add_with_get_server_id(ip_address('192.168.63.16'),0)
get_server_from_ip.add_with_get_server_id(ip_address('192.168.63.19'),1)


# populate the all and active server tables 
#for x in range(0,number_of_servers):
#    select_all_server.add_with_set_server(x,ip_address('192.168.63.'+str(x)),x)
#for x in range(0,number_of_servers):
#    select_active_server.add_with_set_server(x,ip_address('192.168.63.'+str(x)),x)

register_table_size = p4.Ingress.table_size_reg
register_counter = p4.Ingress.test_reg

# set the size of the table
register_table_size.mod(register_index=0,f1=table_size)
# start from the first server
register_counter.mod(register_index=0,f1=table_size-1)


register_conn_table = p4.Ingress.conn_table
register_conn_table_server_ts = p4.Ingress.conn_table_server_ts
register_conn_table_client_ts = p4.Ingress.conn_table_client_ts
register_cookie_stack = p4.Ingress.cookie_stack_reg
register_stack_head = p4.Ingress.stack_head

# add in the stack all the indices to store 'number_of_connections' connections
for x in range(0,number_of_connections):
    register_cookie_stack.mod(register_index=x,f1=x)
    register_conn_table_server_ts.mod(register_index=x,f1=0)
    register_conn_table_client_ts.mod(register_index=x,f1=0)

# point the stack at the last inserted element
register_stack_head.mod(register_index=0,f1=number_of_connections-1)
    
# clean the counters
def clear_counters(table_node):
    for e in table_node.get(regex=True):
        e.data[b'$COUNTER_SPEC_BYTES'] = 0
        e.data[b'$COUNTER_SPEC_PKTS'] = 0
        e.push()

# dump everything
##select_all_server.dump(table=True)
#select_active_server.dump(table=True)
##register_table_size.dump(table=True,from_hw=1)
##register_counter.dump(table=True,from_hw=1)
##register_conn_table.dump(table=True,from_hw=1)
##register_cookie_stack.dump(table=True,from_hw=1)
##register_stack_head.dump(table=True,from_hw=1)

from ipaddress import ip_address

p4 = bfrt.stateful_cheetah.pipe

conn_table = p4.Ingress.conn_table
conn_table_client_ts = p4.Ingress.conn_table_client_ts
conn_table_server_ts = p4.Ingress.conn_table_server_ts
cookie_stack_reg = p4.Ingress.cookie_stack_reg
stack_head = p4.Ingress.stack_head
table_size_reg = p4.Ingress.table_size_reg
test_reg = p4.Ingress.test_reg

# dump everything
conn_table.dump(table=True,from_hw=1)
conn_table_client_ts.dump(table=True,from_hw=1)
conn_table_server_ts.dump(table=True,from_hw=1)
cookie_stack_reg.dump(table=True,from_hw=1)
stack_head.dump(table=True,from_hw=1)
table_size_reg.dump(table=True,from_hw=1)
test_reg.dump(table=True,from_hw=1)


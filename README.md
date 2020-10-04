# Stateless and Stateful Cheetah with TCP timestamps: P4-Tofino code

We implemented Stateless and Stateful Cheetah in P4 on the Tofino to load balancer TCP connections by storing the Cheetah cookie in the TCP timestamp option.

## Code organization

The code consists of two files:

 * `p4src/stateless_cheetah.p4`, which contains the P4 program to handle stateless Cheetah cookies.
 * `p4src/stateful_cheetah.p4`, which contains the P4 program to handle stateful Cheetah cookies.
 * `bfrt_python/setup_stateless_cheetah.py`, which contains the Python commands to populate the P4 switch for the stateless program.
 * `bfrt_python/setup_stateful_cheetah.py`, which contains the Python commands to populate the P4 switch for the stateful program.

## Topology and configuration

The `VIP` of Cheetah is preconfigured to be `192.168.64.1`

The `DIP` of Server-1 is preconfigured to be `192.168.63.16`. Server-1 is connected to port 10 (D_P = 52) of the Tofino switch.
The `DIP` of Server-2 is preconfigured to be `192.168.63.19`. Server-2 is connected to port 13 (D_P = 28) of the Tofino switch.

The client is connected to port 9 (D_P = 60) of the tofino switch.

The current P4 program does not handle ARP requests so ARP should be statically set up on the machines and the MAC addresses should be configured in the `bfrt_python` files.

The LB implements Weighted Round Robin with 2 buckets, each pointing to a server.

If you plan to change these values, you need to modify them in the `bfrt_python` files.

Remember to disable randomized timestamps on the servers:

`sysctl -w net.ipv4.tcp_timestamps=2`

## Running the code

Move the files of this repository into a folder on the switch:

`scp * username@host:$CHEETAH_LAB/p4src/stateless_cheetah.p4` or
`scp * username@host:$CHEETAH_LAB/p4src/stateful_cheetah.p4`

where `$CHEETAH_LAB` is the directory where you plan to store the tofino-related files and host is the IP of the Tofino switch.

### Build the program

`$SDE/p4_build.sh $CHEETAH_LAB/p4src/stateless_cheetah.p4` or
`$SDE/p4_build.sh $CHEETAH_LAB/p4src/stateful_cheetah.p4`

### Run the program

Run the program onto the switch:

`$SDE/run_switchd.sh -p stateless_cheetah` or `$SDE/run_switchd.sh -p stateful_cheetah`

### Populate the table and registers

Run in another window the following commands:

`$SDE/run_bfshell.sh -b $CHEETAH_LAB/bfrt_python/setup_stateless_cheetah.py` or 
`$SDE/run_bfshell.sh -b $CHEETAH_LAB/bfrt_python/setup_stateful_cheetah.py`

Ths switch is now running properly.

## Test the load balancer

Go to Server-1 and run the following command:

`netcat -l 4444 > received_file_server_1`

Go to Server-2 and run the following command:

`netcat -l 4444 > received_file_server_2`

Open three `tcpdump` sessions to spoof traffic at the interfaces of the three machines.

Go to the client and run the following command:

`netcat -w 1 192.168.64.1 4444 < file.txt`, where `file` is any file you wish to transfer.

This will generate a request towards the `VIP` and will be served by Server-1. Check on `tcpdump`.

Run again the same command at the client. The request will now be served by Server-2. Check on `tcpdump`

This cycle repeats for each request sent by a client.



# CS331 - Computer Networks - Assignment-1

By: Bhavya Parmar (23110059) and Romit Mohane (23110279)

## Task 1 - DNS Resolver

After cloning the repository and moving into it's root:
1. To run the DNS Resolver, activate a virtual environment (optional). Then, move to the DNS_Resolver directory with 
```bash
cd DNS_Resolver
```
2. then, __run the server first__ with:
```bash
python server.py
```
3. __then, run the client__ after creating a new terminal, with:
```bash
python client.py
```
The `pcap` file is to be placed in the `DNS_Resolver` directory only, and the file name has to be updated in `client.py`'s line number `57`.
We used the file `8.pcap` as specified by the assignment.

You can then see some logs in the terminal of both client and server, and __a final table will be stored in a text file__ with the filename defined according to the time of the day (see lines `48` to `55` in `client.py`) in the [logs](./DNS_Resolver/logs) sub-directory.

You can finally close the server by clicking the `Enter` key.

## Task 2 - Traceroute Protocol Behavior

The pcapng files for this task have been added in [Task 2](./Task%202) and the rest of the details are in the [report](Report%20-%20Assignment%201.pdf).
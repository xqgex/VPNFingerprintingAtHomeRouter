# VPN Fingerprinting Python implementation

## Background

This directory contains the implementation of the research in Python. The code
was designed to have minimal 3rd party dependencies (`NetfilterQueue==1.1.0`)
and to use as minimal stored memory as possible. The code logic is equivalent to
the C implementation.

The implementation contain the following files:

* `new_packet_arrival_from_nic.py`: Entry point for running the code directly on
  the NIC.
* `new_packet_arrival_from_pcap.py`: Entry point for testing, using a `.pcap`
  file as the source for the data.
* `analyze_packet.py`: Contains the main logic of the VPN fingerprinting.
* `parse_packet.py`: Utility functions to parse the minimal required data from
  raw bytes (either starting at L2 or L3), the file also contains the function
  that filter packets that are not going/arriving from a public IP address.
* `parse_packet_test.py`: Sanity tests for `parse_packet.py` using `pytest` and
  `hamcrest`.

## NetfilterQueue

When running the code for live traffic, a Python library called `NetfilterQueue`
is used in order to raise the packets from the kernel mode to the user space,
The function have hardcoded numbers to read only the first 20 bytes from each
packet, store it at queue number 1, and have a queue for maximum 2048 packets.

## Run the code on live traffic

Start by running the code using the following command:

```
python3 new_packet_arrival_from_nic.py
```

It is important to run the code **before** adding the `iptables` so you will
not lose the internet connectivity and "brick" the device.

To send all incoming packets to the Python code, an `iptables` rules should be
added:

```
iptables -I INPUT 1 -j NFQUEUE --queue-num 1
```

Note that the queue number 1 is hardcoded in the rule, this number should match
the number in the Python code.

In order to restore the settings, you can always remove the `iptables` rule by
executing a `-D` command:

```
sudo iptables -D INPUT 1
```

## Inspect the output

The Python code is using the logger module and it should be visible at the
terminal `stdout`.

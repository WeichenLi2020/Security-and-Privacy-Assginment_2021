from sys import argv
import dpkt


def detect_anomaly(packet_capture):
    """
    Process a dpkt packet capture to determine if any syn scan is detected. For every IP address address that are
    detected as suspicious. We define "suspicious" as having sent more than three times as many SYN packets as the
    number of SYN+ACK packets received.
    :param packet_capture: dpkt packet capture object for processing
    """

    '''
    ip_dict: Dictionary to record the # of SYN packets sent and  the # of SYN-ACK packet received for a given IP address.
            Format:
                ip address: # of SYN packets, # of SYN-ACK packets
    '''
    ip_dict = {}

    for timestamp, buff in packet_capture:
        # Try to read the Ethernet frame, skip if failed
        try:
            eth = dpkt.ethernet.Ethernet(buff)
        except:
            continue

        # if the packet is not tcp packet, then skip
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        # Read tcp data from ip datagram
        tcp = ip.data

        # get the SYN flag and ACK flag of the packet
        syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0

        # the packet is a SYN packet
        if (syn_flag and not ack_flag):
            # get the source ip address
            ip_src = list(ip.src)
            ip_src = "%d.%d.%d.%d" % tuple(ip_src)
            # add the number of sent SYN packet by 1
            if ip_dict.get(ip_src) == None:
                ip_dict[ip_src] = [0, 0]
            ip_dict[ip_src][0] += 1
        # the packet is a SYN-ACK packet
        elif (syn_flag and ack_flag):
            # get the destination ip address
            ip_dst = list(ip.dst)
            ip_dst = "%d.%d.%d.%d" % tuple(ip_dst)
            # add the number of received SYN-ACK packet by 1
            if ip_dict.get(ip_dst) == None:
                ip_dict[ip_dst] = [0, 1]
            ip_dict[ip_dst][1] += 1

    res = []
    for ip_addr, vals in ip_dict.items():
        if (vals[0] > 3 * vals[1]):
            # add the suspicious ip address into the result list
            res.append(ip_addr)
    # print result
    if len(res)>0:
        for ip_addr in res:
            print(ip_addr)
    else:
        print('No suspicious ip address detected')

if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python detector.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        detect_anomaly(pcap_obj)
import nnpy
import struct
import ipaddress
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI

class DigestController():

    def __init__(self, sw_name):

        self.sw_name = sw_name
        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

    def recv_msg_digest(self, msg):

        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                     msg[:32])
        #print num, len(msg)
        offset = 17  #number of bytes in digest message
        msg = msg[32:]
        for sub_message in range(num):
            #msg_type, src, dst = struct.unpack("!BII", msg[0:offset])
            msg_type, arg1, arg2, arg3, arg4 = struct.unpack("!BIIII", msg[0:offset])
            if msg_type == 0:
                print "------------------------------------------------------------"
                print "This is a debug message --> action is executed successfully!"
                print "Message:", msg_type, "data", arg1, "extra:", arg2
                print "------------------------------------------------------------"
            elif msg_type == 1:
                print "message type:", msg_type, "src ip:", str(ipaddress.IPv4Address(arg1)), "dst ip:", str(ipaddress.IPv4Address(arg2))
                self.controller.table_add("whitelist", "NoAction", [str(ipaddress.IPv4Address(arg1))])
            elif msg_type == 2:
                print "message type:", msg_type, "connection is added with Hash:", str(arg1), "diff:", str(arg2)
                self.controller.table_add("connections", "saveDifferenceValue", [str(arg1)], [str(arg2)])
                print "message type:", msg_type, "connection is added with Hash:", str(arg3), "diff:", str(arg4)
                self.controller.table_add("connections", "saveDifferenceValue", [str(arg3)], [str(arg4)])
            else:
                print("Unknown message type!")
            msg = msg[offset:]


        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):

        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        print "connecting to notification sub %s" % notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


def main():
    DigestController("s1").run_digest_loop()

if __name__ == "__main__":
    main()
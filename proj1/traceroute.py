import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3


class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int  # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int  # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    FIELD_TO_LENGTH = {
        "version": 4,
        "header_len": 4,
        "tos": 8,
        "length": 16,
        "id": 16,
        "flags": 3,
        "frag_offset": 13,
        "ttl": 8,
        "proto": 8,
        "cksum": 16,
    }
    MIN_LENGTH = (sum(FIELD_TO_LENGTH.values()) + 32 + 32) // 8

    def __init__(self, buffer: bytes):
        if len(buffer) < self.MIN_LENGTH:
            raise ValueError(
                f"cannot parse IPv4 header from buffer = {buffer.hex()}: required fields are missing / incomplete"
            )

        bits = "".join(format(byte, "08b") for byte in [*buffer])
        for field, length in self.FIELD_TO_LENGTH.items():
            setattr(self, field, int(bits[:length], 2))
            bits = bits[length:]

        self.header_len *= 4

        if len(buffer) < self.header_len:
            raise ValueError(
                f"cannot parse IPv4 header from buffer = {buffer.hex()}: Options field is missing / incomplete"
            )

        self.src = f"{int(bits[:8], 2)}.{int(bits[8:16], 2)}.{int(bits[16:24], 2)}.{int(bits[24:32], 2)}"
        bits = bits[32:]
        self.dst = f"{int(bits[:8], 2)}.{int(bits[8:16], 2)}.{int(bits[16:24], 2)}.{int(bits[24:32], 2)}"
        bits = bits[32:]

    def __str__(self) -> str:
        return (
            f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, "
            + f"id {self.id}, flags 0x{self.flags:x}, "
            + f"ofsset {self.frag_offset}, "
            + f"proto {self.proto}, header_len {self.header_len}, "
            + f"len {self.length}, cksum 0x{self.cksum:x}) "
            + f"{self.src} > {self.dst}"
        )


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    FIELD_TO_LENGTH = {
        "type": 8,
        "code": 8,
        "cksum": 16,
    }
    TOTAL_LENGTH = sum(FIELD_TO_LENGTH.values()) // 8

    def __init__(self, buffer: bytes):
        if len(buffer) < self.TOTAL_LENGTH:
            raise ValueError(
                f"cannot parse ICMP header from buffer = {buffer.hex()}: required fields are missing / incomplete"
            )

        bits = "".join(format(byte, "08b") for byte in [*buffer])
        for field, length in self.FIELD_TO_LENGTH.items():
            setattr(self, field, int(bits[:length], 2))
            bits = bits[length:]

    def __str__(self) -> str:
        return (
            f"ICMP (type {self.type}, code {self.code}, " + f"cksum 0x{self.cksum:x})"
        )


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    FIELD_TO_LENGTH = {
        "src_port": 16,
        "dst_port": 16,
        "len": 16,
        "cksum": 16,
    }
    TOTAL_LENGTH = sum(FIELD_TO_LENGTH.values()) // 8

    def __init__(self, buffer: bytes):
        if len(buffer) < self.TOTAL_LENGTH:
            raise ValueError(
                f"cannot parse UDP header from buffer = {buffer.hex()}: required fields are missing / incomplete"
            )

        bits = "".join(format(byte, "08b") for byte in [*buffer])
        for field, length in self.FIELD_TO_LENGTH.items():
            setattr(self, field, int(bits[:length], 2))
            bits = bits[length:]

    def __str__(self) -> str:
        return (
            f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, "
            + f"len {self.len}, cksum 0x{self.cksum:x})"
        )


# TODO feel free to add helper functions if you'd like


def traceroute(
    sendsock: util.Socket, recvsock: util.Socket, ip: str
) -> list[list[str]]:
    """Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        util.print_result([], ttl)
    return []


if __name__ == "__main__":
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

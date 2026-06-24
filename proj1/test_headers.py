import pytest

from traceroute import ICMP, UDP, IPv4


@pytest.fixture
def ipv4_header():
    return bytes.fromhex("45C0003F0FF000003F01D4B10A000001AC1FE03C")


@pytest.fixture
def ipv4_header_invalid_header_len():
    return bytes.fromhex("46C0003F0FF000003F01D4B10A000001AC1FE03C")


@pytest.fixture
def icmp_header():
    return bytes.fromhex("0B00A32400000000")


@pytest.fixture
def orig_ipv4_header():
    return bytes.fromhex("450000231D10400001112652AC1FE03C80022A0A")


@pytest.fixture
def orig_udp_datagram():
    return bytes.fromhex("D2CD829A000F9523506F7461746F2E")


def test_parse_valid_ipv4(ipv4_header: bytes):
    ipv4 = IPv4(ipv4_header)
    assert ipv4.version == 4
    assert ipv4.header_len == 20
    assert ipv4.tos == 0xC0
    assert ipv4.length == 63
    assert ipv4.id == 4080
    assert ipv4.flags == 0x0
    assert ipv4.frag_offset == 0
    assert ipv4.ttl == 63
    assert ipv4.proto == 1
    assert ipv4.cksum == 0xD4B1
    assert ipv4.src == "10.0.0.1"
    assert ipv4.dst == "172.31.224.60"


def test_parse_valid_icmp(icmp_header: bytes):
    icmp = ICMP(icmp_header)
    assert icmp.type == 11
    assert icmp.code == 0
    assert icmp.cksum == 0xA324


def test_parse_valid_udp(orig_udp_datagram: bytes):
    udp = UDP(orig_udp_datagram)
    assert udp.src_port == 53965
    assert udp.dst_port == 33434
    assert udp.len == 15
    assert udp.cksum == 0x9523


def test_parse_invalid_ipv4():
    with pytest.raises(ValueError):
        IPv4(bytes(1))


def test_parse_invalid_ipv4_header_len(ipv4_header_invalid_header_len: bytes):
    with pytest.raises(ValueError, match="Options"):
        IPv4(ipv4_header_invalid_header_len)


def test_parse_invalid_icmp():
    with pytest.raises(ValueError):
        ICMP(bytes(1))


def test_parse_invalid_udp():
    with pytest.raises(ValueError):
        UDP(bytes(1))

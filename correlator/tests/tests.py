from correlator.classes import XDR3G, XDR4G, Message3G, Message4G

from .fixtures import msg_3g_from_text, msg_4g_from_text


def test_msg_4G_parsing():
    msg = Message4G()
    msg.from_text(msg_4g_from_text[0].split("\n"))
    assert msg.body is not None
    assert msg.gci == 153979139
    assert msg.name == "INTERNAL_PER_RADIO_UE_MEASUREMENT_TA"
    assert msg.enbid == 273678
    assert msg.trsr == 27918
    assert msg.timestamp == "06:48:56.489"


def test_msg_3G_parsing():
    msg = Message3G()
    msg.from_text(msg_3g_from_text[2].split("\n"))
    assert msg.body is not None
    assert msg.ueid == 512
    assert msg.name == "INTERNAL_SOFT_HANDOVER_EXECUTION"
    assert msg.rncmodid == 0
    assert msg.rncid == 2241
    assert msg.timestamp == "2020-09-21T06:37:59.790Z"


def test_msg_matches():
    msg = Message3G()
    msg.from_text(msg_3g_from_text[2].split("\n"))
    assert msg.matches(ueid=512, rncmodid=0, gci=None)
    assert not msg.matches(ueid=512, rncmodid=1, gci=None)
    msg2 = Message4G()
    msg2.from_text(msg_4g_from_text[0].split("\n"))
    assert msg2.matches(gci=153979139, trsr=27918, enbid=273678, ueid=None)
    assert not msg2.matches(gci=1, trsr=27918, enbid=273678, ueid=None)


def test_xdr_descr():
    msg = Message4G()
    msg.from_text(msg_4g_from_text[1].split("\n"))
    xdr = XDR4G(msg)
    msg_proper = Message4G()
    msg_proper.from_text(msg_4g_from_text[2].split("\n"))
    xdr.add_msg(msg_proper)
    assert len(xdr.get_msg_descr()) == 2


def test_xdr_4G_correlation():
    msg = Message4G()
    msg.from_text(msg_4g_from_text[1].split("\n"))
    xdr = XDR4G(msg)
    msg_proper = Message4G()
    msg_proper.from_text(msg_4g_from_text[2].split("\n"))
    assert xdr.matches(msg_proper)
    msg_inproper = Message4G()
    msg_inproper.from_text(msg_4g_from_text[3].split("\n"))
    assert xdr.matches(msg_inproper) == False


def test_xdr_3G_correlation():
    msg = Message3G()
    msg.from_text(msg_3g_from_text[0].split("\n"))
    xdr = XDR3G(msg)
    msg_proper = Message3G()
    msg_proper.from_text(msg_3g_from_text[1].split("\n"))
    assert xdr.matches(msg_proper)
    msg_inproper = Message3G()
    msg_inproper.from_text(msg_3g_from_text[2].split("\n"))
    assert xdr.matches(msg_inproper) == False


def test_x2_handover():
    msg = Message4G()
    msg.from_text(msg_4g_from_text[1].split("\n"))
    xdr = XDR4G(msg)
    msg_proper = Message4G()
    msg_proper.from_text(msg_4g_from_text[2].split("\n"))
    if xdr.matches(msg_proper):
        xdr.add_msg(msg_proper)
    x2_msg = Message4G()
    x2_msg.from_text(msg_4g_from_text[5].split("\n"))
    assert xdr.matches(x2_msg)
    xdr2 = XDR4G(x2_msg)
    assert xdr2.matches(msg)

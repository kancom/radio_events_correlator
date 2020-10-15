import itertools
import re
import sys
from datetime import datetime

__all__ = ["XDR", "Message"]
bounds = ("{", "}")
TS_FORMAT = "%H:%M:%S.%f"
# [650500] INTERNAL_PER_RADIO_UE_MEASUREMENT_TA(3108) @ 06:19:51.247 {
re_msg_nm = re.compile(r"\[[\d]+\]\W([^\(]+)\([\d]+\)\W@\W([\d:\.]+)\W{")
# ENBS1APID: 271461
re_keywords = {}
for keyword in (
    "ENBS1APID",
    "GLOBAL_CELL_ID",
    "TRACE_RECORDING_SESSION_REFERENCE",
    "CRNTI",
):
    re_keywords[keyword] = re.compile(rf"\W+{keyword}:\W([\d]+)")

re_l3 = re.compile(r"\W+L3\[[^\]]+\]:\W([0-9a-f]+)")
re_l3_value = re.compile(r'value="([^"]+)')

NULL_ENB = 8388608
NULL_MME = 2147483648
T1 = 60
I1 = 300


DATE_CACHE = {}


X2_HND_REQ = "X2_HANDOVER_REQUEST"
MODE = 4
CORR_RULES = {4: {X2_HND_REQ: ("enb",)}}
EXTRACT_RULES = {
    4: {
        "tmsi": {
            "RRC_RRC_CONNECTION_SETUP_COMPLETE": ("gsm_a.tmsi", "nas_eps.emm.m_tmsi"),
            "S1_INITIAL_UE_MESSAGE": ("s1ap.m_TMSI",),
            "RRC_RRC_CONNECTION_RECONFIGURATION": ("nas_eps.emm.m_tmsi",),
            "RRC_RRC_CONNECTION_REQUEST": ("lte-rrc.m_TMSI",),
            "S1_INITIAL_CONTEXT_SETUP_REQUEST": ("nas_eps.emm.m_tmsi",),
        }
    }
}


class Message:
    def __init__(self):
        self.NAME = None
        self.TIMESTAMP = None
        self.ENBS1APID = None
        self.GLOBAL_CELL_ID = None
        self.TRACE_RECORDING_SESSION_REFERENCE = None
        self.CRNTI = None
        self.BODY = None
        self.l3 = None

    def __eq__(self, other):
        return self.BODY[50:] == other.BODY[50:]

    def __str__(self):
        return (
            f"{self.NAME:>45} @ {self.TIMESTAMP}: {self.GLOBAL_CELL_ID}\t"
            f"e:{self.ENBS1APID}\tt:{self.TRACE_RECORDING_SESSION_REFERENCE}\t"
            f"c:{self.CRNTI}"
        )

    def matches(self, gci=None, enbid=None, trsr=None, crnti=None):
        result = True
        if gci is not None:
            result &= gci == self.GLOBAL_CELL_ID
        if crnti is not None and self.CRNTI is not None:
            result &= crnti == self.CRNTI
        if enbid is not None and self.ENBS1APID is not None:
            result &= enbid == self.ENBS1APID
        if trsr is not None and self.TRACE_RECORDING_SESSION_REFERENCE is not None:
            result &= trsr == self.TRACE_RECORDING_SESSION_REFERENCE
        return result

    def __repr__(self):
        return self.__str__()

    def from_text(self, strings, l3=False):
        # self.reset()
        body = False
        for line in strings:
            if bounds[0] in line:
                mo = re_msg_nm.match(line)
                if mo:
                    body = True
                    self.BODY = ""
                    self.NAME = mo.group(1)
                    self.TIMESTAMP = mo.group(2)
            if body:
                if bounds[1] in line:
                    return
                self.BODY += line
                for k, v in re_keywords.items():
                    mo = v.search(line)
                    if mo:
                        val = int(mo.group(1))
                        if (
                            k in ("ENBS1APID", "TRACE_RECORDING_SESSION_REFERENCE")
                            and val == NULL_ENB
                        ):
                            continue
                        setattr(self, k, val)
                if (l3) and "L3" in line:
                    mo = re_l3.match(line)
                    if mo:
                        self.l3 = mo.group(1)

    def __lt__(self, other):
        return self.TIMESTAMP < other.TIMESTAMP


def parse_ts(ts: str):
    if ts in DATE_CACHE:
        return DATE_CACHE[ts]
    try:
        result = datetime.strptime(ts, TS_FORMAT)
    except:
        result = datetime.strptime(ts, "%H:%M:%S")
    DATE_CACHE[ts] = result
    return result


class XDR:
    def __init__(self, msg: Message):
        self.enb = msg.ENBS1APID
        self.crnti = msg.CRNTI
        self.trsr = msg.TRACE_RECORDING_SESSION_REFERENCE
        self.gci = msg.GLOBAL_CELL_ID
        self.ts_begin = parse_ts(msg.TIMESTAMP)
        self.ts_end = self.ts_begin
        self.metas = []
        self.messages = [msg]
        self.tmsi = None

    def is_closed(self, last_ts: str):
        result = (parse_ts(last_ts) - self.ts_end).total_seconds() > T1
        return result

    def merge(self, other):
        for msg in other.messages:
            self.add_msg(msg)
        for meta in other.metas:
            self.add_meta(meta)
        if self.tmsi is None:
            self.tmsi = other.tmsi

    def matches(self, item: Message):
        key_match: bool = False
        if self.gci == item.GLOBAL_CELL_ID:
            key_match = True
            if item.ENBS1APID is not None and self.enb is not None:
                if (item.NAME not in CORR_RULES[4]) or (
                    item.NAME in CORR_RULES[4] and "enb" in CORR_RULES[4][item.NAME]
                ):
                    key_match &= self.enb == item.ENBS1APID
                if len(self.messages) == 1 and self.messages[0].NAME == X2_HND_REQ:
                    pass
                elif (item.NAME not in CORR_RULES[4]) or (
                    item.NAME in CORR_RULES[4] and "trsr" in CORR_RULES[4][item.NAME]
                ):
                    key_match &= self.trsr == item.TRACE_RECORDING_SESSION_REFERENCE
            elif item.CRNTI is not None and self.crnti is not None:
                key_match &= self.crnti == item.CRNTI
            else:
                # print("neither crnti nor enbs1apid are filled\n" f"{self}\n{item}")
                return
        if key_match and self.ts_begin is not None and self.ts_end is not None:
            new_ts = parse_ts(item.TIMESTAMP)
            if self.ts_begin < new_ts < self.ts_end:
                return key_match
            if new_ts >= self.ts_end and (new_ts - self.ts_end).total_seconds() < I1:
                return key_match
            if (
                new_ts <= self.ts_begin
                and (self.ts_begin - new_ts).total_seconds() < I1
            ):
                return key_match

    def add_msg(self, msg: Message, meta=None):
        if msg in self.messages:
            print("same message")
            return
        if msg.TRACE_RECORDING_SESSION_REFERENCE is not None:
            if self.trsr is not None:
                # if msg.TRACE_RECORDING_SESSION_REFERENCE != self.trsr:
                #     print(self, msg)
                assert msg.TRACE_RECORDING_SESSION_REFERENCE == self.trsr
            self.trsr = msg.TRACE_RECORDING_SESSION_REFERENCE
        if msg.ENBS1APID is not None:
            if self.enb is not None:
                # if self.enb != msg.ENBS1APID:
                #     breakpoint()
                assert self.enb == msg.ENBS1APID
            self.enb = msg.ENBS1APID
        if msg.CRNTI is not None:
            if self.crnti is None:
                self.crnti = msg.CRNTI
        self.ts_end = max(self.ts_end, parse_ts(msg.TIMESTAMP))
        self.messages.append(msg)
        if not meta:
            return
        for meta_id in EXTRACT_RULES[MODE]:
            # meta_id=='imsi'
            if msg.NAME in EXTRACT_RULES[MODE][meta_id]:
                ws_filters = EXTRACT_RULES[MODE][meta_id][msg.NAME]
                value = None
                for line, ws_filter in itertools.product(meta.split("\n"), ws_filters):
                    if ws_filter in line:
                        mo = re_l3_value.search(line)
                        if mo:
                            value = mo.group(1)
                if value:
                    try:
                        value = int("0x" + value, 16)
                    except:
                        value = int(value)
                    self_val = getattr(self, meta_id)
                    if self_val is not None:
                        if self_val != value:
                            print(
                                f"replacing {meta_id}. old: {self_val},"
                                f"new: {value}",
                                file=sys.stderr,
                            )
                        # assert self_val == value
                    else:
                        setattr(self, meta_id, value)

    def add_meta(self, metas: str):
        if metas not in self.metas:
            self.metas.append(metas)

    def __str__(self):
        result = self.__repr__()
        result += ",".join(self.metas) + "\n"
        for msg in sorted(self.messages):
            result += "\t" + str(msg) + "\n"
        return result

    def __repr__(self):
        ts_begin = self.ts_begin.strftime(TS_FORMAT)
        ts_end = self.ts_end.strftime(TS_FORMAT)
        result = (
            f"{ts_begin} -- {ts_end}({len(self.messages)}): {self.tmsi}\t\t"
            f"{self.gci}\t{self.enb}\t{self.trsr}\t{self.crnti}\n"
        )
        return result

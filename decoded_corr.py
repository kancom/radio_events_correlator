import argparse
import concurrent.futures
import csv
import itertools
import multiprocessing
import pathlib
import pipes
import re
import sys
import tempfile
from datetime import datetime
from typing import List

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
DLT_FILE = "dlt.csv"
DLTs = {}
L3_LOOK_FOR = ("tmsi", "imsi", "imei", "teid")
bounds = ("{", "}")
T1 = 60
I1 = 300
MODE = 4
NULL_ENB = 8388608
NULL_MME = 2147483648
X2_HND_REQ = "X2_HANDOVER_REQUEST"
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
DATE_CACHE = {}
TSHARK_CACHE = {}
DECODING_CACHE_SZ = 10
DECODING_CACHE = {}


def get_vcpu_nb():
    # hope not on restricted cpu usage)
    # return len(os.sched_getaffinity(0))
    return multiprocessing.cpu_count()


CPU_NB = get_vcpu_nb()
CPU_RATIO = 2 / 3


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

    def __repr__(self):
        return self.__str__()

    def parse_message(self, fl, l3=False):
        # self.reset()
        body = False
        for line in fl:
            if bounds[0] in line:
                mo = re_msg_nm.match(line)
                if mo:
                    body = True
                    msg = Message()
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
        result = datetime.strptime(ts, "%H:%M:%S.%f")
    except:
        result = datetime.strptime(ts, "%H:%M:%S")
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
                assert msg.TRACE_RECORDING_SESSION_REFERENCE == self.trsr
            self.trsr = msg.TRACE_RECORDING_SESSION_REFERENCE
        if msg.ENBS1APID is not None:
            if self.enb is not None:
                if self.enb != msg.ENBS1APID:
                    breakpoint()
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
        for msg in self.messages:
            result += "\t" + str(msg) + "\n"
        return result

    def __repr__(self):
        result = (
            f"{self.ts_begin} -- {self.ts_end}({len(self.messages)}): {self.tmsi}\t\t"
            f"{self.gci}\t{self.enb}\t{self.trsr}\t{self.crnti}\n"
        )
        return result


XDRs: List[XDR] = []


def decode_l3_short(msg: Message):
    return decode_l3(msg)


def decode_l3_full(msg: Message):
    return decode_l3(msg, True)


def decode_l3(msg: Message, fulldecode: bool = False):
    if msg.l3 is None:
        return
    p = t = None
    if msg.NAME in TSHARK_CACHE:
        p, t = TSHARK_CACHE[msg.NAME]
    else:
        p = pipes.Template()
        p.append("xxd -r -p", "--")
        p.append("od -Ax -tx1", "--")
        p.append("text2pcap -a -l 147 -n - - 2>/dev/null", "--")
        dlt = DLTs.get(msg.NAME, "s1ap") if "X2" not in msg.NAME else "x2ap"
        tshark_cmd = (
            'tshark -n -o \'uat:user_dlts:"User 0 (DLT=147)","'
            + dlt
            + '","0","","0",""\' -V -T pdml -r - 2>&1'
        )
        p.append(tshark_cmd, "--")
        if not fulldecode:
            grep_cmd = 'grep -iP "' + "|".join(L3_LOOK_FOR) + '"'
            p.append(grep_cmd, "--")

        t = tempfile.NamedTemporaryFile(mode="w")
        TSHARK_CACHE[msg.NAME] = p, t
    t.write(msg.l3)
    t.flush()

    f = p.open(t.name, "r")
    result = f.read()
    # t.close()
    return result


def correlate(msg: Message, func=None):
    matches = []
    meta = None  # if func is None else func(msg)
    for idx, xdr in enumerate(XDRs):
        if not xdr.is_closed(msg.TIMESTAMP) and xdr.matches(msg):
            matches.append(idx)
    if len(matches) > 0:
        if len(matches) > 1:
            print("merge required")
            for idx in matches[1:]:
                XDRs[matches[0]].merge(XDRs[idx])
            for idx in matches[-1:0:-1]:
                del XDRs[idx]
        XDRs[matches[0]].add_msg(msg, meta)
        if meta:
            XDRs[matches[0]].add_meta(f"{msg.NAME}: {meta}")
    else:
        XDRs.append(XDR(msg))
        if meta:
            XDRs[-1].add_meta(f"{msg.NAME}: {meta}")


def load_dlt(csv_file):
    with open(csv_file) as c_file:
        reader = csv.DictReader(c_file)
        for row in reader:
            DLTs[row["name"]] = row["dlt"]
    assert len(DLTs) > 1


def main(args):
    parser = argparse.ArgumentParser(description="correlate text file")
    for key in ("crnti", "enbs1apid", "trsr", "tmsi"):
        parser.add_argument(f"--{key}", dest=key, type=int, action="store")
    parser.add_argument("--file", nargs="+", dest="file", action="store", required=True)
    parser.add_argument("--gci", dest="gci", type=int, action="store")
    parser.add_argument("-f", dest="filter", action="store_true")
    parser.add_argument("--headers", dest="headers", action="store_true")
    parser.add_argument("--sorted", dest="sorted", action="store_true")
    parser.add_argument("--correlate", dest="correlate", action="store_true")
    parser.add_argument("--l3", dest="l3", action="store_true")
    parser.add_argument("--fulldecode", dest="fulldecode", action="store_true")

    parsed = parser.parse_args(args)
    parsed.l3 = parsed.l3 or parsed.fulldecode
    # func = None
    # if parsed.fulldecode:
    #     func = decode_l3_full
    # elif parsed.l3:
    #     func = decode_l3_short
    dlt_file = pathlib.Path(DLT_FILE)
    fl_nb = len(parsed.file)
    for in_file in parsed.file:
        results = []
        msg = Message()
        print(in_file, fl_nb)
        in_file = pathlib.Path(in_file)
        assert in_file.exists()
        if parsed.l3:
            assert dlt_file.exists()
            load_dlt(dlt_file)
        fl = open(in_file, "r")
        msg.parse_message(fl, l3=parsed.l3 or parsed.fulldecode)
        while msg.NAME is not None:
            filtered = True
            if parsed.gci is not None:
                filtered &= parsed.gci == msg.GLOBAL_CELL_ID
            if msg.CRNTI is not None and parsed.crnti is not None:
                filtered &= parsed.crnti == msg.CRNTI
            if msg.ENBS1APID is not None and parsed.enbs1apid is not None:
                filtered &= parsed.enbs1apid == msg.ENBS1APID
            if (
                msg.TRACE_RECORDING_SESSION_REFERENCE is not None
                and parsed.trsr is not None
            ):
                filtered &= parsed.trsr == msg.TRACE_RECORDING_SESSION_REFERENCE
            if filtered:
                results.append(msg)
                ts = msg.TIMESTAMP
                DATE_CACHE[ts] = parse_ts(ts)
            msg = Message()
            msg.parse_message(fl, l3=parsed.l3 or parsed.fulldecode)
        if parsed.sorted or parsed.correlate:
            results = sorted(results)
        if not parsed.correlate:
            for msg in results:
                if parsed.headers:
                    print(msg)
                else:
                    print(msg.BODY)
        else:
            msg_nb: int = len(results)
            with concurrent.futures.ProcessPoolExecutor(
                max_workers=int(CPU_NB * CPU_RATIO)
            ) as executor:
                for _ in executor.map(correlate, results):
                    print(f"{fl_nb} {msg_nb} left")
                    msg_nb -= 1

        fl_nb -= 1
    if parsed.correlate:
        for idx, xdr in enumerate(XDRs):
            if (parsed.tmsi and parsed.tmsi == xdr.tmsi) or (not parsed.tmsi):
                print(idx, xdr)
    print("Nb of messages: ", len(results))


if __name__ == "__main__":
    ts_start = datetime.now()
    main(sys.argv[1:])
    print("Execution time", datetime.now() - ts_start)

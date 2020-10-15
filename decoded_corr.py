import argparse
import concurrent.futures
import csv
import multiprocessing as mp
import pathlib
import pipes
import sys
import tempfile
from datetime import datetime
from typing import List

from classes import XDR, Message, parse_ts

DLT_FILE = "dlt.csv"
DLTs = {}
L3_LOOK_FOR = ("tmsi", "imsi", "imei", "teid")
TSHARK_CACHE = {}
DECODING_CACHE_SZ = 10
DECODING_CACHE = {}
XDRs: List[XDR] = []


def get_vcpu_nb():
    # hope not on restricted cpu usage)
    # return len(os.sched_getaffinity(0))
    return mp.cpu_count()


CPU_NB = get_vcpu_nb()
JOBS_NB = int(2 / 3 * CPU_NB)


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


def correlate(msgs: List[Message]):
    matches = []
    xdrs: List[XDR] = []
    print("Nb of msgs:", len(msgs))
    for msg in msgs:
        for idx, xdr in enumerate(xdrs):
            if not xdr.is_closed(msg.TIMESTAMP) and xdr.matches(msg):
                matches.append(idx)
        if len(matches) > 0:
            if len(matches) > 1:
                print("merge required")
                for idx in matches[1:]:
                    xdrs[matches[0]].merge(xdrs[idx])
                for idx in matches[-1:0:-1]:
                    del xdrs[idx]
            xdrs[matches[0]].add_msg(msg)
        else:
            xdrs.append(XDR(msg))
        del matches[:]
    return xdrs


def load_dlt(csv_file):
    with open(csv_file) as c_file:
        reader = csv.DictReader(c_file)
        for row in reader:
            DLTs[row["name"]] = row["dlt"]
    assert len(DLTs) > 1


def parse_argsuments(args):
    parser = argparse.ArgumentParser(description="correlate text file")
    for key in ("crnti", "enbid", "trsr", "tmsi"):
        parser.add_argument(f"--{key}", dest=key, type=int, action="store")
    parser.add_argument("--file", nargs="+", dest="file", action="store", required=True)
    parser.add_argument("--gci", dest="gci", type=int, action="store")
    parser.add_argument("--headers", dest="headers", action="store_true")
    parser.add_argument("--sorted", dest="sorted", action="store_true")
    parser.add_argument("--correlate", dest="correlate", action="store_true")
    parser.add_argument("--l3", dest="l3", action="store_true")
    parser.add_argument("--fulldecode", dest="fulldecode", action="store_true")
    return parser.parse_args(args)


def main(args):
    parsed = parse_argsuments(args)
    parsed.l3 = parsed.l3 or parsed.fulldecode
    if parsed.l3:
        dlt_file = pathlib.Path(DLT_FILE)
        assert dlt_file.exists()
        load_dlt(dlt_file)
    quenue = [[] for x in range(JOBS_NB)]
    fl_nb = len(parsed.file) + 1
    results = []
    for in_file in parsed.file:
        fl_nb -= 1
        msg = Message()
        print(in_file, fl_nb)
        in_file = pathlib.Path(in_file)
        assert in_file.exists()
        fl = open(in_file, "r")
        msg.from_text(fl, l3=parsed.l3 or parsed.fulldecode)
        while msg.NAME is not None:
            filtered = msg.matches(
                gci=parsed.gci, enbid=parsed.enbid, trsr=parsed.trsr, crnti=parsed.crnti
            )
            if filtered:
                if parsed.correlate:
                    quenue[msg.GLOBAL_CELL_ID % JOBS_NB].append(msg)
                else:
                    results.append(msg)
                ts = msg.TIMESTAMP
                parse_ts(ts)
            msg = Message()
            msg.from_text(fl, l3=parsed.l3 or parsed.fulldecode)

        if parsed.correlate:
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for xdrs in executor.map(correlate, quenue):
                    XDRs.extend(xdrs)
                    # print(f"{fl_nb} {msg_nb} left")
                    # msg_nb -= 1
            func = None
            if parsed.fulldecode:
                func = decode_l3_full
            elif parsed.l3:
                func = decode_l3_short
            else:
                continue
            xdr_nb = sum([len(x) for x in quenue])

            for xdr in XDRs:
                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=JOBS_NB
                ) as executor:
                    for msg, meta in zip(
                        xdr.messages, executor.map(func, xdr.messages)
                    ):
                        if meta is not None:
                            xdr.add_meta(f"{msg.NAME}: {meta}")
                        print(f"l3 decoding. {len(xdr.messages)} {xdr_nb} left")
                        xdr_nb -= 1
    if parsed.correlate:
        for idx, xdr in enumerate(XDRs):
            if (parsed.tmsi and parsed.tmsi == xdr.tmsi) or (not parsed.tmsi):
                print(idx, xdr)
    else:
        if parsed.sorted:
            results = sorted(results)
        for msg in results:
            if parsed.headers:
                print(msg)
            else:
                print(msg.BODY)
    print("Nb of messages: ", sum([len(x) for x in quenue]))
    for _, t in TSHARK_CACHE.values():
        t.close()


if __name__ == "__main__":
    ts_start = datetime.now()
    main(sys.argv[1:])
    print("Execution time", datetime.now() - ts_start)

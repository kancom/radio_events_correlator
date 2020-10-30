import argparse
import concurrent.futures
import csv
import gzip
import multiprocessing as mp
import pathlib
import pipes
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from typing import List

from correlator.classes import (XDR, XDR3G, XDR4G, Message, Message3G,
                                Message4G, XDR_scenario)

DLT_FILE = "dlt.csv"
DLTs = {}
L3_LOOK_FOR = ("tmsi", "imsi", "imei", "teid")
XDRs: List[XDR] = []

# smm = Manager()
# TSHARK_CACHE = smm.dict()


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
    if False and msg.name in TSHARK_CACHE:
        p = TSHARK_CACHE[msg.name]
    else:
        p = pipes.Template()
        p.append("xxd -r -p", "--")
        p.append("od -Ax -tx1", "--")
        p.append("text2pcap -a -l 147 -n - - 2>/dev/null", "--")
        dlt = DLTs.get(msg.name, "s1ap") if "X2" not in msg.name else "x2ap"
        tshark_cmd = (
            'tshark -n -o \'uat:user_dlts:"User 0 (DLT=147)","'
            + dlt
            + '","0","","0",""\' -V -T pdml -r - 2>&1'
        )
        p.append(tshark_cmd, "--")
        if not fulldecode:
            grep_cmd = 'grep -iP "' + "|".join(L3_LOOK_FOR) + '"'
            p.append(grep_cmd, "--")

        # TSHARK_CACHE[msg.name] = p
    t = tempfile.NamedTemporaryFile(mode="w")
    t.write(msg.l3)
    t.flush()

    f = p.open(t.name, "r")
    result = f.read()
    t.close()
    return result


def correlate(msgs: List[Message]):
    matches = []
    xdrs: List[XDR] = []
    if len(msgs) > 0:
        XDR_ = XDR4G if isinstance(msgs[0], Message4G) else XDR3G
    print("Nb of msgs:", len(msgs), file=sys.stderr)
    for msg in msgs:
        for idx, xdr in enumerate(xdrs):
            if not xdr.is_closed(msg.timestamp) and xdr.matches(msg):
                matches.append(idx)
        if len(matches) > 0:
            if len(matches) > 1:
                # print("merge required", file=sys.stderr)
                for idx in matches[1:]:
                    xdrs[matches[0]].merge(xdrs[idx])
                for idx in matches[-1:0:-1]:
                    del xdrs[idx]
            xdrs[matches[0]].add_msg(msg)
        else:
            xdrs.append(XDR_(msg))
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
    for key in ("crnti", "enbid", "trsr", "tmsi", "ueid", "rncmodid", "scenario"):
        parser.add_argument(f"--{key}", dest=key, type=int, action="store")
    parser.add_argument("--file", nargs="+", dest="file", action="store", required=True)
    parser.add_argument("--gci", dest="gci", type=int, action="store")
    parser.add_argument("--headers", dest="headers", action="store_true")
    parser.add_argument("--sorted", dest="sorted", action="store_true")
    parser.add_argument("--correlate", dest="correlate", action="store_true")
    parser.add_argument("--l3", dest="l3", action="store_true")
    parser.add_argument("--fulldecode", dest="fulldecode", action="store_true")
    parser.add_argument("--stat", dest="stat", action="store_true")
    parser.add_argument(
        "-g", dest="tech", action="store", choices=("3G", "4G"), default="4G"
    )
    return parser.parse_args(args)


def main(args):
    parsed = parse_argsuments(args)
    if parsed.tech == "4G":
        XDR_ = XDR4G
        Message_ = Message4G
    else:
        XDR_ = XDR3G
        Message_ = Message3G
    parse_ts = XDR_.parse_ts

    parsed.l3 = parsed.l3 or parsed.fulldecode
    if parsed.l3:
        dlt_file = pathlib.Path(DLT_FILE)
        assert dlt_file.exists()
        load_dlt(dlt_file)
    quenue = [[] for x in range(JOBS_NB)]
    fl_nb = len(parsed.file) + 1
    results = []
    scenarios = XDR_scenario()
    scenarios.load_persistent()
    for in_file in parsed.file:
        fl_nb -= 1
        msg = Message_()
        print(in_file, fl_nb, file=sys.stderr)
        in_file = pathlib.Path(in_file)
        assert in_file.exists()
        if in_file.suffix == ".gz":
            fl = iter(gzip.open(in_file, "rt").readlines())
        else:
            fl = open(in_file, "r")
        msg.from_text(fl, l3=parsed.l3 or parsed.fulldecode)
        while msg.cardinal_field_val is not None:
            filtered = msg.matches(
                gci=parsed.gci,
                enbid=parsed.enbid,
                trsr=parsed.trsr,
                crnti=parsed.crnti,
                rncmodid=parsed.rncmodid,
                ueid=parsed.ueid,
            )
            if filtered:
                if parsed.correlate:
                    quenue[msg.cardinal_field_val % JOBS_NB].append(msg)
                else:
                    results.append(msg)
                ts = msg.timestamp
                parse_ts(ts)
            msg = Message_()
            msg.from_text(fl, l3=parsed.l3 or parsed.fulldecode)

        if parsed.correlate:
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for xdrs in executor.map(correlate, quenue):
                    if parsed.scenario:
                        xdrs = [
                            xdr
                            for xdr in xdrs
                            if scenarios.scenario_nb(xdr.get_msg_descr())
                            == parsed.scenario
                        ]
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
            msg_nb = sum([len(x) for x in quenue])

            for xdr in XDRs:
                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=JOBS_NB
                ) as executor:
                    for msg, meta in zip(
                        xdr.messages, executor.map(func, xdr.messages)
                    ):
                        if meta is not None:
                            xdr.add_meta(f"{msg.name}: {meta}")
                msg_nb -= len(xdr.messages)
                print(
                    f"l3. {len(xdr.messages)} msgs in xdr. {msg_nb} msgs in curr file left",
                    file=sys.stderr,
                )
    if parsed.correlate:
        for idx, xdr in enumerate(XDRs):
            ptrn = xdr.get_msg_descr()
            if (parsed.tmsi and parsed.tmsi == xdr.tmsi) or (not parsed.tmsi):
                print(idx, scenarios.scenario_nb(ptrn), xdr)
    else:
        if parsed.sorted:
            results = sorted(results)
        for msg in results:
            if parsed.headers:
                print(msg)
            else:
                print(msg.BODY)
    if parsed.stat:
        stats = defaultdict(int)
        for xdr in XDRs:
            ptrn = xdr.get_msg_descr()
            pos = scenarios.scenario_nb(ptrn)
            stats[pos] += 1
        for ptrn in sorted(stats, key=stats.get, reverse=True):
            print(f"pattern: {ptrn}\tnumber: {stats[ptrn]}")
    print("Nb of messages: ", sum([len(x) for x in quenue]))
    scenarios.save_persistent()


if __name__ == "__main__":
    ts_start = datetime.now()
    main(sys.argv[1:])
    print("Execution time", datetime.now() - ts_start)

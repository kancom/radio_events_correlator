import csv
import itertools
import pathlib
import re
import sys
from datetime import datetime

__all__ = ["XDR3G", "XDR4G", "Message4G", "Message3G"]
NULL_ENB = 8388608
NULL_MME = 2147483648

re_l3_value = re.compile(r'value="([^"]+)')

DATE_CACHE = {}


class Message:
    key_fields = {}
    re_l3 = re.compile(r"\W+L3\[[^\]]+\]:\W([0-9a-f]+)")
    bounds = ("{", "}")
    re_msg_nm = None

    def __init__(self):
        self.name = None
        self.timestamp = None
        self.body = None
        self.l3 = None
        self.re_keywords = {}
        for k in self.key_fields.keys():
            setattr(self, k, None)
        self.key_field = list(self.key_fields.keys())[0]

    # def __hash__(self):
    #     return self.body.__hash__()

    def __eq__(self, other):
        return self.body[50:] == other.body[50:]

    def __str__(self):
        result = f"{self.name:>45} @ {self.timestamp}: "
        for key in self.key_fields.keys():
            result += f"{key}:{getattr(self,key,None)}\t"
        return result

    def matches(self, **kwargs):
        result = True
        for key in kwargs:
            if kwargs[key] is None:
                continue
            val = getattr(self, key, None)
            if key in self.key_fields and val is not None:
                result &= kwargs[key] == val
        return result

    def __repr__(self):
        return self.__str__()

    def from_text(self, strings, l3=False):
        body = False
        for line in strings:
            if self.bounds[0] in line:
                mo = self.re_msg_nm.match(line)
                if mo:
                    body = True
                    self.body = ""
                    self.name = mo.group(1)
                    self.timestamp = mo.group(2)
            if body:
                if self.bounds[1] in line:
                    return self.cardinal_field_val is not None
                self.body += line
                for k, v in self.key_fields.items():
                    mo = v["regexp"].search(line)
                    if mo:
                        val = int(mo.group(1))
                        if k in ("enbid", "trsr") and val == NULL_ENB:
                            continue
                        setattr(self, k, val)
                if (l3) and "L3" in line:
                    mo = self.re_l3.match(line)
                    if mo:
                        self.l3 = mo.group(1)
        return self.cardinal_field_val is not None

    def __lt__(self, other):
        return self.timestamp < other.timestamp

    @property
    def cardinal_field_val(self):
        return getattr(self, self.key_field, None)


class Message4G(Message):
    # [650500] INTERNAL_PER_RADIO_UE_MEASUREMENT_TA(3108) @ 06:19:51.247 {
    re_msg_nm = re.compile(r"\[[\d]+\]\W([^\(]+)\([\d]+\)\W@\W([\d:\.]+)\W{")
    key_fields = {
        "gci": {"tag": "GLOBAL_CELL_ID", "regexp": None},
        "enbid": {"tag": "ENBS1APID", "regexp": None},
        "trsr": {"tag": "TRACE_RECORDING_SESSION_REFERENCE", "regexp": None},
        "crnti": {"tag": "CRNTI", "regexp": None},
    }

    def __init__(self):
        super().__init__()
        # ENBS1APID: 271461
        for field in self.key_fields.values():
            field["regexp"] = re.compile(rf"\W+{field['tag']}:\W([\d]+)")


class Message3G(Message):
    # [2610] INTERNAL_SOFT_HANDOVER_EXECUTION(408) @ 2020-09-21T06:37:59.790Z {
    re_msg_nm = re.compile(r"\[[\d]+\]\W([^\(]+)\([\d]+\)\W@\W([\d:\.\-TZ]+)\W{")
    key_fields = {
        "rncmodid": {"tag": "RNC_MODULE_ID", "regexp": None},
        "ueid": {"tag": "UE_CONTEXT_ID", "regexp": None},
        "rncid": {"tag": r"RNC_ID/CELL_ID\[1\]", "regexp": None},
    }

    def __init__(self):
        super().__init__()
        # UE_CONTEXT_ID: Some(512)
        # RNC_MODULE_ID: Some(0)
        # RNC_ID/CELL_ID[1]: (2241, 7079)
        for field in self.key_fields.values():
            field["regexp"] = re.compile(rf"\W+{field['tag']}:\W[^\(]*\(([\d]+)")


class XDR:
    TS_FORMAT = ("%H:%M:%S.%f", "%H:%M:%S")
    T1 = 60
    I1 = 300
    key_filter = ()
    key_fields = {}

    extract_rules = {}

    @classmethod
    def parse_ts(cls, ts: str):
        if ts in DATE_CACHE:
            return DATE_CACHE[ts]
        try:
            result = datetime.strptime(ts, cls.TS_FORMAT[0])
        except ValueError:
            result = datetime.strptime(ts, cls.TS_FORMAT[1])
        DATE_CACHE[ts] = result
        return result

    def __init__(self, msg: Message):
        self.ts_begin = self.parse_ts(msg.timestamp)
        self.ts_end = self.ts_begin
        self.metas = []
        self.messages = [msg]
        self.tmsi = None
        for field in self.key_fields.keys():
            setattr(self, field, getattr(msg, field, None))

    def is_closed(self, last_ts: str):
        result = (self.parse_ts(last_ts) - self.ts_end).total_seconds() > self.T1
        return result

    def merge(self, other):
        for msg in other.messages:
            self.add_msg(msg)
        for meta in other.metas:
            self.add_meta(meta)
        if self.tmsi is None:
            self.tmsi = other.tmsi

    def matches(self, item: Message):
        key_match: bool = True
        for field in self.key_filter:
            key_match &= getattr(self, field, None) == getattr(item, field, None)

        if key_match and self.ts_begin is not None and self.ts_end is not None:
            new_ts = self.parse_ts(item.timestamp)
            if self.ts_begin < new_ts < self.ts_end:
                return True
            if (
                new_ts >= self.ts_end
                and (new_ts - self.ts_end).total_seconds() < self.I1
            ):
                return True
            if (
                new_ts <= self.ts_begin
                and (self.ts_begin - new_ts).total_seconds() < self.I1
            ):
                return True
        return False

    def add_msg(self, msg: Message, meta=None):
        if msg in self.messages:
            # print("same message", file=sys.stderr)
            return
        for field, attr in self.key_fields.items():
            s_v = getattr(self, field, None)
            o_v = getattr(msg, field, None)
            if o_v is not None:
                if s_v is not None and attr["strict"]:
                    assert s_v == o_v
                setattr(self, field, o_v)
        self.ts_end = max(self.ts_end, self.parse_ts(msg.timestamp))
        self.messages.append(msg)

        if not meta:
            return
        for meta_id in self.extract_rules:
            # meta_id=='imsi'
            if msg.name in self.extract_rules[meta_id]:
                ws_filters = self.extract_rules[meta_id][msg.name]
                value = None
                for line, ws_filter in itertools.product(meta.split("\n"), ws_filters):
                    if ws_filter in line:
                        mo = re_l3_value.search(line)
                        if mo:
                            value = mo.group(1)
                if value:
                    try:
                        value = int("0x" + value, 16)
                    except ValueError:
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
            self.metas.append(metas + "\n")

    def __str__(self):
        result = self.__repr__()
        result += ",".join(self.metas) + "\n"
        for msg in sorted(self.messages):
            result += "\t" + str(msg) + "\n"
        return result

    def __repr__(self):
        ts_begin = self.ts_begin.strftime(self.TS_FORMAT[0])
        ts_end = self.ts_end.strftime(self.TS_FORMAT[0])
        result = f"{ts_begin} -- {ts_end}({len(self.messages)}): {self.tmsi}\t\t"
        for key in self.key_fields.keys():
            result += f"{key}:{getattr(self,key,None)}\t"
        return result + "\n"

    def get_msg_descr(self):
        return set(
            sorted(
                [
                    msg.name
                    for msg in self.messages
                    if not msg.name.startswith("INTERNAL")
                ]
            )
        )


class XDR3G(XDR):
    # 2020-09-21T06:37:59.790Z
    TS_FORMAT = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
    key_filter = ("rncmodid", "ueid")
    key_fields = {
        "rncid": {"strict": False},
        "rncmodid": {"strict": True},
        "ueid": {"strict": True},
    }

    def __init__(self, msg: Message3G):
        assert isinstance(msg, Message3G)
        super().__init__(msg)

    def matches(self, item: Message3G):
        assert isinstance(item, Message3G)
        key_match: bool = True
        key_match &= super().matches(item)
        return key_match


class XDR4G(XDR):
    x2_hnd_req = "X2_HANDOVER_REQUEST"
    key_filter = ("gci",)
    key_fields = {
        "gci": {"strict": True},
        "enbid": {"strict": True},
        "crnti": {"strict": False},
        "trsr": {"strict": True},
    }
    extract_rules = {
        "tmsi": {
            "RRC_RRC_CONNECTION_SETUP_COMPLETE": ("gsm_a.tmsi", "nas_eps.emm.m_tmsi"),
            "S1_INITIAL_UE_MESSAGE": ("s1ap.m_TMSI",),
            "RRC_RRC_CONNECTION_RECONFIGURATION": ("nas_eps.emm.m_tmsi",),
            "RRC_RRC_CONNECTION_REQUEST": ("lte-rrc.m_TMSI",),
            "S1_INITIAL_CONTEXT_SETUP_REQUEST": ("nas_eps.emm.m_tmsi",),
        }
    }

    def __init__(self, msg: Message4G):
        assert isinstance(msg, Message4G)
        super().__init__(msg)

    def matches(self, item: Message4G):
        assert isinstance(item, Message4G)
        key_match: bool = True
        key_match &= super().matches(item)
        if not key_match:
            return False

        if item.enbid is not None and self.enbid is not None:
            key_match &= self.enbid == item.enbid
            if (
                len(self.messages) == 1 and (self.messages[0].name == self.x2_hnd_req)
            ) or (item.name == self.x2_hnd_req):
                pass
            else:
                key_match &= self.trsr == item.trsr
        elif item.crnti is not None and self.crnti is not None:
            key_match &= self.crnti == item.crnti
        else:
            key_match = False
        return key_match


class XDR_scenario:
    persistent_name = "scenarios"
    key_nb = "number"
    key_msgs = "msgs"
    delim = ";"

    def __init__(self, file_name=None):
        self._xdr_scenarios = []
        self._file_name = file_name if file_name else self.persistent_name

    def load_persistent(self):
        path = pathlib.Path(self._file_name)
        if not path.exists():
            return
        with open(path, "r") as file_hnd:
            dict_reader = csv.DictReader(file_hnd)
            for line in dict_reader:
                self._xdr_scenarios.append(set(line[self.key_msgs].split(self.delim)))

    def save_persistent(self):
        with open(self._file_name, "w") as file_hnd:
            dict_writer = csv.DictWriter(
                file_hnd, fieldnames=[self.key_nb, self.key_msgs]
            )
            dict_writer.writeheader()
            for nb, scenario in enumerate(self._xdr_scenarios):
                dict_writer.writerow(
                    {self.key_nb: nb, self.key_msgs: self.delim.join(scenario)}
                )

    def scenario_nb(self, scenario: str) -> int:
        if scenario not in self._xdr_scenarios:
            self._xdr_scenarios.append(scenario)
        result = self._xdr_scenarios.index(scenario)
        return result

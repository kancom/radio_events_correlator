msg_4g_from_text = [
    """
}
[492] INTERNAL_PER_RADIO_UE_MEASUREMENT_TA(3108) @ 06:48:56.489 {
    SCANNER_ID: 0000000000010000000000
    RBS_MODULE_ID: EXTENSION_DU1
    GLOBAL_CELL_ID: 153979139
    ENBS1APID: 273678
    MMES1APID: 127984332
    GUMMEI: 250 - 01 - 33066 - 112
    RAC_UE_REF: 31278838
    TRACE_RECORDING_SESSION_REFERENCE: 27918
    TIMESTAMP_START: 06:48:52.488
    TA_INTERVAL: 1000 Measure(None, 1.0)
    ARRAY_TA: [<NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>, <NA>]
}
[672] INTERNAL_PER_RADIO_UE_MEASUREMENT(3075) @ 06:48:56.490 {
""",  #  1
    """
[28036] S1_INITIAL_CONTEXT_SETUP_RESPONSE(1039) @ 06:48:53.817 {
    SCANNER_ID: 0000000000010000000000
    RBS_MODULE_ID: EXTENSION_DU2
    GLOBAL_CELL_ID: 153813763
    ENBS1APID: 268687
    MMES1APID: 132170838
    GUMMEI: 250 - 01 - 33066 - 112
    RAC_UE_REF: 29443979
    TRACE_RECORDING_SESSION_REFERENCE: 22927
    L3[SENT]: 2009002700000300004005c007e0c456000840048004198f0033400f000032400a0a1f0b1a017d1aee0c16
}""",  #  2
    """
[28124] RRC_UE_CAPABILITY_ENQUIRY(10) @ 06:48:53.818 {
    SCANNER_ID: 0000000000010000000000
    RBS_MODULE_ID: EXTENSION_DU2
    GLOBAL_CELL_ID: 153813763
    ENBS1APID: 268687
    MMES1APID: 132170838
    GUMMEI: 250 - 01 - 33066 - 112
    RAC_UE_REF: 29443979
    TRACE_RECORDING_SESSION_REFERENCE: 22927
    L3[SENT]: 380040
    CRNTI: 2799 Measure(None, 1.0)
}""",  #  3
    """
[28176] RRC_RRC_CONNECTION_RECONFIGURATION_COMPLETE(13) @ 06:48:53.846 {
    SCANNER_ID: 0000000000010000000000
    RBS_MODULE_ID: EXTENSION_DU2
    GLOBAL_CELL_ID: 153813763
    ENBS1APID: 268673
    MMES1APID: 151057579
    GUMMEI: 250 - 01 - 33066 - 144
    RAC_UE_REF: 29443972
    TRACE_RECORDING_SESSION_REFERENCE: 22913
    L3[RECEIVED]: 1200
    CRNTI: 2769 Measure(None, 1.0)
}""",  #  4
    """
[28236] RRC_UE_CAPABILITY_INFORMATION(19) @ 06:48:53.934 {
    SCANNER_ID: 0000000000010000000000
    RBS_MODULE_ID: EXTENSION_DU2
    GLOBAL_CELL_ID: 153813763
    ENBS1APID: 268687
    MMES1APID: 132170838
    GUMMEI: 250 - 01 - 33066 - 112
    RAC_UE_REF: 29443979
    TRACE_RECORDING_SESSION_REFERENCE: 22927
    L3[RECEIVED]: 380115240002740caab541a955aa22920c112000600054284251cfb9a6bb65ca128e7dcd35db2f509473ee69aed96073cf5c4109c38f5d0cd35db2d001901d01bd5a60000cd24b7a4491b30600850e2468f4f2e7d800
    CRNTI: 2799 Measure(None, 1.0)
}

""",  #  5
    """
[1068] X2_HANDOVER_REQUEST(2058) @ 06:48:53.827 {
    SCANNER_ID: 0000000000010000000000
    RBS_MODULE_ID: EXTENSION_DU2
    GLOBAL_CELL_ID: 153813763
    ENBS1APID: 268687
    MMES1APID: 132170838
    GUMMEI: 250 - 01 - 33066 - 112
    RAC_UE_REF: 181330159
    TRACE_RECORDING_SESSION_REFERENCE: 8388608
    L3[SENT]: 0000008216000008000a000204c3000540020000000b00080052f01092a0e160001700070052f010812a70000e0081c52410a7ed1c000e0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0312c000006012c00000000004400e4500080501f00ae761188313227981790a3031c59ad45001060e4d3858bf8dfe2fe37f8bf8dfe2fe37f8bf8dfe2fe37fffcffebe88100870ca74a93bbe069c08000006c01534001a2f8c903841a980c21a8250112000600054184231ee65a6bb7a8463dccb4d76c0679bb88212875d0ccb4d76c801d01f30ab4c000dda497f48c337ea15021468f4f3eb5021468f4f3d0a810a347a79f7b2420f33035758b2601434e2918100123e8095d80004032f8df003601083041160c26e206d850eb0c2461c76e40f1c9223545272cb0c6201ad4335c9a73d36d82919160ba4ea64dd8da3b9957eced4b65e98cc565b9be3b59066f22ce6619dd8b3dbb77f8ad10014804acb8408f99d0dc40638df0dc40000200880272a64037b03ffa9c0b83ffa9c083ea26607d7538a1c88cf9806ee320690f9563ff854d618721c381216ca10b5fa1982e0903f1d4000000928007444f2541c2b040430103089846c246a13256fd92958460390001800040044162fd4aaf06a00328030073740074197c2c00f0559c4b37700012045f0400052f010000f400c000052f01092a0e1500000010024400100a8dd400d000001103f40061c00ff653801
    SEND_GENBID: [0, 82, 240, 16, 146, 160, 224, 0]
    RECV_GENBID: [0, 82, 240, 16, 146, 160, 224, 0]
}
""",
]
msg_3g_from_text = [
    """
[1516] RANAP_RELOCATION_REQUEST(275) @ 2020-09-21T06:37:59.758Z {
    scanners: 000000000000000010000000
    UE_CONTEXT_ID: Some(4107)
    RNC_MODULE_ID: Some(0)
    RNC_ID/CELL_ID[1]: (2241, 38327)
    RNC_ID/CELL_ID[2]: <NA>
    RNC_ID/CELL_ID[3]: <NA>
    RNC_ID/CELL_ID[4]: <NA>
    PDU_TYPE: PduType::UNAVAILABLE
    PROTOCOL_ID: ProtocolId::RANAP(2)
    L3[RECEIVED]: 00030081fa400008001740095052002116592233f7000440020a000003000180003d00815000a081291833035758b25300a1a7148c080091f4010cf200405c86481c20d4c0610d412808900030002a1c2138e7cf732d35db94271cf9ee65a6bb7
884e39f3dccb4d76f509c73e7b9969aedb3d0127c410a438f4eba19969aedb003203803a03e82ad3001046925fd631cdfc8740830a1c48d1e9dbc397367d18f40830a1c48d1e9dbc397367d1a740830a1c48d1e9dbc397367d1af40830a1c48d1e9dbc397367d143a04
1850e2468f4ede1cb9b3e8fed2d49005376c99a04d000820610307266d0a54c9d40d9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ff9bfff91ffffcffebe882002321
c329d2a4eefc2e702000001f6b70000000002b800800018b2040084a000103808c195b7000000c8401817100052f01092c051500000010052f010927c815000000700310041000001002f003a34144504f423ff802ee0000918000000b10005600e4e1bff00000043e0
d557443d0080fb202d0001005940095000000000ad40010000ee400100000c40120808b187a811fa3b7429df434c32f083094e000b40120080d4f37bbfe400cdb86a72949933ed9378004f40039d31c300010060000552f010029b007f400352f010
}""",
    """
[2063] NBAP_RADIO_LINK_SETUP_REQUEST(128) @ 2020-09-21T06:37:59.759Z {
    scanners: 000000000000000010000000
    UE_CONTEXT_ID: Some(4107)
    RNC_MODULE_ID: Some(0)
    RNC_ID/CELL_ID[1]: (2241, 38327)
    RNC_ID/CELL_ID[2]: <NA>
    RNC_ID/CELL_ID[3]: <NA>
    RNC_ID/CELL_ID[4]: <NA>
    PDU_TYPE: PduType::UNAVAILABLE
    PROTOCOL_ID: ProtocolId::NBAP(1)
    L3[SENT]: 001b22114681fa400004002c00020000012700180900b02406b700000140541105fa207a00000002a80001800038002100080028000200001f000000005114e5340a0001000050000100945114e534f02000d880770000d38072040095b700063200000000200140014f00c800020067401c00c01f20fc324f803500010a6ca8010000000000000000000000000002a200010002ae4035016240fc324f803500010a6ca801000000000000000000000000006440faf34f803500010a6ca8010000000000000000000000000000090212008089585c1e10fe404f803500010a6ca801000000000000000000000000000000026840020a00727840fc034f803500010a6ca8010000000000000000000000000000000268400200402e0791a4200d48010000930000000362000300001152488d2008014f0000000362000300012f068000001804295c0002036100018003b3400100043d40048000000002170002577d021d00010002a5000a12280243f13e60a00100029b005e202e278140e0000000a7990f8000000000000362000300001123f00000000000000362000300001125f00000000000000362000300001127f000000000000003620003000011723c0047000c0c140000000000000362000300005100166e02a7000200000278000200080336000100fc17400100fc1b40100008c10008c1402406400040100b0000
}""",
    """
[2610] INTERNAL_SOFT_HANDOVER_EXECUTION(408) @ 2020-09-21T06:37:59.790Z {
    scanners: 000000000000000000100000
    UE_CONTEXT_ID: Some(512)
    RNC_MODULE_ID: Some(0)
    RNC_ID/CELL_ID[1]: (2241, 7079)
    RNC_ID/CELL_ID[2]: (2241, 3939)
    RNC_ID/CELL_ID[3]: <NA>
    RNC_ID/CELL_ID[4]: <NA>
    EVENT_TRIGGER: ADD_CELL_PROPOSAL (21)
    C_ID_EVALUATED: 7079 Measure(None, 1.0)
    RNC_ID_EVALUATED: 2241 Measure(None, 1.0)
    CPICH_EC_NO_EVAL_CELL: 33 Measure(DeciBel, 0.5)
    RSCP_EVAL_CELL: 25 Measure(DeciBelMilliWatt, 1.0)
    HANDOVER_TYPE: ADD_CELL_PROPOSAL_ACT (0)
    RESULT: SUCCESS (0)
    FAILURE_REASON: <NA>
    SOURCE_CONNECTION_PROPERTIES: 34588 Measure(None, 1.0)
    SOURCE_C_ID_1_SECONDARY_SERV_HSDSCH_CELL: 23939 Measure(None, 1.0)
    SOURCE_CONNECTION_PROPERTIES_EXT: 0 Measure(None, 1.0)
    ANR_INITIATED: <NA>
    SOURCE_C_ID_2_SECONDARY_SERV_HSDSCH_CELL: <NA>
    SOURCE_CONF: 25 Measure(None, 1.0)
""",
]
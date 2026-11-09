"""Exact stock builds with the verified RSA public-root block protocol.

Static discovery is retained in analysis/reports/core-spec-discovery.json.
Eligibility for isolated deployment is separate from browser acceptance.
"""

CORE_SPECS = {
    '104': {
        'resource_root': {'file': '104.0.5112.133/resources.pak', 'id': 19002, 'offset': 2689055, 'length': 372, 'key_offset': 78, 'sha256': '88f1bae169ac14c7f45a2eb8fc3bb6abe26776052ba54d68ccc41a0f94d3ee5b'},
        'sha256': '6cf65b4a3400d6bb4512a4c5df6209a9d337a552333688d7c716b87bc5c3bb6f',
        'offset': 0xb1678e9,
        'seeds': (0x5c02b26b5aed03c7, 0xf5aeabaf49b6ecfe),
    },
    '112': {
        'resource_root': {'file': '112.0.5615.215/resources.pak', 'id': 21002, 'offset': 2796987, 'length': 352, 'key_offset': 58, 'sha256': 'cdc367d01d76e7f83ddd45cd451bdb1e2d45dcbcfe6ae538bd2a249b9ff0e26f'},
        'sha256': '82824abe2476355125503178aacd92a39425419f10b2ef83d85eecd31e3d5c5a',
        'offset': 0xb7df450,
        'seeds': (0xfdb7687b12650d11, 0x27ccba8576cfda8),
    },
    '118': {
        'resource_root': {'file': '118.0.5993.224/resources.pak', 'id': 23803, 'offset': 3109116, 'length': 402, 'key_offset': 108, 'sha256': 'a24118736a82407f6888f8335f88fbba1c7a4708abe7c2f854f97e0ac49b1bc4'},
        'sha256': '57031571e7f103bc9597defff043a167b334f769f1dee2ab77e9a044f8ba4842',
        'offset': 0xc7f6371,
        'seeds': (0x86a67c94d419091f, 0x7dafe6f4a2a505f3),
    },
    '122': {
        'resource_root': {'file': '122.0.6261.172/resources.pak', 'id': 25203, 'offset': 3257921, 'length': 389, 'key_offset': 95, 'sha256': '01e00f9174aff0cfc0b86ac2119ea9f5c10656068e4f44f0220f64eb14680fec'},
        'sha256': '3dedd259a3cd622ba04d9ef37ba6d489a06249042cd0812b9e3f57d1697eb969',
        'offset': 0xc9f9c30,
        'seeds': (0xaaa6d7740a97f29, 0x27fda94cb4cb1a7),
    },
    '124': {
        'resource_root': {'file': '124.0.6367.258/resources.pak', 'id': 24803, 'offset': 3327048, 'length': 370, 'key_offset': 76, 'sha256': '5a4d138d00ddde3a08616ca574f76f946961c77fbeab9c4dde5962845dba6165'},
        'sha256': 'c3292667aa1958b9f4a8c9d0013fbc767fb11c6d242c4d8f26c725f300ce2b25',
        'offset': 0xc62f300,
        'seeds': (0x93517b7fce3dd278, 0x72b82b57a240e648),
    },
    '126': {
        'resource_root': {'file': '126.0.6478.271/resources.pak', 'id': 25203, 'offset': 3593389, 'length': 358, 'key_offset': 64, 'sha256': 'd9f1483bf6f2740f582793df932107fa2ef3ecf84591776019fab00f3d6a9890'},
        'sha256': 'ef42730b59d0c71138ccec52eee47267ea4fa7ebaa93d1c4a937bb6a053f5950',
        'offset': 0xcacc408,
        'seeds': (0xa8e094f05e7c5e4c, 0xea3fd4d816a403b0),
    },
    '128': {
        'resource_root': {'file': '128.0.6613.195/resources.pak', 'id': 26303, 'offset': 3530075, 'length': 402, 'key_offset': 108, 'sha256': '553dbf1bee95ccbf7cd44f1a885a9bc9830aad0c0e6f8051522a8bd94f2915e0'},
        'sha256': '7b1b37bc7b3c79b4ebe6fd9d2e2b08cd68d472608dec1d534188c3a9550f2615',
        'offset': 0xcf3960b,
        'seeds': (0x79f69b0f693a2e81, 0x70ba35b14a62852),
    },
    '130': {
        'resource_root': {'file': '130.0.6723.193/resources.pak', 'id': 26503, 'offset': 3616085, 'length': 394, 'key_offset': 100, 'sha256': 'd672079de8d1305fa254ee35de875652cbf4e0a63435e76a01bb2c209b7a9a73'},
        'sha256': '5a6c3fcb576c00afc2a6a9895453169baa9e0503af305f20ac68c45f1e503375',
        'offset': 0xd4c1cee,
        'seeds': (0xf1fcc8d656583189, 0x50584787ac256878),
    },
    '132': {
        'resource_root': {'file': '132.0.6834.246/resources.pak', 'id': 26003, 'offset': 3296138, 'length': 405, 'key_offset': 111, 'sha256': '47320ab6d3c3bf262163b422e62faeee3f885aa353ec925866fb0d42fcef90b2'},
        'sha256': 'e1a57612e387811edbbbc7e1a04117af361eab8c42df155bfdf86dbf30fdc320',
        'offset': 0xd36aee3,
        'seeds': (0x9f20f6570e1af6ca, 0x6fab82a2391a0cb4),
    },
    '134': {
        'resource_root': {'file': '134.0.6998.222/resources.pak', 'id': 26703, 'offset': 3416287, 'length': 395, 'key_offset': 101, 'sha256': '05df324914ff2d0fccad84cce54f8d532de7f641f653e835f4e4da345a57a166'},
        'sha256': '105f846fa2e0e71e053584bd7adc697f07fba5e9c01fa13782d5033e81f803a4',
        'offset': 0xd80d267,
        'seeds': (0x748dfed726c6f5ee, 0x3b5658799cb2c92f),
    },
    '136': {
        'resource_root': {'file': '136.0.7103.186/resources.pak', 'id': 27003, 'offset': 4066969, 'length': 411, 'key_offset': 117, 'sha256': '87416aeb87cbb3042beb08a8a7ea0660976b9ac8796a409fdcad2a170c074417'},
        'sha256': '1a81f19ce5e469aacebec977646ee8789ea7836232688ea6f4e41f1c84dd3418',
        'offset': 0xd97c3ed,
        'seeds': (0x81348c303c310470, 0x211c41f518f9e437),
    },
    '138': {
        'resource_root': {'file': '138.0.7204.311/resources.pak', 'id': 27103, 'offset': 4259636, 'length': 389, 'key_offset': 95, 'sha256': '8d5e5bdac393912805a846c3cbe2a403532a771fa5b13bd7d45d55396e943955'},
        'sha256': '478072a76b97d0c7bee4140aa6a30603d6e4866cb9cbea5cc21bfe314f2c99f4',
        'offset': 0xdc382fa,
        'seeds': (0x98dd111047c4014f, 0x242bb7bb9964d303),
    },
    '140': {
        'resource_root': {'file': '140.0.7339.265/resources.pak', 'id': 27203, 'offset': 4379071, 'length': 407, 'key_offset': 113, 'sha256': 'f266b58fb9b3bac40729d8357c1430f841a6a8c0eeb1266846161edd38c7d3b7'},
        'sha256': 'a3c774cd177c784a36f6c7f59e9a3b745b56b0568341200895a987b3430563b2',
        'offset': 0xe3c7a11,
        'seeds': (0xbf9d96ab0248f595, 0x9d7ccd7d2abaecd1),
    },
    '142': {
        'resource_root': {'file': '142.0.7444.274/resources.pak', 'id': 23303, 'offset': 4546179, 'length': 357, 'key_offset': 63, 'sha256': '4d0f78d865ff5b214c707b95ab0691f0c3f8b3e2abac8a494143ceab222e8824'},
        'sha256': '70fdc6a13dae7698e387a7ceb36b0d8318c032de4f125253b9405060e4d0ed51',
        'offset': 0xe65af0b,
        'seeds': (0xa947cdb6da391382, 0x973871d0697c7a1a),
    },
    '144': {
        'resource_root': {'file': '144.0.7559.262/resources.pak', 'id': 24403, 'offset': 4868677, 'length': 370, 'key_offset': 76, 'sha256': '09eca9baa45e096529177e66b1f82e14811bc3911d6e4b79c169bdaade7c2ff0'},
        'sha256': '7822a3d573cad135c594fb9a42c720893ce5529da63baa81d62164e5b54166bd',
        'offset': 0xeacf7c4,
        'seeds': (0x22d2f66c47cab310, 0xde54e700d1b9a8ad),
    },
    '146': {
        'resource_root': {'file': '146.0.7680.253/resources.pak', 'id': 24503, 'offset': 10488709, 'length': 385, 'key_offset': 91, 'sha256': 'd6360434e6d9f2590c46e3f184f2c8ca6d29eb77276e3ffdd4eb64766ec9fbdd'},
        'sha256': '561bbc5e93619118cec2af76964db0f03371ea89c4f15cd45156a6c57c051257',
        'offset': 0xef0cd5b,
        'seeds': (0x2418eab8bf6c250c, 0xa7a70c10e6f73384),
    },
    '148': {
        'resource_root': {'file': '148.0.7778.289/resources.pak', 'id': 24703, 'offset': 6663915, 'length': 373, 'key_offset': 79, 'sha256': '030adcc69dabf2669a3aaf5932f064b46d8087bad41eaf26ed599ca8e46acd13'},
        'sha256': '591c5de91f4dd55c680c5e394e93ed3e3b48f73960c820a4d14e61d773653691',
        'offset': 0xf4e5112,
        'seeds': (0xd850fcb7620a7581, 0x5ca528ce38193db9),
    },
    '150': {
        'resource_root': {'file': '150.0.7871.257/resources.pak', 'id': 24103, 'offset': 7317291, 'length': 361, 'key_offset': 67, 'sha256': '1443874101553ea8b646f8cfd91e45186602377b1fc97cc0c7de1e0e56e3afe8'},
        'sha256': '6e83026149b41dc16f087736b31afc532e9f45aa5d986a0e63ffe52ddd56fae8',
        'offset': 0xf78f521,
        'seeds': (0xbcd5e3865a06eb13, 0x3d93d4ce919336b5),
    },
    '152': {
        'resource_root': {'file': '152.0.7977.169/resources.pak', 'id': 23203, 'offset': 12546420, 'length': 404, 'key_offset': 110, 'sha256': 'cba569117e7372e4f33be22eee61f9d3b040113d8a3282ac3de7431e95eefb51'},
        'sha256': 'c31151fb551ec9365d39cef77ba667409937734e0c7ccdb3db311456f7ec1436',
        'offset': 0xff4c4dc,
        'seeds': (0x7f7e83b88a1f7937, 0x160e3819d5226a2a),
    },
    '154': {
        'resource_root': {'file': '154.0.8037.153/resources.pak', 'id': 23303, 'offset': 13943795, 'length': 361, 'key_offset': 67, 'sha256': 'bd6c4c47e58b4797f1a99df10d8768cf4c815653add3de949c80e9a8bd98ee4e'},
        'sha256': '90e3dad416e438c2569f5b4563a3fcf031b83a180b2f76fb3a9442ee5a5692ed',
        'offset': 0x10301e09,
        'seeds': (0x36d4c28f376cf88, 0x55d2377bf9fcb96b),
    },
    '156': {
        'resource_root': {'file': '156.0.8078.78/resources.pak', 'id': 23703, 'offset': 14572589, 'length': 374, 'key_offset': 80, 'sha256': '385b79224ee51c9500afbd9621bb2eed41b71ba8891fb12df71f8104e194cd04'},
        'sha256': 'bd381aada460d4fb2c46035c92542cac85866153387271eef28f5c59074a447b',
        'offset': 0x105cd0cb,
        'seeds': (0xda51be35e98e30f9, 0x176d551bea1f6695),
    },
}


def supports_major(major):
    return str(major) in CORE_SPECS


def majors():
    return tuple(sorted(CORE_SPECS, key=int))

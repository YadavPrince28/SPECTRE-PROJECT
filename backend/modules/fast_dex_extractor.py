import struct
from collections import defaultdict
from pathlib import Path

_OP_LEN = [
    1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
    2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
    1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
    3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,
]

_INVOKE_OPS = frozenset((0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xFA, 0xFB))


def _read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7


def _scan_dex_binary(
    data: bytes,
    framework_prefixes: tuple[str, ...],
    normalize_fn,
    transitions: dict,
    app_classes: set,
    fw_classes: set,
    sa_mod=None,
    chain_stats: dict | None = None,
) -> tuple[int, int]:
    if len(data) < 112 or data[:4] != b"dex\n":
        raise ValueError("Not a valid DEX header")

    (
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        _proto_sz, _proto_off,
        _field_sz, _field_off,
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
    ) = struct.unpack_from("<12I", data, 56)

    str_offs = struct.unpack_from(f"<{string_ids_size}I", data, string_ids_off)
    type_str_idxs = struct.unpack_from(f"<{type_ids_size}I", data, type_ids_off)

    strings: list[str] = [""] * string_ids_size
    for s_idx, s_off in enumerate(str_offs):
        _, pos = _read_uleb128(data, s_off)
        end = data.find(b"\x00", pos)
        strings[s_idx] = data[pos:end].decode("utf-8", errors="ignore")

    type_to_fw: list[str | None] = [None] * type_ids_size
    type_to_norm: list[str] = [""] * type_ids_size
    type_to_chain_cls: list[str] = [""] * type_ids_size

    norm_chain_cls = sa_mod._normalize_descriptor if sa_mod is not None else None
    method_cats_fn = sa_mod._method_categories if sa_mod is not None else None
    chain_rules = sa_mod.API_CHAIN_RULES if sa_mod is not None else None
    find_chain_fn = sa_mod._find_ordered_category_chain if sa_mod is not None else None

    for t_idx, s_idx in enumerate(type_str_idxs):
        raw = strings[s_idx]
        if raw.startswith("L") and raw.endswith(";"):
            norm = normalize_fn(raw)
            type_to_norm[t_idx] = norm
            if norm and norm.startswith(framework_prefixes):
                type_to_fw[t_idx] = norm
            if norm_chain_cls is not None:
                type_to_chain_cls[t_idx] = norm_chain_cls(raw.strip("L;"))

    # method_ids entry: class_idx (H), proto_idx (H), name_idx (I) -> 8 bytes
    method_to_fw: list[str | None] = [None] * method_ids_size
    method_info: list[tuple[str, str]] | None = [( "", "" )] * method_ids_size if method_cats_fn is not None else None

    for m_idx in range(method_ids_size):
        cls_idx, _proto_idx, name_idx = struct.unpack_from("<HHI", data, method_ids_off + m_idx * 8)
        method_to_fw[m_idx] = type_to_fw[cls_idx]
        if method_info is not None and name_idx < string_ids_size:
            method_info[m_idx] = (type_to_chain_cls[cls_idx], strings[name_idx])

    methods_with_api = 0
    api_calls = 0

    for c_idx in range(class_defs_size):
        c_off = class_defs_off + c_idx * 32
        cls_type_idx, _acc, _super, _iface, _src, _annot, class_data_off, _svals = struct.unpack_from("<8I", data, c_off)

        cls_name = type_to_norm[cls_type_idx]
        if cls_name:
            if type_to_fw[cls_type_idx] is not None:
                fw_classes.add(cls_name)
            else:
                app_classes.add(cls_name)

        if class_data_off == 0:
            continue

        pos = class_data_off
        static_fields, pos = _read_uleb128(data, pos)
        inst_fields, pos = _read_uleb128(data, pos)
        direct_methods, pos = _read_uleb128(data, pos)
        virtual_methods, pos = _read_uleb128(data, pos)

        for _ in range(static_fields + inst_fields):
            _, pos = _read_uleb128(data, pos)
            _, pos = _read_uleb128(data, pos)

        for _ in range(direct_methods + virtual_methods):
            _, pos = _read_uleb128(data, pos)
            _, pos = _read_uleb128(data, pos)
            code_off, pos = _read_uleb128(data, pos)
            if code_off == 0:
                continue

            insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
            if insns_size == 0:
                continue

            insns = struct.unpack_from(f"<{insns_size}H", data, code_off + 16)
            pc = 0
            prev_api = None
            m_api = 0
            calls_in_method = [] if method_cats_fn is not None else None

            while pc < insns_size:
                unit = insns[pc]
                op = unit & 0xFF
                if op in _INVOKE_OPS:
                    if pc + 1 < insns_size:
                        m_idx = insns[pc + 1]
                        if m_idx < method_ids_size:
                            api_cls = method_to_fw[m_idx]
                            if api_cls is not None:
                                fw_classes.add(api_cls)
                                api_calls += 1
                                m_api += 1
                                if prev_api is not None:
                                    transitions[(prev_api, api_cls)] += 1
                                prev_api = api_cls

                            if method_info is not None and chain_stats is not None:
                                chain_stats["total_invocations"] += 1
                                c_api, m_name = method_info[m_idx]
                                if c_api:
                                    chain_stats["recognized_references"] += 1
                                    cats = method_cats_fn(c_api, m_name)
                                    if cats:
                                        for cat in cats:
                                            chain_stats["category_totals"][cat] = chain_stats["category_totals"].get(cat, 0) + 1
                                        calls_in_method.append({
                                            "index": pc,
                                            "api_class": c_api,
                                            "method": m_name,
                                            "categories": cats,
                                        })
                    pc += _OP_LEN[op]
                elif unit == 0x0100:
                    pc += (insns[pc + 1] * 2) + 4 if pc + 1 < insns_size else 1
                elif unit == 0x0200:
                    pc += (insns[pc + 1] * 4) + 2 if pc + 1 < insns_size else 1
                elif unit == 0x0300:
                    if pc + 3 < insns_size:
                        elem_w = insns[pc + 1]
                        sz = insns[pc + 2] | (insns[pc + 3] << 16)
                        pc += ((sz * elem_w + 1) // 2) + 4
                    else:
                        pc += 1
                else:
                    pc += _OP_LEN[op]

            if m_api > 0:
                methods_with_api += 1

            if calls_in_method and chain_stats is not None:
                chain_stats["methods_with_api_calls"] += 1
                found_in_method = False
                for rule in chain_rules:
                    selected = find_chain_fn(calls_in_method, tuple(rule["required_order"]))
                    if not selected:
                        continue
                    found_in_method = True
                    chain_stats["raw_chains"].append({
                        "chain": rule["name"],
                        "strength": rule["strength"],
                        "score": int(rule["score"]),
                        "defining_class": type_to_chain_cls[cls_type_idx] or "unknown",
                        "method": "",
                    })
                if found_in_method:
                    chain_stats["methods_with_source_sink_candidates"] += 1

    return methods_with_api, api_calls


def fast_extract_all(apk_path: Path, bd_module, sa_module=None) -> tuple[dict, dict | None]:
    """Single-pass binary DEX extractor for M2 transitions and (optionally) M1 API chain telemetry."""
    dex_blobs = bd_module.extract_target_dex(apk_path)
    transitions = defaultdict(int)
    app_classes = set()
    fw_classes = set()
    methods = 0
    api_calls = 0

    chain_stats = None
    if sa_module is not None:
        chain_stats = {
            "total_invocations": 0,
            "recognized_references": 0,
            "methods_with_api_calls": 0,
            "methods_with_source_sink_candidates": 0,
            "category_totals": {},
            "raw_chains": [],
        }

    for dex_bytes in dex_blobs:
        m_cnt, a_cnt = _scan_dex_binary(
            dex_bytes,
            bd_module.FRAMEWORK_PREFIXES,
            bd_module.normalize_class_name,
            transitions,
            app_classes,
            fw_classes,
            sa_mod=sa_module,
            chain_stats=chain_stats,
        )
        methods += m_cnt
        api_calls += a_cnt

    m2_out = {
        "class_transition_counts": dict(transitions),
        "application_classes": app_classes,
        "framework_classes": fw_classes,
        "methods": methods,
        "api_calls": api_calls,
        "dex_files": len(dex_blobs),
    }

    chain_out = None
    if chain_stats is not None:
        raw_chains = chain_stats["raw_chains"]
        raw_chains.sort(key=lambda item: (-item.get("score", 0), item.get("chain", ""), item.get("defining_class", "")))
        unique = []
        seen_keys = set()
        for f in raw_chains:
            key = (f.get("chain", ""), f.get("defining_class", ""), f.get("method", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(f)

        scoring_chains = [x for x in unique if x.get("strength") in {"STRONG", "MEDIUM"}]
        distinct_scoring_rules = {x["chain"] for x in scoring_chains}
        max_rule_score = max((int(x["score"]) for x in scoring_chains), default=0)
        api_chain_score = 0
        if scoring_chains:
            api_chain_score = min(
                100,
                max_rule_score
                + 12 * max(0, len(distinct_scoring_rules) - 1)
                + 4 * min(4, max(0, len(scoring_chains) - len(distinct_scoring_rules))),
            )

        chain_out = {
            "suspicious_chains": unique[:100],
            "chain_count": len(unique),
            "api_chain_score": api_chain_score,
            "malicious_api_chain_score": api_chain_score,
            "api_invocation_count": chain_stats["total_invocations"],
            "recognized_api_reference_count": chain_stats["recognized_references"],
            "methods_with_api_calls": chain_stats["methods_with_api_calls"],
            "strong_chain_count": sum(1 for x in unique if x.get("strength") == "STRONG"),
            "medium_chain_count": sum(1 for x in unique if x.get("strength") == "MEDIUM"),
            "contextual_chain_count": sum(1 for x in unique if x.get("strength") == "CONTEXTUAL"),
            "distinct_rule_count": len({x["chain"] for x in unique}),
            "distinct_scoring_rule_count": len(distinct_scoring_rules),
            "methods_with_source_sink_candidates": chain_stats["methods_with_source_sink_candidates"],
            "api_chain_score_status": "EXPERIMENTAL_UNCALIBRATED",
            "api_category_totals": chain_stats["category_totals"],
            "api_category_samples": [],
            "raw_api_samples": [],
            "raw_instruction_samples": [],
            "multi_category_method_count": 0,
            "multi_category_method_samples": [],
        }

    return m2_out, chain_out


def fast_extract_target_transitions(apk_path: Path, bd_module) -> dict:
    m2_out, _ = fast_extract_all(apk_path, bd_module, sa_module=None)
    return m2_out
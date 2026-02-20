#!/usr/bin/env python3
"""
Extract ClassNetCache data for all C++ native classes from a UE5 binary.
Scans Z_Construct_UClass static registration stubs to compute:
  - SerializeInt Max values (seed_values)
  - Per-field handle indices (field_indices)
Tested on UE 5.7

Usage:
    python class_net_cache_parser.py <Game.exe> [output.json]
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from typing import Sequence

from pe_analyzer import PEAnalyzer, log


DEFAULT_OUTPUT_PATH = 'class_net_cache_seed.json'


@dataclass(frozen=True)
class FieldInfo:
    kind: str
    name: str
    array_dim: int = 0


@dataclass
class ClassInfo:
    name: str
    parent: int | None
    net_props: list[tuple[str, int]]
    net_funcs: list[str]


@dataclass(frozen=True)
class ClassLayout:
    base: int
    own_fields: list[FieldInfo]


def parse_cli_args(argv: Sequence[str]) -> tuple[str, str]:
    if len(argv) < 2:
        raise ValueError('Usage: python class_net_cache_parser.py <Game.exe> [output.json]')
    exe_path = argv[1]
    out_path = argv[2] if len(argv) > 2 else DEFAULT_OUTPUT_PATH
    return exe_path, out_path


def build_class_map(
    pe: PEAnalyzer,
    z_list: list[tuple[int, int]],
    names: dict[int, str],
    z_set: set[int],
) -> dict[int, ClassInfo]:
    classes: dict[int, ClassInfo] = {}

    for func_va, class_params_va in z_list:
        parsed = pe.parse_fclass(class_params_va)
        if not parsed:
            continue

        n_deps = int(parsed.get('n_deps', 0) or 0)
        dep_arr = parsed.get('dep_arr')
        parent = pe.resolve_parent(dep_arr, n_deps, z_set) if dep_arr and n_deps > 0 else None

        n_props = int(parsed.get('n_props', 0) or 0)
        prop_arr = parsed.get('prop_arr')
        net_props = pe.net_prop_names(prop_arr, n_props) if prop_arr and n_props > 0 else []

        n_funcs = int(parsed.get('n_funcs', 0) or 0)
        func_arr = parsed.get('func_arr')
        net_funcs = pe.net_func_names(func_arr, n_funcs) if func_arr and n_funcs > 0 else []

        classes[func_va] = ClassInfo(
            name=names.get(func_va, f'Unknown_0x{func_va:X}'),
            parent=parent,
            net_props=net_props,
            net_funcs=net_funcs,
        )

    return classes


def compute_class_layouts(classes: dict[int, ClassInfo]) -> dict[int, ClassLayout]:
    cache: dict[int, ClassLayout] = {}

    def compute(va: int, visiting: set[int] | None = None) -> ClassLayout | None:
        if va in cache:
            return cache[va]
        if va not in classes:
            return None

        vis = visiting if visiting is not None else set()
        if va in vis:
            return None
        vis.add(va)

        try:
            cls = classes[va]
            if cls.parent is None:
                base = 0
            else:
                parent_layout = compute(cls.parent, vis)
                if parent_layout is None:
                    return None
                base = parent_layout.base + len(parent_layout.own_fields)

            own_fields: list[FieldInfo] = []
            for prop_name, array_dim in cls.net_props:
                own_fields.append(FieldInfo('property', prop_name, array_dim))
            for func_name in cls.net_funcs:
                own_fields.append(FieldInfo('function', func_name, 0))

            layout = ClassLayout(base=base, own_fields=own_fields)
            cache[va] = layout
            return layout
        finally:
            vis.discard(va)

    for va in classes:
        compute(va)

    return cache


def build_output(
    z_list: list[tuple[int, int]],
    names: dict[int, str],
    classes: dict[int, ClassInfo],
    layouts: dict[int, ClassLayout],
    elapsed: float,
) -> dict:
    seed_values: dict[str, int] = {}
    per_class: dict[str, dict] = {}
    flat: dict[str, int] = {}

    for va in sorted(layouts, key=lambda key: classes[key].name):
        cls = classes[va]
        layout = layouts[va]
        seed_values[cls.name] = 1 + layout.base + len(layout.own_fields)

        if not layout.own_fields:
            continue

        entry = {'fields_base': layout.base, 'fields': {}}
        for i, field in enumerate(layout.own_fields):
            handle = layout.base + i
            field_info = {'name': field.name, 'type': field.kind}
            if field.array_dim > 1:
                field_info['array_dim'] = field.array_dim
            entry['fields'][str(handle)] = field_info
            flat[f'{cls.name}::{field.name}'] = handle

        per_class[cls.name] = entry

    total_fields = sum(len(entry['fields']) for entry in per_class.values())
    total_props = sum(
        1
        for entry in per_class.values()
        for field in entry['fields'].values()
        if field['type'] == 'property'
    )
    total_funcs = total_fields - total_props

    return {
        'stats': {
            'total_classes': len(z_list),
            'named': len(names),
            'resolved_max': len(seed_values),
            'resolved_fields': len(per_class),
            'total_fields': total_fields,
            'total_props': total_props,
            'total_funcs': total_funcs,
            'elapsed_sec': round(elapsed, 1),
        },
        'seed_values': dict(sorted(seed_values.items())),
        'per_class': per_class,
        'flat_index': dict(sorted(flat.items())),
    }


def main(argv: Sequence[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv
    try:
        exe_path, out_path = parse_cli_args(argv)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    log(f'Loading {exe_path}...')
    pe = PEAnalyzer(exe_path)
    log(f'ImageBase = 0x{pe.base:X}')

    try:
        z_list = pe.find_z_constructs()
        z_set = {va for va, _ in z_list}

        log('Mapping class names...')
        names = pe.find_names(z_set)
        log(f'{len(names)}/{len(z_list)} names resolved')
        if not names:
            log('WARNING: No class names found. UE 5.6 or earlier may not be supported.')

        log('Parsing class metadata...')
        classes = build_class_map(pe, z_list, names, z_set)

        log('Computing Max values and field indices...')
        layouts = compute_class_layouts(classes)
        output = build_output(
            z_list=z_list,
            names=names,
            classes=classes,
            layouts=layouts,
            elapsed=time.perf_counter() - t0,
        )

        with open(out_path, 'w', encoding='utf-8') as stream:
            json.dump(output, stream, indent=2)

        stats = output['stats']
        log(
            f"Written {stats['resolved_max']} Max values + {stats['total_fields']} fields "
            f"({stats['total_props']}p + {stats['total_funcs']}f) -> {out_path} "
            f"({stats['elapsed_sec']:.1f}s)"
        )
        return 0
    finally:
        pe.close()


if __name__ == '__main__':
    raise SystemExit(main())

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

import sys, json, time

from pe_analyzer import PEAnalyzer, CPF_NET, log


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <Game.exe> [output.json]", file=sys.stderr)
        sys.exit(1)

    exe_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "class_net_cache_seed.json"
    t0 = time.time()

    log(f"Loading {exe_path}...")
    pe = PEAnalyzer(exe_path)
    log(f"ImageBase = 0x{pe.base:X}")

    z_list = pe.find_z_constructs()
    z_set = {va for va, _ in z_list}

    log("Mapping class names...")
    names = pe.find_names(z_set)
    log(f"{len(names)}/{len(z_list)} names resolved")
    if len(names) == 0:
        log("WARNING: No class names found. UE 5.6 or earlier may not be supported.")

    log("Parsing class metadata...")
    classes = {}
    for fva, fcp in z_list:
        p = pe.parse_fclass(fcp)
        if not p:
            continue
        classes[fva] = {
            'name':      names.get(fva, f"Unknown_0x{fva:X}"),
            'parent':    pe.resolve_parent(p['dep_arr'], p['n_deps'], z_set),
            'net_props': pe.net_prop_names(p['prop_arr'], p['n_props']),
            'net_funcs': pe.net_func_names(p['func_arr'], p['n_funcs']),
        }

    log("Computing Max values and field indices...")
    cache = {}  # va -> (base, own_fields)

    def compute(va, vis=None):
        if vis is None:
            vis = set()
        if va in cache:
            return cache[va]
        if va not in classes or va in vis:
            return None
        vis.add(va)
        cls = classes[va]
        if cls['parent'] is None:
            base = 0
        else:
            r = compute(cls['parent'], vis)
            if r is None:
                return None
            base = r[0] + len(r[1])

        own = []
        for name, adim in cls['net_props']:
            own.append(('property', name, adim))
        for name in cls['net_funcs']:
            own.append(('function', name, 0))

        cache[va] = (base, own)
        return cache[va]

    for va in classes:
        compute(va)

    # Build output
    seed_values = {}
    per_class = {}
    flat = {}

    for va in sorted(cache, key=lambda v: classes[v]['name']):
        cname = classes[va]['name']
        base, own = cache[va]
        seed_values[cname] = 1 + base + len(own)

        if not own:
            continue
        entry = {'fields_base': base, 'fields': {}}
        for i, (ftype, fname, adim) in enumerate(own):
            h = base + i
            field = {'name': fname, 'type': ftype}
            if adim > 1:
                field['array_dim'] = adim
            entry['fields'][str(h)] = field
            flat[f"{cname}::{fname}"] = h
        per_class[cname] = entry

    elapsed = time.time() - t0
    total_f = sum(len(e['fields']) for e in per_class.values())
    n_props = sum(1 for e in per_class.values()
                  for f in e['fields'].values() if f['type'] == 'property')
    n_funcs = total_f - n_props

    output = {
        'stats': {
            'total_classes': len(z_list),
            'named': len(names),
            'resolved_max': len(seed_values),
            'resolved_fields': len(per_class),
            'total_fields': total_f,
            'total_props': n_props,
            'total_funcs': n_funcs,
            'elapsed_sec': round(elapsed, 1),
        },
        'seed_values': dict(sorted(seed_values.items())),
        'per_class': per_class,
        'flat_index': dict(sorted(flat.items())),
    }

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)

    log(f"Written {len(seed_values)} Max values + {total_f} fields "
        f"({n_props}p + {n_funcs}f) → {out_path} ({elapsed:.1f}s)")
    pe.close()


if __name__ == '__main__':
    main()

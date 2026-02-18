#!/usr/bin/env python3
"""
Shared PE binary analysis utilities for UE5 Z_Construct static registration parsing.
Used by both class_net_cache_parser.py and rep_layout_parser.py.
"""

import struct, sys, mmap
import pefile

# ── Z_Construct_UClass stub layout (47 bytes) ──
#
#  +0   48 83 EC 28        sub  rsp, 0x28
#  +4   48 8B 05 [d32]     mov  rax, [rip+d32]      ; OuterSingleton
#  +11  48 85 C0           test rax, rax
#  +14  75 xx              jnz  short
#  +16  48 8D 15 [d32]     lea  rdx, [rip+d32]       ; FClassParams*
#  +23  48 8D 0D [d32]     lea  rcx, [rip+d32]       ; &OuterSingleton
#  +30  E8 [d32]           call ConstructUClass

STUB_HEAD = b'\x48\x83\xEC\x28\x48\x8B\x05'
STUB_TEST = b'\x48\x85\xC0'
STUB_LEA  = b'\x48\x8D\x15'

# ConstructUClass body fingerprints
FINGERPRINTS = [
    b'\xFF\x07\x00\x00',   # 0x7FF bitfield mask
    b'\x5E\x86\xA3\x4A',  # 0x4AA3865E ClassFlags (ARK/Lyra)
    b'\x48\x63\x42\x38',  # movsxd rax, [rdx+0x38] bitfield read
    b'\x5E\x06\xA3\x4A',  # 0x4AA3065E ClassFlags (Palworld)
]

# FClassParams offsets
OFF_DEPS  = 0x18  # DependencySingletonFuncArray*
OFF_FUNCS = 0x20  # FunctionLinkArray*
OFF_PROPS = 0x28  # PropertyArray*
OFF_BITS  = 0x38  # packed bitfield: deps(4) | funcs(11) | props(11)

# FPropertyParamsBase offsets
OFF_PNAME  = 0x00  # const char* NameUTF8
OFF_PFLAGS = 0x10  # PropertyFlags (uint64)
OFF_PADIM  = 0x30  # uint16 ArrayDim
CPF_NET    = 0x20

# FFunctionParams / FClassFunctionLinkInfo
OFF_FFLAGS = 0x38  # FunctionFlags (uint32)
OFF_FLNAME = 0x08  # const char* FuncNameUTF8
FUNC_NET   = 0x40


def log(msg):
    print(f"[*] {msg}", file=sys.stderr)


class PEAnalyzer:
    def __init__(self, path):
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self._secs = [(
            s.Name.decode('ascii', errors='replace').rstrip('\x00'),
            s.VirtualAddress, s.Misc_VirtualSize,
            s.PointerToRawData, s.SizeOfRawData,
        ) for s in pe.sections]
        self._f = open(path, 'rb')
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self):
        self._mm.close()
        self._f.close()

    def _va2off(self, va):
        rva = va - self.base
        for _, svr, svs, spr, sps in self._secs:
            if svr <= rva < svr + svs:
                o = spr + (rva - svr)
                return o if o < spr + sps else None
        return None

    def _off2va(self, off):
        for _, svr, _, spr, sps in self._secs:
            if spr <= off < spr + sps:
                return self.base + svr + (off - spr)
        return None

    def _r16(self, va):
        o = self._va2off(va)
        return struct.unpack_from('<H', self._mm, o)[0] if o else None

    def _r32(self, va):
        o = self._va2off(va)
        return struct.unpack_from('<I', self._mm, o)[0] if o else None

    def _r64(self, va):
        o = self._va2off(va)
        return struct.unpack_from('<Q', self._mm, o)[0] if o else None

    def _ri32(self, off):
        return struct.unpack_from('<i', self._mm, off)[0]

    def _sec(self, name):
        for n, svr, svs, spr, sps in self._secs:
            if n == name:
                return spr, sps, self.base + svr
        raise RuntimeError(f"section '{name}' not found")

    def _cstr(self, va, maxlen=256):
        o = self._va2off(va)
        if not o:
            return None
        end = self._mm.find(b'\x00', o, o + maxlen)
        return self._mm[o:end].decode('utf-8', errors='replace') if end >= 0 else None

    def _wstr(self, va, maxlen=512):
        o = self._va2off(va)
        if not o:
            return None
        chars = []
        for i in range(0, maxlen, 2):
            ch = struct.unpack_from('<H', self._mm, o + i)[0]
            if ch == 0:
                break
            chars.append(chr(ch))
        return ''.join(chars)

    def find_z_constructs(self):
        """Scan .text for Z_Construct stubs, identify ConstructUClass by fingerprint."""
        raw, size, _ = self._sec('.text')
        mm = self._mm
        groups = {}

        pos, end = raw, raw + size - 47
        while True:
            p = mm.find(STUB_HEAD, pos, end)
            if p < 0:
                break
            if (mm[p+11:p+14] == STUB_TEST and mm[p+14] == 0x75
                    and mm[p+16:p+19] == STUB_LEA and mm[p+30] == 0xE8):
                target = self._off2va(p + 30) + 5 + self._ri32(p + 31)
                func_va = self._off2va(p)
                lea_va = self._off2va(p + 16)
                fcp_va = lea_va + 7 + self._ri32(p + 19)
                groups.setdefault(target, []).append((func_va, fcp_va))
            pos = p + 1

        best, best_score = None, 0
        for tva, callers in groups.items():
            if len(callers) < 1000:
                continue
            o = self._va2off(tva)
            if not o:
                continue
            body = mm[o:o+4096]
            # Follow JMP thunk
            if body[5] == 0xE9:
                o2 = self._va2off(tva + 10 + self._ri32(o + 6))
                if o2:
                    body = mm[o2:o2+4096]
            score = sum(body.count(fp) for fp in FINGERPRINTS)
            if score > best_score:
                best, best_score = tva, score

        if not best:
            raise RuntimeError("ConstructUClass not found")
        log(f"ConstructUClass @ 0x{best:X}  ({len(groups[best])} classes, score={best_score})")
        return groups[best]

    def parse_fclass(self, va):
        bf = self._r32(va + OFF_BITS)
        if bf is None:
            return None
        return {
            'n_deps':  bf & 0xF,
            'n_funcs': (bf >> 4) & 0x7FF,
            'n_props': (bf >> 15) & 0x7FF,
            'dep_arr':  self._r64(va + OFF_DEPS),
            'func_arr': self._r64(va + OFF_FUNCS),
            'prop_arr': self._r64(va + OFF_PROPS),
        }

    def net_prop_names(self, arr, n):
        """Return [(name, array_dim), ...] for CPF_Net properties, in declaration order."""
        result = []
        for i in range(n):
            ptr = self._r64(arr + i * 8)
            if not ptr:
                continue
            flags = self._r64(ptr + OFF_PFLAGS)
            if not flags or not (flags & CPF_NET):
                continue
            name_ptr = self._r64(ptr + OFF_PNAME)
            if not name_ptr:
                continue
            name = self._cstr(name_ptr)
            if not name:
                continue
            adim = self._r16(ptr + OFF_PADIM) or 1
            result.append((name, adim))
        return result

    def net_func_names(self, arr, n):
        """Return [name, ...] for FUNC_Net functions, in declaration order."""
        result = []
        mm = self._mm
        for i in range(n):
            entry_va = arr + i * 16
            zf = self._r64(entry_va)
            if not zf:
                continue
            o = self._va2off(zf + 16)
            if not o or mm[o:o+3] != STUB_LEA:
                continue
            ff_va = zf + 23 + self._ri32(o + 3)
            ff = self._r32(ff_va + OFF_FFLAGS)
            if not ff or not (ff & FUNC_NET):
                continue
            name_ptr = self._r64(entry_va + OFF_FLNAME)
            if not name_ptr:
                continue
            name = self._cstr(name_ptr)
            if name:
                result.append(name)
        return result

    def resolve_parent(self, dep_arr, n_deps, known):
        for i in range(n_deps):
            va = self._r64(dep_arr + i * 8)
            if va in known:
                return va
        return None

    def find_names(self, z_set):
        """Scan .rdata for FClassRegisterCompiledInInfo → wchar_t* class names."""
        mm = self._mm
        raw, size, _ = self._sec('.rdata')
        names = {}
        pos, end = raw, raw + size - 0x28
        while pos <= end:
            val = struct.unpack_from('<Q', mm, pos)[0]
            if val in z_set and val not in names:
                nptr = struct.unpack_from('<Q', mm, pos + 0x10)[0]
                no = self._va2off(nptr)
                if no:
                    ch = struct.unpack_from('<H', mm, no)[0]
                    if 0x41 <= ch <= 0x5A:
                        name = self._wstr(nptr)
                        if name and len(name) >= 2 and name[0] in 'AUF' and name[1].isupper():
                            names[val] = name[1:]
            pos += 8
        return names

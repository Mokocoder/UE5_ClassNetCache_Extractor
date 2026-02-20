#!/usr/bin/env python3
"""Shared PE binary analysis utilities for UE5 Z_Construct static registration parsing."""
import struct, sys, mmap
import pefile

from layout_detector import (
    CPF_NET, FUNC_NET,
    DetectedOffsets, LayoutDetector,
)

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
    b'\xFF\x07\x00\x00',
    b'\x5E\x86\xA3\x4A',
    b'\x48\x63\x42\x38',
    b'\x5E\x06\xA3\x4A',
]


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
        self.offsets = DetectedOffsets()  # populated by find_z_constructs

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
        return struct.unpack_from('<H', self._mm, o)[0] if o is not None else None

    def _r32(self, va):
        o = self._va2off(va)
        return struct.unpack_from('<I', self._mm, o)[0] if o is not None else None

    def _r64(self, va):
        o = self._va2off(va)
        return struct.unpack_from('<Q', self._mm, o)[0] if o is not None else None

    def _ri32(self, off):
        return struct.unpack_from('<i', self._mm, off)[0]

    def _sec(self, name):
        for n, svr, svs, spr, sps in self._secs:
            if n == name:
                return spr, sps, self.base + svr
        raise RuntimeError(f"section '{name}' not found")

    def _cstr(self, va, maxlen=256):
        o = self._va2off(va)
        if o is None:
            return None
        end = self._mm.find(b'\x00', o, o + maxlen)
        return self._mm[o:end].decode('utf-8', errors='replace') if end >= 0 else None

    def _wstr(self, va, maxlen=512):
        o = self._va2off(va)
        if o is None:
            return None
        chars = []
        for i in range(0, maxlen, 2):
            ch = struct.unpack_from('<H', self._mm, o + i)[0]
            if ch == 0:
                break
            chars.append(chr(ch))
        return ''.join(chars)

    def find_z_constructs(self):
        """Scan .text for Z_Construct stubs, identify ConstructUClass,
        then auto-detect all struct field offsets."""
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

        def score_target(tva):
            off = self._va2off(tva)
            if off is None:
                return None
            body = mm[off:off + 4096]
            # Follow JMP thunk
            if len(body) > 10 and body[5] == 0xE9:
                o2 = self._va2off(tva + 10 + self._ri32(off + 6))
                if o2 is not None:
                    body = mm[o2:o2 + 4096]
            return sum(body.count(fp) for fp in FINGERPRINTS)

        best, best_score = None, -1
        used_fallback = False
        for tva, callers in groups.items():
            if len(callers) < 1000:
                continue
            score = score_target(tva)
            if score is None:
                continue
            if score > best_score:
                best, best_score = tva, score

        if best is None:
            # Fallback for smaller titles / minimal test binaries
            used_fallback = True
            for tva, _ in groups.items():
                score = score_target(tva)
                if score is None:
                    continue
                if score > best_score:
                    best, best_score = tva, score

        if best is None:
            raise RuntimeError("ConstructUClass not found")

        z_list = groups[best]
        if used_fallback:
            log("No high-population ConstructUClass target found; using best-score fallback")
        log(f"ConstructUClass @ 0x{best:X}  ({len(z_list)} classes, score={best_score})")

        # ── Auto-detect struct offsets ──
        detector = LayoutDetector(self)
        self.offsets = detector.detect(best, z_list)
        log("Detected offsets:\n" + self.offsets.summary())

        return z_list

    def parse_fclass(self, va):
        o = self.offsets
        bf = self._r32(va + o.fclass_bits)
        if bf is None:
            return None
        return {
            'n_deps':  bf & 0xF,
            'n_funcs': (bf >> 4) & 0x7FF,
            'n_props': (bf >> 15) & 0x7FF,
            'dep_arr':  self._r64(va + o.fclass_deps),
            'func_arr': self._r64(va + o.fclass_funcs),
            'prop_arr': self._r64(va + o.fclass_props),
        }

    def net_prop_names(self, arr, n):
        """Return [(name, array_dim), ...] for CPF_Net properties, in declaration order."""
        o = self.offsets
        result = []
        for i in range(n):
            ptr = self._r64(arr + i * 8)
            if not ptr:
                continue
            flags = self._r64(ptr + o.fprop_flags)
            if not flags or not (flags & CPF_NET):
                continue
            name_ptr = self._r64(ptr + o.fprop_name)
            if not name_ptr:
                continue
            name = self._cstr(name_ptr)
            if not name:
                continue
            adim = self._r16(ptr + o.fprop_array_dim) or 1
            result.append((name, adim))
        return result

    def net_func_names(self, arr, n):
        """Return [name, ...] for FUNC_Net functions, in declaration order."""
        o = self.offsets
        result = []
        mm = self._mm
        for i in range(n):
            entry_va = arr + i * 16
            zf = self._r64(entry_va)
            if not zf:
                continue
            fo = self._va2off(zf + 16)
            if fo is None or mm[fo:fo+3] != STUB_LEA:
                continue
            ff_va = zf + 23 + self._ri32(fo + 3)
            ff = self._r32(ff_va + o.ffunc_flags)
            if not ff or not (ff & FUNC_NET):
                continue
            name_ptr = self._r64(entry_va + o.flink_name)
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
                if no is not None:
                    ch = struct.unpack_from('<H', mm, no)[0]
                    if 0x41 <= ch <= 0x5A:
                        name = self._wstr(nptr)
                        if name and len(name) >= 2 and name[0] in 'AUF' and name[1].isupper():
                            names[val] = name[1:]
            pos += 8
        return names

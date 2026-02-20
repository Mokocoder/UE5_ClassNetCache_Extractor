"""Auto-detect UE internal struct field offsets"""
from __future__ import annotations

import struct as _struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from pe_analyzer import PEAnalyzer


# ── Known flag constants ───────────

CPF_NET = 0x20
FUNC_NET = 0x40
FUNC_NATIVE = 0x0400

# ── FFunctionParams scan range ────────────────────────────────────────────

_FFUNC_SCAN_START = 0x20
_FFUNC_SCAN_END   = 0x60
_FFUNC_SCAN_STEP  = 0x04
_FFUNC_TARGET_SAMPLES = 100
_FFUNC_MAX_CLASSES = 200

# ── Anchor byte patterns ─────────────────────────────────────────────────

_MASK_7FF = b"\xFF\x07\x00\x00"  # 0x7FF as LE dword


@dataclass
class DetectedOffsets:
    """All struct field offsets, auto-detected or defaulted."""

    # FClassParams
    fclass_deps: int = 0x18
    fclass_funcs: int = 0x20
    fclass_props: int = 0x28
    fclass_bits: int = 0x38

    # FFunctionParams
    ffunc_flags: int = 0x28

    # FPropertyParamsBase
    fprop_name: int = 0x00
    fprop_flags: int = 0x10
    fprop_gen_flags: int = 0x18
    fprop_array_dim: int = 0x30
    fprop_struct_func: int = 0x38

    # FStructParams
    fstruct_super: int = 0x08
    fstruct_ops: int = 0x10
    fstruct_name: int = 0x18
    fstruct_props: int = 0x20
    fstruct_count: int = 0x28

    # FEnumParams
    fenum_name: int = 0x10
    fenum_values: int = 0x20
    fenum_count: int = 0x2C
    fenum_entry_size: int = 0x10
    fenum_entry_value: int = 0x08

    # FClassFunctionLinkInfo
    flink_name: int = 0x08

    # Metadata
    _detected: dict[str, bool] = field(default_factory=dict, repr=False)

    def summary(self) -> str:
        parts = []
        for name, default in _DEFAULTS.items():
            val = getattr(self, name)
            tag = "auto" if name in self._detected else "default"
            mark = "" if val == default else " CHANGED"
            parts.append(f"  {name} = 0x{val:02X} ({tag}{mark})")
        return "\n".join(parts)


_DEFAULTS = {f.name: f.default for f in DetectedOffsets.__dataclass_fields__.values() if isinstance(f.default, int)}


class LayoutDetector:
    def __init__(self, pe: PEAnalyzer):
        self._pe = pe

    def detect(
        self,
        construct_uclass_va: int,
        z_constructs: Sequence[tuple[int, int]],
    ) -> DetectedOffsets:
        off = DetectedOffsets()
        if not z_constructs:
            _log("No Z_Construct entries provided; using all default offsets")
            return off

        self._detect_fclass(construct_uclass_va, z_constructs, off)
        self._detect_ffunc(z_constructs, off)
        self._validate_fprop(z_constructs, off)
        self._validate_fstruct(z_constructs, off)

        return off

    def _detect_fclass(
        self,
        construct_va: int,
        z_constructs: Sequence[tuple[int, int]],
        off: DetectedOffsets,
    ) -> None:
        body = self._read_body(construct_va)
        bf = self._find_bitfield_offset(body)
        if bf is None:
            _log("FClassParams bitfield anchor not found. using defaults")
            return

        # Derive array pointer offsets (4 QWORDs immediately before bitfield)
        candidate = DetectedOffsets(
            fclass_deps=bf - 0x20,
            fclass_funcs=bf - 0x18,
            fclass_props=bf - 0x10,
            fclass_bits=bf,
        )

        if self._validate_fclass(candidate, z_constructs):
            off.fclass_deps = candidate.fclass_deps
            off.fclass_funcs = candidate.fclass_funcs
            off.fclass_props = candidate.fclass_props
            off.fclass_bits = candidate.fclass_bits
            for k in ("fclass_deps", "fclass_funcs", "fclass_props", "fclass_bits"):
                off._detected[k] = True
            _log(f"FClassParams bitfield @ 0x{bf:02X}  "
                 f"(deps=0x{off.fclass_deps:02X} funcs=0x{off.fclass_funcs:02X} "
                 f"props=0x{off.fclass_props:02X})")
        else:
            _log(f"FClassParams validation failed for bitfield=0x{bf:02X}. using defaults")

    def _find_bitfield_offset(self, body: bytes) -> int | None:
        """Locate the packed bitfield via the 0x7FF mask anchor"""
        from collections import Counter

        positions: list[int] = []
        start = 0
        while len(positions) < 8:
            idx = body.find(_MASK_7FF, start)
            if idx < 0:
                break
            positions.append(idx)
            start = idx + 1
        if len(positions) < 2:
            return None

        all_disps: list[int] = []
        for pos in positions:
            for s in range(pos - 1, max(pos - 30, -1), -1):
                if s < 0:
                    break
                # SHR r32, imm8:  [optional REX] C1 [E8-EF] imm8
                if (body[s] == 0xC1
                        and s + 2 < len(body)
                        and (body[s + 1] & 0xF8) == 0xE8):
                    all_disps.extend(self._collect_dword_load_disps(body, s))
                    break

        if not all_disps:
            return None

        counts = Counter(all_disps)
        winner, _ = counts.most_common(1)[0]
        return winner

    @staticmethod
    def _collect_dword_load_disps(body: bytes, before: int, search_range: int = 40) -> list[int]:
        results: list[int] = []
        lo = max(before - search_range, 1)
        for i in range(before - 1, lo - 1, -1):
            # movsxd r64, [reg+disp8]:  48/4C 63 [mod=01, rm!=4] disp8
            if body[i] == 0x63 and body[i - 1] in (0x48, 0x4C):
                modrm = body[i + 1]
                if (modrm >> 6) == 1 and (modrm & 7) != 4:
                    results.append(body[i + 2])
                continue

            # REX + mov r32, [reg+disp8]:  4? 8B [mod=01, rm!=4] disp8
            if (body[i] & 0xF0) == 0x40 and i + 3 < len(body) and body[i + 1] == 0x8B:
                modrm = body[i + 2]
                if (modrm >> 6) == 1 and (modrm & 7) != 4:
                    results.append(body[i + 3])
                continue

            # Plain mov r32, [reg+disp8]:  8B [mod=01, rm!=4] disp8
            if body[i] == 0x8B and i + 2 < len(body):
                modrm = body[i + 1]
                if (modrm >> 6) == 1 and (modrm & 7) != 4:
                    if i > 0 and (body[i - 1] & 0xF0) == 0x40:
                        continue  # already handled by REX case
                    results.append(body[i + 2])

        return results

    def _validate_fclass(
        self,
        candidate: DetectedOffsets,
        z_constructs: Sequence[tuple[int, int]],
    ) -> bool:
        """Check that the derived offsets produce sane data for a few classes."""
        pe = self._pe
        ok = 0
        for _, fcp_va in z_constructs[:20]:
            bf = pe._r32(fcp_va + candidate.fclass_bits)
            if bf is None:
                continue
            n_deps = bf & 0xF
            n_funcs = (bf >> 4) & 0x7FF
            n_props = (bf >> 15) & 0x7FF
            if n_deps > 15 or n_funcs > 2000 or n_props > 2000:
                continue
            # If count > 0 the matching array pointer must be non-null
            if n_props > 0:
                arr = pe._r64(fcp_va + candidate.fclass_props)
                if not arr:
                    return False
            if n_funcs > 0:
                arr = pe._r64(fcp_va + candidate.fclass_funcs)
                if not arr:
                    return False
            ok += 1
            if ok >= 5:
                return True
        return ok > 0

    def _detect_ffunc(
        self,
        z_constructs: Sequence[tuple[int, int]],
        off: DetectedOffsets,
    ) -> None:
        pe = self._pe
        samples = self._collect_ffunc_samples(z_constructs, off)

        if not samples:
            _log("FFunctionParams: no samples. using default")
            return

        best, best_score = off.ffunc_flags, -1
        for cand in range(_FFUNC_SCAN_START, _FFUNC_SCAN_END, _FFUNC_SCAN_STEP):
            score = sum(
                1 for va in samples
                if (v := pe._r32(va + cand)) and (v & FUNC_NATIVE)
            )
            if score > best_score:
                best, best_score = cand, score

        if best_score <= 0:
            _log("FFunctionParams.FunctionFlags detection low-confidence ??using default")
            return

        off.ffunc_flags = best
        off._detected["ffunc_flags"] = True
        _log(f"FFunctionParams.FunctionFlags @ 0x{best:02X}  (score={best_score}/{len(samples)})")

    def _collect_ffunc_samples(
        self,
        z_constructs: Sequence[tuple[int, int]],
        off: DetectedOffsets,
    ) -> list[int]:
        pe = self._pe
        mm = pe._mm
        samples: list[int] = []

        for _, fcp_va in z_constructs[:_FFUNC_MAX_CLASSES]:
            bf = pe._r32(fcp_va + off.fclass_bits)
            if bf is None:
                continue
            n_funcs = (bf >> 4) & 0x7FF
            func_arr = pe._r64(fcp_va + off.fclass_funcs)
            if not func_arr or n_funcs == 0:
                continue
            for j in range(min(n_funcs, 5)):
                zf = pe._r64(func_arr + j * 16)
                if not zf:
                    continue
                zf_off = pe._va2off(zf + 16)
                if zf_off is None or mm[zf_off: zf_off + 3] != b"\x48\x8D\x15":
                    continue
                samples.append(zf + 23 + _struct.unpack_from("<i", mm, zf_off + 3)[0])
            if len(samples) >= _FFUNC_TARGET_SAMPLES:
                break

        return samples

    def _validate_fprop(
        self,
        z_constructs: Sequence[tuple[int, int]],
        off: DetectedOffsets,
    ) -> None:
        pe = self._pe
        valid = 0
        for _, fcp_va in z_constructs[:50]:
            bf = pe._r32(fcp_va + off.fclass_bits)
            if bf is None:
                continue
            n_props = (bf >> 15) & 0x7FF
            prop_arr = pe._r64(fcp_va + off.fclass_props)
            if not prop_arr or n_props == 0:
                continue

            ptr = pe._r64(prop_arr)
            if not ptr:
                continue

            name_ptr = pe._r64(ptr + off.fprop_name)
            if not name_ptr:
                continue
            name = pe._cstr(name_ptr)
            if not name or not name.isascii():
                continue

            gen_off = pe._va2off(ptr + off.fprop_gen_flags)
            if gen_off is None:
                continue
            gen = pe._mm[gen_off] & 0x3F
            if gen > 0x24:
                _log(f"FPropertyParamsBase: unexpected GenFlags 0x{gen:02X} for '{name}' - offsets may be wrong")
                return

            dim = pe._r16(ptr + off.fprop_array_dim)
            if dim is None or dim > 256:
                continue

            valid += 1
            if valid >= 3:
                _log("FPropertyParamsBase: validated OK")
                return

        if valid == 0:
            _log("FPropertyParamsBase: validation inconclusive. using defaults")

    def _validate_fstruct(
        self,
        z_constructs: Sequence[tuple[int, int]],
        off: DetectedOffsets,
    ) -> None:
        pe = self._pe
        mm = pe._mm
        valid = 0

        for _, fcp_va in z_constructs[:100]:
            bf = pe._r32(fcp_va + off.fclass_bits)
            if bf is None:
                continue
            n_props = (bf >> 15) & 0x7FF
            prop_arr = pe._r64(fcp_va + off.fclass_props)
            if not prop_arr or n_props == 0:
                continue

            for k in range(min(n_props, 20)):
                ptr = pe._r64(prop_arr + k * 8)
                if not ptr:
                    continue
                gen_off = pe._va2off(ptr + off.fprop_gen_flags)
                if gen_off is None:
                    continue
                gen = mm[gen_off] & 0x3F
                if gen != 0x19:  # GEN_STRUCT
                    continue

                z_struct = pe._r64(ptr + off.fprop_struct_func)
                if not z_struct:
                    continue

                sp_va = self._resolve_stub_params(z_struct)
                if sp_va is None:
                    continue

                # Validate FStructParams fields
                name_ptr = pe._r64(sp_va + off.fstruct_name)
                name = pe._cstr(name_ptr) if name_ptr else None
                if not name or not name.isascii():
                    continue

                count_off = pe._va2off(sp_va + off.fstruct_count)
                if count_off is None:
                    continue
                count = _struct.unpack_from("<H", mm, count_off)[0]
                if count > 512:
                    continue

                valid += 1
                if valid >= 3:
                    _log(f"FStructParams: validated OK (e.g. struct '{name}')")
                    return

        if valid == 0:
            _log("FStructParams: validation inconclusive – using defaults")

    def _read_body(self, va: int, size: int = 4096) -> bytes:
        """Read function body, following JMP thunks."""
        pe = self._pe
        o = pe._va2off(va)
        if o is None:
            return b""
        body = pe._mm[o: o + size]

        # 1:  lea r8, [rsp+XX]; jmp target  (5+5 bytes)
        if len(body) > 10 and body[5] == 0xE9:
            disp = _struct.unpack_from("<i", body, 6)[0]
            o2 = pe._va2off(va + 10 + disp)
            if o2 is not None:
                body = pe._mm[o2: o2 + size]

        # 2:  bare jmp
        elif len(body) > 5 and body[0] == 0xE9:
            disp = _struct.unpack_from("<i", body, 1)[0]
            o2 = pe._va2off(va + 5 + disp)
            if o2 is not None:
                body = pe._mm[o2: o2 + size]

        return body

    def _resolve_stub_params(self, z_construct_va: int) -> int | None:
        """Resolve FStructParams/FEnumParams pointer from a Z_Construct stub."""
        pe = self._pe
        mm = pe._mm
        base = pe._va2off(z_construct_va)
        if base is None:
            return None
        for i in range(40):
            if mm[base + i: base + i + 3] == b"\x48\x8D\x15":
                if base + i + 7 > len(mm):
                    break
                lea_va = pe._off2va(base + i)
                if lea_va is None:
                    continue
                return lea_va + 7 + _struct.unpack_from("<i", mm, base + i + 3)[0]
        return None


def _log(msg: str) -> None:
    import sys
    print(f"[*] {msg}", file=sys.stderr)

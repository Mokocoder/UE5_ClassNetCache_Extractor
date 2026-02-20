# UE5 ClassNetCache Extractor

Extracts `ClassNetCache` data (SerializeInt Max values + field indices) from Unreal Engine 5 games via static analysis of the PE binary and cooked `.pak` archives. These values are required by netcode implementations that replicate UE5 network traffic outside the engine.

**Pipeline:**

1. **class_net_cache_parser.py** &mdash; Static analysis of the game binary (PE) to extract Max values and field indices for all C++ native classes
2. **ClassNetCacheExtractor** &mdash; Reads cooked `.pak` archives via CUE4Parse to extract data for Blueprint classes, then merges both into a single output

## Requirements

- Python 3.10+ with [`pefile`](https://pypi.org/project/pefile/)
- .NET 8.0 SDK

## Build

```bash
git clone --recurse-submodules <repo-url>
cd class_net_cache_extractor
dotnet build ClassNetCacheExtractor/ClassNetCacheExtractor.csproj -c Release
```

## Usage

### Step 1: Extract C++ Seed Data

```
python class_net_cache_parser.py <Game.exe> [output.json]
```

Scans `Z_Construct_UClass` static registration stubs in the `.text` section, identifies `ConstructUClass` via fingerprint scoring, and computes Max values + field indices by walking the class hierarchy. Tested on UE 5.7.

**Example (Lyra Starter Game, UE 5.7):**

```
python class_net_cache_parser.py "LyraGame.exe" lyra_cpp_seed.json
```

```
[*] Loading LyraGame.exe...
[*] ImageBase = 0x140000000
[*] ConstructUClass @ 0x142183CF0  (5523 classes, score=3)
[*] FClassParams bitfield @ 0x38  (deps=0x18 funcs=0x20 props=0x28)
[*] FFunctionParams.FunctionFlags @ 0x28  (score=62/66)
[*] FPropertyParamsBase: validated OK
[*] FStructParams: validated OK
[*] Detected offsets: ...
[*] Mapping class names...
[*] 5523/5523 names resolved
[*] Parsing class metadata...
[*] Computing Max values and field indices...
[*] Written 5523 Max values + 553 fields (334p + 219f) → lyra_cpp_seed.json (52.7s)
```

Output format:

```json
{
  "stats": {
    "total_classes": 5523,
    "named": 5523,
    "resolved_max": 5523,
    "resolved_fields": 219,
    "total_fields": 553,
    "total_props": 334,
    "total_funcs": 219,
    "elapsed_sec": 52.7
  },
  "seed_values": {
    "AIController": 15,
    "Actor": 11,
    "Character": 17,
    ...
  },
  "per_class": {
    "Actor": {
      "fields_base": 0,
      "fields": {
        "0": { "name": "bReplicateMovement", "type": "property" },
        "1": { "name": "bHidden", "type": "property" },
        ...
      }
    },
    ...
  },
  "flat_index": {
    "Actor::bReplicateMovement": 0,
    "Actor::bHidden": 1,
    ...
  }
}
```

### Step 2: Merge Blueprint Data

```
ClassNetCacheExtractor <PaksDir> <SeedJson> [GameName] [UsmapPath] [OutputPath]
```

| Argument       | Required | Description                                                       |
| -------------- | -------- | ----------------------------------------------------------------- |
| `PaksDir`      | Yes      | Directory containing `.pak` / `.utoc` / `.ucas` files             |
| `SeedJson`     | Yes      | Output from Step 1                                                |
| `GameName`     | No       | CUE4Parse `EGame` enum value (default: `GAME_UE5_7`)             |
| `UsmapPath`    | No       | Path to `.usmap` mappings file, required for unversioned packages |
| `OutputPath`   | No       | Output JSON path (default: `./class_net_cache.json`)              |

**Example (Lyra Starter Game, UE 5.7):**

```
dotnet run --project ClassNetCacheExtractor -c Release -- \
  "LyraStarterGame/Content/Paks" \
  lyra_cpp_seed.json \
  GAME_UE5_7
```

```
[*] Loaded 5523 C++ seed values, 92 field entries
[*] Mounted 6 containers, 9828 files (175ms)
[*] Scanning 3834 packages...
[*] Scan complete: 292 BPs in 3834 packages (704ms)
[*] Resolved: 289, Unresolved: 0
[*] Field indices: 553 C++ + 30 BP = 583 total
[*] Written 5812 Max values (5523 C++ + 289 BP), 583 fields → class_net_cache.json
```

Output format:

```json
{
  "stats": {
    "cpp_classes": 5523,
    "bp_classes": 289,
    "resolved": 5812,
    "unresolved": 0,
    "total_fields": 583,
    "packages": 3834,
    "skipped": 3542,
    "errors": 0
  },
  "max_values": {
    "AIController": 15,
    "Actor": 11,
    "Character": 17,
    ...
  },
  "per_class": {
    "Actor": {
      "fields_base": 0,
      "fields": {
        "0": { "name": "bReplicateMovement", "type": "property" },
        ...
      }
    },
    ...
  },
  "flat_index": {
    "Actor::bReplicateMovement": 0,
    ...
  }
}
```

## Notes

- **Unversioned packages**: Most shipping builds use unversioned property serialization. In this case, a `.usmap` mappings file is required for Step 2. Use [UnrealMappingsDumper](https://github.com/TheNaeem/UnrealMappingsDumper) to generate one from a running process.
- **UE version support**: Struct offsets are auto-detected from the binary. Tested on UE 5.7.

## Example Output

The [`example/`](example/) directory contains extraction results from [Lyra Starter Game](https://dev.epicgames.com/documentation/en-us/unreal-engine/lyra-sample-game-in-unreal-engine) (UE 5.7):

- `lyra_cpp_seed.json` &mdash; 5,523 C++ native classes (Max values + 553 field indices)
- `lyra_class_net_cache.json` &mdash; 5,812 merged classes (C++ + Blueprint, 583 field indices)

## Project Structure

```
├── pe_analyzer.py                          # Shared PE binary analysis module
├── layout_detector.py                      # Auto-detect struct offsets from Construct* code patterns
├── class_net_cache_parser.py               # Step 1: PE binary → C++ seed data
├── ClassNetCacheExtractor/
│   ├── ClassNetCacheExtractor.csproj
│   └── Program.cs                          # Step 2: .pak archives → merged output
├── CUE4Parse/                              # Git submodule
└── example/
    ├── lyra_cpp_seed.json
    └── lyra_class_net_cache.json
```

## License

This project uses [CUE4Parse](https://github.com/FabianFG/CUE4Parse) (Apache-2.0) as a git submodule.

using System.Diagnostics;
using CUE4Parse.Compression;
using CUE4Parse.FileProvider;
using CUE4Parse.UE4.Assets;
using CUE4Parse.UE4.Assets.Exports;
using CUE4Parse.UE4.IO.Objects;
using CUE4Parse.UE4.Objects.Engine;
using CUE4Parse.UE4.Objects.UObject;
using CUE4Parse.UE4.Versions;
using CUE4Parse.MappingsProvider;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

// ─── Args ───
if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: ClassNetCacheExtractor <PaksDir> <SeedJson> [GameName] [UsmapPath] [OutputPath]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("  PaksDir:    Game .pak directory");
    Console.Error.WriteLine("  SeedJson:   C++ class_net_cache seed (from class_net_cache_parser.py)");
    Console.Error.WriteLine("  GameName:   CUE4Parse EGame enum (default: GAME_UE5_7)");
    Console.Error.WriteLine("  UsmapPath:  .usmap mappings file path");
    Console.Error.WriteLine("  OutputPath: Output file (default: class_net_cache.json)");
    return 1;
}

var paksDir = args[0];
var seedPath = args[1];
var gameName = args.Length > 2 ? args[2] : "GAME_UE5_7";
var usmapPath = args.Length > 3 ? args[3] : "";
var outputPath = args.Length > 4 ? args[4]
    : Path.Combine(Environment.CurrentDirectory, "class_net_cache.json");

// ─── Resolve EGame ───
if (!Enum.TryParse<EGame>(gameName, ignoreCase: true, out var eGame))
{
    Console.Error.WriteLine($"[!] Unknown game: {gameName}");
    Console.Error.WriteLine($"    Available: {string.Join(", ", Enum.GetNames<EGame>().Where(n => n.StartsWith("GAME_UE5")).Take(10))}...");
    return 1;
}

// ─── Load seed data (from z_construct_parser.py output) ───
Log($"Loading seed data from {seedPath}...");
var seedJson = JObject.Parse(File.ReadAllText(seedPath));
var seedValues = seedJson["seed_values"]!.ToObject<Dictionary<string, int>>()!;
var seedPerClass = seedJson["per_class"] as JObject ?? new JObject();
var seedFlatIndex = seedJson["flat_index"]?.ToObject<Dictionary<string, int>>()
    ?? new Dictionary<string, int>();
Log($"Loaded {seedValues.Count} C++ seed values, {seedPerClass.Count} field entries");

// ─── Oodle ───
InitOodle();

// ─── CUE4Parse ───
var sw = Stopwatch.StartNew();
var provider = new DefaultFileProvider(
    paksDir,
    SearchOption.TopDirectoryOnly,
    new VersionContainer(eGame),
    StringComparer.OrdinalIgnoreCase);

provider.Initialize();
if (File.Exists(usmapPath))
{
    provider.MappingsContainer = new FileUsmapTypeMappingsProvider(usmapPath);
    Log($"Loaded mappings: {usmapPath}");
}
provider.Mount();
Log($"Mounted {provider.MountedVfs.Count} containers, {provider.Files.Count} files ({sw.ElapsedMilliseconds}ms)");

// ─── Find BlueprintGeneratedClass index for fast filtering ───
var bpClassIdx = FindBpClassIndex(provider);

// ─── Scan packages ───
var classes = new Dictionary<string, (string Parent, List<(string Name, string Type, int ArrayDim)> Fields)>();
int packageCount = 0, bpCount = 0, errorCount = 0, skippedCount = 0;

var packageFiles = provider.Files
    .Where(kvp => kvp.Value.IsUePackage)
    .ToList();

Log($"Scanning {packageFiles.Count} packages...");
sw.Restart();

foreach (var (path, gameFile) in packageFiles)
{
    packageCount++;
    if (packageCount % 10000 == 0)
        Log($"  {packageCount}/{packageFiles.Count} ({bpCount} BPs, {sw.ElapsedMilliseconds}ms)...");

    try
    {
        var package = provider.LoadPackage(gameFile);

        if (package is IoPackage io && bpClassIdx != FPackageObjectIndex.InvalidObjectIndex)
        {
            bool found = false;
            for (int i = 0; i < io.ExportMap.Length; i++)
            {
                if (io.ExportMap[i].ClassIndex != bpClassIdx) continue;
                found = true;
                try
                {
                    if (io.ExportsLazy[i].Value is UBlueprintGeneratedClass bp)
                        ProcessBpClass(bp, classes, ref bpCount);
                }
                catch { errorCount++; }
            }
            if (!found) skippedCount++;
        }
        else
        {
            foreach (var export in package.GetExports())
                if (export is UBlueprintGeneratedClass bp)
                    ProcessBpClass(bp, classes, ref bpCount);
        }
    }
    catch (Exception ex)
    {
        if (errorCount++ == 0) Log($"First error: {ex.Message}");
    }
}

sw.Stop();
Log($"Scan complete: {bpCount} BPs in {packageCount} packages ({sw.ElapsedMilliseconds}ms)");
Log($"Skipped {skippedCount} packages (no BP exports), {errorCount} errors");

// ─── Resolve Max values ───
var maxValues = new SortedDictionary<string, int>();
var maxCache = new Dictionary<string, int?>();
int unresolvedCount = 0;

foreach (var (name, _) in classes)
{
    var max = ResolveMax(name, [], seedValues, classes, maxCache);
    if (max.HasValue)
        maxValues[name] = max.Value;
    else
        unresolvedCount++;
}

Log($"Resolved: {maxValues.Count}, Unresolved: {unresolvedCount}");

// ─── Merge seed + BP Max values ───
foreach (var (name, val) in seedValues)
    maxValues.TryAdd(name, val);

// ─── Build field indices ───
var perClass = new SortedDictionary<string, object>();
var flatIndex = new SortedDictionary<string, int>();

// C++ field data (pass-through from seed)
foreach (var prop in seedPerClass.Properties())
    perClass[prop.Name] = prop.Value;
foreach (var (key, val) in seedFlatIndex)
    flatIndex[key] = val;

// BP field data
int bpFieldCount = 0;
foreach (var (name, info) in classes)
{
    if (!maxValues.TryGetValue(name, out var max)) continue;
    if (info.Fields.Count == 0) continue;

    var fieldsBase = max - info.Fields.Count - 1;
    var fields = new SortedDictionary<string, object>();
    for (int i = 0; i < info.Fields.Count; i++)
    {
        var h = fieldsBase + i;
        var f = info.Fields[i];
        object entry = f.ArrayDim > 1
            ? new { name = f.Name, type = f.Type, array_dim = f.ArrayDim }
            : new { name = f.Name, type = f.Type };
        fields[h.ToString()] = entry;
        flatIndex[$"{name}::{f.Name}"] = h;
    }
    perClass[name] = new { fields_base = fieldsBase, fields };
    bpFieldCount += info.Fields.Count;
}

var totalFields = seedFlatIndex.Count + bpFieldCount;
Log($"Field indices: {seedFlatIndex.Count} C++ + {bpFieldCount} BP = {totalFields} total");

// ─── Output ───
var output = new
{
    stats = new
    {
        cpp_classes = seedValues.Count,
        bp_classes = classes.Count,
        resolved = maxValues.Count,
        unresolved = unresolvedCount,
        total_fields = totalFields,
        packages = packageCount,
        skipped = skippedCount,
        errors = errorCount,
    },
    max_values = maxValues,
    per_class = perClass,
    flat_index = flatIndex,
};

var outputDir = Path.GetDirectoryName(outputPath);
if (!string.IsNullOrEmpty(outputDir))
    Directory.CreateDirectory(outputDir);
File.WriteAllText(outputPath, JsonConvert.SerializeObject(output, Formatting.Indented));
Log($"Written {maxValues.Count} Max values ({seedValues.Count} C++ + {maxValues.Count - seedValues.Count} BP), "
    + $"{totalFields} fields → {outputPath}");

provider.Dispose();
Log("Done.");
return 0;

// ──────────────────────────────────────────────────────────────────────

void ProcessBpClass(
    UBlueprintGeneratedClass bpClass,
    Dictionary<string, (string Parent, List<(string Name, string Type, int ArrayDim)> Fields)> dict,
    ref int count)
{
    count++;
    var parent = bpClass.SuperStruct is { IsNull: false }
        ? bpClass.SuperStruct.Name : "Unknown";

    var fields = new List<(string Name, string Type, int ArrayDim)>();

    if (bpClass.ChildProperties != null)
        foreach (var field in bpClass.ChildProperties)
            if (field is FProperty prop && prop.PropertyFlags.HasFlag(EPropertyFlags.Net))
                fields.Add((prop.Name.Text, "property", prop.ArrayDim));

    if (bpClass.FuncMap != null)
        foreach (var (funcName, funcIdx) in bpClass.FuncMap)
            try
            {
                if (funcIdx.TryLoad<UFunction>(out var f) &&
                    f.FunctionFlags.HasFlag(EFunctionFlags.FUNC_Net))
                    fields.Add((funcName.Text, "function", 0));
            }
            catch { }

    dict[bpClass.Name] = (parent, fields);
}

int? ResolveMax(
    string name, HashSet<string> visited,
    Dictionary<string, int> seeds,
    Dictionary<string, (string Parent, List<(string Name, string Type, int ArrayDim)> Fields)> cls,
    Dictionary<string, int?> c)
{
    if (c.TryGetValue(name, out var cached)) return cached;
    if (seeds.TryGetValue(name, out var seed)) { c[name] = seed; return seed; }
    if (!cls.TryGetValue(name, out var info) || !visited.Add(name)) return null;

    var parentMax = ResolveMax(info.Parent, visited, seeds, cls, c);
    if (parentMax == null) return null;

    var result = parentMax.Value + info.Fields.Count;
    c[name] = result;
    return result;
}

FPackageObjectIndex FindBpClassIndex(DefaultFileProvider prov)
{
    if (prov.GlobalData == null)
        return FPackageObjectIndex.InvalidObjectIndex;

    foreach (var (idx, entry) in prov.GlobalData.ScriptObjectEntriesMap)
    {
        if (!entry.ObjectName.IsGlobal) continue;
        var nameIdx = (int)entry.ObjectName.NameIndex;
        if (nameIdx < prov.GlobalData.GlobalNameMap.Length &&
            prov.GlobalData.GlobalNameMap[nameIdx].Name == "BlueprintGeneratedClass")
        {
            Log($"BlueprintGeneratedClass index: 0x{idx.TypeAndId:X16}");
            return idx;
        }
    }

    Log("BlueprintGeneratedClass not found in global data, using full scan");
    return FPackageObjectIndex.InvalidObjectIndex;
}

void InitOodle()
{
    string? path = Path.Combine(AppContext.BaseDirectory, OodleHelper.OodleFileName);
    if (!File.Exists(path))
        path = Path.Combine(Environment.CurrentDirectory, OodleHelper.OodleFileName);
    if (!File.Exists(path))
        path = null;

    OodleHelper.Initialize(path);

    if (OodleHelper.Instance != null)
    {
        Log("Oodle initialized");
        return;
    }

    Log("Oodle not found, downloading...");
    string? dlPath = Path.Combine(AppContext.BaseDirectory, OodleHelper.OodleFileName);
    if (OodleHelper.DownloadOodleDll(ref dlPath))
    {
        OodleHelper.Initialize(dlPath);
        Log("Oodle downloaded and initialized");
    }
    else
    {
        Console.Error.WriteLine("[!] Failed to initialize Oodle");
        Environment.Exit(1);
    }
}

void Log(string msg) => Console.Error.WriteLine($"[*] {msg}");

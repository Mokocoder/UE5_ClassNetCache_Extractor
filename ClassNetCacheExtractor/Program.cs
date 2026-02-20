using System.Diagnostics;
using CUE4Parse.Compression;
using CUE4Parse.FileProvider;
using CUE4Parse.MappingsProvider;
using CUE4Parse.UE4.Assets;
using CUE4Parse.UE4.Assets.Exports;
using CUE4Parse.UE4.IO.Objects;
using CUE4Parse.UE4.Objects.Engine;
using CUE4Parse.UE4.Objects.UObject;
using CUE4Parse.UE4.Versions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

internal static class Program
{
    private const string DefaultGameName = "GAME_UE5_7";
    private const string DefaultOutputFileName = "class_net_cache.json";
    private const int ScanProgressInterval = 10_000;

    private sealed record CliOptions(
        string PaksDir,
        string SeedPath,
        string GameName,
        string UsmapPath,
        string OutputPath);

    private sealed record SeedData(
        Dictionary<string, int> SeedValues,
        JObject SeedPerClass,
        Dictionary<string, int> SeedFlatIndex);

    private sealed record BpField(string Name, string Type, int ArrayDim);

    private sealed record BpClassInfo(string Parent, List<BpField> Fields);

    private sealed record ScanStats(
        int PackageCount,
        int BlueprintCount,
        int ErrorCount,
        int SkippedCount);

    private sealed record ScanResult(
        Dictionary<string, BpClassInfo> Classes,
        ScanStats Stats);

    private sealed record MergeStats(
        int UnresolvedCount,
        int BpFieldCount,
        int TotalFieldCount);

    private sealed record MergeResult(
        SortedDictionary<string, int> MaxValues,
        SortedDictionary<string, object> PerClass,
        SortedDictionary<string, int> FlatIndex,
        MergeStats Stats);

    public static int Main(string[] args)
    {
        if (!TryParseOptions(args, out var options))
        {
            return 1;
        }

        if (!TryResolveGame(options.GameName, out var eGame))
        {
            return 1;
        }

        try
        {
            var seed = LoadSeedData(options.SeedPath);
            InitOodle();

            using var provider = CreateProvider(options.PaksDir, eGame, options.UsmapPath);
            var bpClassIdx = FindBpClassIndex(provider);
            var scanResult = ScanBlueprintClasses(provider, bpClassIdx);
            var mergeResult = MergeSeedAndBlueprint(seed, scanResult.Classes);

            WriteOutput(options.OutputPath, seed, scanResult.Stats, scanResult.Classes.Count, mergeResult);
            Log(
                $"Written {mergeResult.MaxValues.Count} Max values "
                + $"({seed.SeedValues.Count} C++ + {mergeResult.MaxValues.Count - seed.SeedValues.Count} BP), "
                + $"{mergeResult.Stats.TotalFieldCount} fields -> {options.OutputPath}");
            Log("Done.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] {ex.Message}");
            return 1;
        }
    }

    private static bool TryParseOptions(string[] args, out CliOptions options)
    {
        if (args.Length < 2)
        {
            PrintUsage();
            options = null!;
            return false;
        }

        var paksDir = args[0];
        var seedPath = args[1];
        var gameName = args.Length > 2 ? args[2] : DefaultGameName;
        var usmapPath = args.Length > 3 ? args[3] : string.Empty;
        var outputPath = args.Length > 4
            ? args[4]
            : Path.Combine(Environment.CurrentDirectory, DefaultOutputFileName);

        options = new CliOptions(paksDir, seedPath, gameName, usmapPath, outputPath);
        return true;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("Usage: ClassNetCacheExtractor <PaksDir> <SeedJson> [GameName] [UsmapPath] [OutputPath]");
        Console.Error.WriteLine();
        Console.Error.WriteLine("  PaksDir:    Game .pak directory");
        Console.Error.WriteLine("  SeedJson:   C++ class_net_cache seed (from class_net_cache_parser.py)");
        Console.Error.WriteLine($"  GameName:   CUE4Parse EGame enum (default: {DefaultGameName})");
        Console.Error.WriteLine("  UsmapPath:  .usmap mappings file path");
        Console.Error.WriteLine($"  OutputPath: Output file (default: {DefaultOutputFileName})");
    }

    private static bool TryResolveGame(string gameName, out EGame eGame)
    {
        if (Enum.TryParse(gameName, ignoreCase: true, out eGame))
        {
            return true;
        }

        var available = string.Join(
            ", ",
            Enum.GetNames<EGame>()
                .Where(name =>
                    name.StartsWith("GAME_UE5", StringComparison.Ordinal)
                    || name.Contains("ARK", StringComparison.OrdinalIgnoreCase))
                .Take(12));

        Console.Error.WriteLine($"[!] Unknown game: {gameName}");
        Console.Error.WriteLine($"    Available: {available}...");
        return false;
    }

    private static SeedData LoadSeedData(string seedPath)
    {
        Log($"Loading seed data from {seedPath}...");
        var seedJson = JObject.Parse(File.ReadAllText(seedPath));

        var seedValues = seedJson["seed_values"]?.ToObject<Dictionary<string, int>>()
            ?? throw new InvalidDataException("seed JSON is missing 'seed_values'");
        var seedPerClass = seedJson["per_class"] as JObject ?? new JObject();
        var seedFlatIndex = seedJson["flat_index"]?.ToObject<Dictionary<string, int>>()
            ?? new Dictionary<string, int>(StringComparer.Ordinal);

        Log($"Loaded {seedValues.Count} C++ seed values, {seedPerClass.Count} field entries");
        return new SeedData(seedValues, seedPerClass, seedFlatIndex);
    }

    private static DefaultFileProvider CreateProvider(string paksDir, EGame eGame, string usmapPath)
    {
        var sw = Stopwatch.StartNew();
        var provider = new DefaultFileProvider(
            paksDir,
            SearchOption.TopDirectoryOnly,
            new VersionContainer(eGame),
            StringComparer.OrdinalIgnoreCase);

        provider.Initialize();
        if (!string.IsNullOrWhiteSpace(usmapPath) && File.Exists(usmapPath))
        {
            provider.MappingsContainer = new FileUsmapTypeMappingsProvider(usmapPath);
            Log($"Loaded mappings: {usmapPath}");
        }

        provider.Mount();
        Log($"Mounted {provider.MountedVfs.Count} containers, {provider.Files.Count} files ({sw.ElapsedMilliseconds}ms)");
        return provider;
    }

    private static ScanResult ScanBlueprintClasses(DefaultFileProvider provider, FPackageObjectIndex bpClassIdx)
    {
        var classes = new Dictionary<string, BpClassInfo>(StringComparer.Ordinal);
        var packageCount = 0;
        var bpCount = 0;
        var errorCount = 0;
        var skippedCount = 0;

        var packageFiles = provider.Files
            .Where(static kvp => kvp.Value.IsUePackage)
            .ToList();

        Log($"Scanning {packageFiles.Count} packages...");
        var sw = Stopwatch.StartNew();

        foreach (var (_, gameFile) in packageFiles)
        {
            packageCount++;
            if (packageCount % ScanProgressInterval == 0)
            {
                Log($"  {packageCount}/{packageFiles.Count} ({bpCount} BPs, {sw.ElapsedMilliseconds}ms)...");
            }

            try
            {
                var package = provider.LoadPackage(gameFile);

                if (package is IoPackage io && bpClassIdx != FPackageObjectIndex.InvalidObjectIndex)
                {
                    var found = false;
                    for (var i = 0; i < io.ExportMap.Length; i++)
                    {
                        if (io.ExportMap[i].ClassIndex != bpClassIdx)
                        {
                            continue;
                        }

                        found = true;
                        try
                        {
                            if (io.ExportsLazy[i].Value is UBlueprintGeneratedClass bp)
                            {
                                ProcessBpClass(bp, classes, ref bpCount);
                            }
                        }
                        catch
                        {
                            errorCount++;
                        }
                    }

                    if (!found)
                    {
                        skippedCount++;
                    }
                }
                else
                {
                    foreach (var export in package.GetExports())
                    {
                        if (export is UBlueprintGeneratedClass bp)
                        {
                            ProcessBpClass(bp, classes, ref bpCount);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (errorCount++ == 0)
                {
                    Log($"First error: {ex.Message}");
                }
            }
        }

        sw.Stop();
        Log($"Scan complete: {bpCount} BPs in {packageCount} packages ({sw.ElapsedMilliseconds}ms)");
        Log($"Skipped {skippedCount} packages (no BP exports), {errorCount} errors");

        return new ScanResult(classes, new ScanStats(packageCount, bpCount, errorCount, skippedCount));
    }

    private static MergeResult MergeSeedAndBlueprint(
        SeedData seed,
        Dictionary<string, BpClassInfo> classes)
    {
        var maxValues = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var maxCache = new Dictionary<string, int?>(StringComparer.Ordinal);
        var unresolvedCount = 0;

        foreach (var name in classes.Keys)
        {
            var max = ResolveMax(
                name,
                new HashSet<string>(StringComparer.Ordinal),
                seed.SeedValues,
                classes,
                maxCache);
            if (max.HasValue)
            {
                maxValues[name] = max.Value;
            }
            else
            {
                unresolvedCount++;
            }
        }

        Log($"Resolved: {maxValues.Count}, Unresolved: {unresolvedCount}");

        foreach (var (name, value) in seed.SeedValues)
        {
            maxValues.TryAdd(name, value);
        }

        var perClass = new SortedDictionary<string, object>(StringComparer.Ordinal);
        var flatIndex = new SortedDictionary<string, int>(StringComparer.Ordinal);

        foreach (var prop in seed.SeedPerClass.Properties())
        {
            perClass[prop.Name] = prop.Value.DeepClone();
        }
        foreach (var (key, value) in seed.SeedFlatIndex)
        {
            flatIndex[key] = value;
        }

        var bpFieldCount = 0;
        foreach (var (name, info) in classes)
        {
            if (!maxValues.TryGetValue(name, out var max))
            {
                continue;
            }
            if (info.Fields.Count == 0)
            {
                continue;
            }

            var fieldsBase = max - info.Fields.Count - 1;
            var fields = new SortedDictionary<string, object>(StringComparer.Ordinal);
            for (var i = 0; i < info.Fields.Count; i++)
            {
                var handle = fieldsBase + i;
                var field = info.Fields[i];

                object entry = field.ArrayDim > 1
                    ? new { name = field.Name, type = field.Type, array_dim = field.ArrayDim }
                    : new { name = field.Name, type = field.Type };

                fields[handle.ToString()] = entry;
                flatIndex[$"{name}::{field.Name}"] = handle;
            }

            perClass[name] = new { fields_base = fieldsBase, fields };
            bpFieldCount += info.Fields.Count;
        }

        var totalFields = seed.SeedFlatIndex.Count + bpFieldCount;
        Log($"Field indices: {seed.SeedFlatIndex.Count} C++ + {bpFieldCount} BP = {totalFields} total");

        return new MergeResult(
            maxValues,
            perClass,
            flatIndex,
            new MergeStats(unresolvedCount, bpFieldCount, totalFields));
    }

    private static void ProcessBpClass(
        UBlueprintGeneratedClass bpClass,
        Dictionary<string, BpClassInfo> dict,
        ref int count)
    {
        count++;
        var parent = bpClass.SuperStruct is { IsNull: false }
            ? bpClass.SuperStruct.Name
            : "Unknown";

        var fields = new List<BpField>();

        if (bpClass.ChildProperties != null)
        {
            foreach (var field in bpClass.ChildProperties)
            {
                if (field is FProperty prop && prop.PropertyFlags.HasFlag(EPropertyFlags.Net))
                {
                    fields.Add(new BpField(prop.Name.Text, "property", prop.ArrayDim));
                }
            }
        }

        if (bpClass.FuncMap != null)
        {
            foreach (var (funcName, funcIdx) in bpClass.FuncMap)
            {
                try
                {
                    if (funcIdx.TryLoad<UFunction>(out var f)
                        && f.FunctionFlags.HasFlag(EFunctionFlags.FUNC_Net))
                    {
                        fields.Add(new BpField(funcName.Text, "function", 0));
                    }
                }
                catch
                {
                    // Ignore per-function decode errors and continue scanning.
                }
            }
        }

        dict[bpClass.Name] = new BpClassInfo(parent, fields);
    }

    private static int? ResolveMax(
        string name,
        HashSet<string> visited,
        Dictionary<string, int> seeds,
        Dictionary<string, BpClassInfo> classes,
        Dictionary<string, int?> cache)
    {
        if (cache.TryGetValue(name, out var cached))
        {
            return cached;
        }
        if (seeds.TryGetValue(name, out var seed))
        {
            cache[name] = seed;
            return seed;
        }
        if (!classes.TryGetValue(name, out var info) || !visited.Add(name))
        {
            return null;
        }

        try
        {
            var parentMax = ResolveMax(info.Parent, visited, seeds, classes, cache);
            if (parentMax == null)
            {
                cache[name] = null;
                return null;
            }

            var result = parentMax.Value + info.Fields.Count;
            cache[name] = result;
            return result;
        }
        finally
        {
            visited.Remove(name);
        }
    }

    private static void WriteOutput(
        string outputPath,
        SeedData seed,
        ScanStats scanStats,
        int bpClassCount,
        MergeResult mergeResult)
    {
        var output = new
        {
            stats = new
            {
                cpp_classes = seed.SeedValues.Count,
                bp_classes = bpClassCount,
                resolved = mergeResult.MaxValues.Count,
                unresolved = mergeResult.Stats.UnresolvedCount,
                total_fields = mergeResult.Stats.TotalFieldCount,
                packages = scanStats.PackageCount,
                skipped = scanStats.SkippedCount,
                errors = scanStats.ErrorCount,
            },
            max_values = mergeResult.MaxValues,
            per_class = mergeResult.PerClass,
            flat_index = mergeResult.FlatIndex,
        };

        var outputDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }

        File.WriteAllText(outputPath, JsonConvert.SerializeObject(output, Formatting.Indented));
    }

    private static FPackageObjectIndex FindBpClassIndex(DefaultFileProvider provider)
    {
        if (provider.GlobalData == null)
        {
            return FPackageObjectIndex.InvalidObjectIndex;
        }

        foreach (var (idx, entry) in provider.GlobalData.ScriptObjectEntriesMap)
        {
            if (!entry.ObjectName.IsGlobal)
            {
                continue;
            }

            var nameIdx = (int)entry.ObjectName.NameIndex;
            if (nameIdx >= provider.GlobalData.GlobalNameMap.Length)
            {
                continue;
            }
            if (provider.GlobalData.GlobalNameMap[nameIdx].Name != "BlueprintGeneratedClass")
            {
                continue;
            }

            Log($"BlueprintGeneratedClass index: 0x{idx.TypeAndId:X16}");
            return idx;
        }

        Log("BlueprintGeneratedClass not found in global data, using full scan");
        return FPackageObjectIndex.InvalidObjectIndex;
    }

    private static void InitOodle()
    {
        string? path = Path.Combine(AppContext.BaseDirectory, OodleHelper.OodleFileName);
        if (!File.Exists(path))
        {
            path = Path.Combine(Environment.CurrentDirectory, OodleHelper.OodleFileName);
        }
        if (!File.Exists(path))
        {
            path = null;
        }

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
            return;
        }

        throw new InvalidOperationException("Failed to initialize Oodle");
    }

    private static void Log(string msg) => Console.Error.WriteLine($"[*] {msg}");
}

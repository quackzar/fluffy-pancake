using System.Globalization;
using System.Text;

namespace magic;

public class BenchmarkEntry
{
    public string Name { get; set; }
    public double Time { get; set; }
    public TimeSpan TimeSpan { get; set; }
    public double Throughput { get; set; }
    public double Elements { get; set; }
    public string ElementUnit { get; set; }

    public override string ToString() => $"{Name}: {TimeSpan.TotalMilliseconds:N2} ms, {Elements:N0} {ElementUnit}, {Throughput:N2} {ElementUnit}/s";
}

public class Benchmark
{
    public string Name { get; set; }
    public double Elements { get; set; }
    public List<BenchmarkEntry> Entries { get; set; } = new();
    public string DataFile { get; set; } = "";
    public BenchmarkGroup Group { get; set; }

    public override string ToString() => Name;
}

public class BenchmarkGroup
{
    public string Name { get; set; }
    public Dictionary<string, Benchmark> Benchmarks { get; set; } = new();

    public Benchmark Benchmark(string name)
    {
        if (Benchmarks.TryGetValue(name, out var actual))
        {
            return actual;
        }

        var benchmark = new Benchmark
        {
            Name = name,
            Group = this,
        };
        Benchmarks.Add(name, benchmark);
        return benchmark;
    }

    public override string ToString() => Name;
}

internal static class Program
{
    internal record Result(double Elements, double Elapsed, TimeSpan Span);

    private static string NormalizeName(string name)
    {
        var newName = new StringBuilder(name.Length);

        foreach (var c in name)
        {
            newName.Append(c switch
            {
                ' ' => '_',
                ',' => '_',
                '-' => '_',
                _ => char.ToLower(c)
            });
        }

        return newName.ToString();
    }

    internal static void Main(string[] args)
    {
        var inputFolder = args[0];
        var dataFolder = args[1];
        var plotsFolder = args[2];
        
        if (!Directory.Exists(dataFolder))
        {
            Directory.CreateDirectory(dataFolder);
        }
        
        if (!Directory.Exists(plotsFolder))
        {
            Directory.CreateDirectory(plotsFolder);
        }

        // Find the files with data to be plotted
        var files = from file
            in Directory.GetFiles(inputFolder, "*.csv", SearchOption.AllDirectories)
            where file.Contains($"new{Path.DirectorySeparatorChar}")
            select (Path.GetRelativePath(inputFolder, file), File.ReadAllLines(file));

        // Combine the data into lists of results
        var groups = new Dictionary<string, BenchmarkGroup>();
        BenchmarkGroup Group(string name)
        {
            if (groups.TryGetValue(name, out var actual))
            {
                return actual;
            }

            var group = new BenchmarkGroup
            {
                Name = name
            };
            groups.Add(name, group);
            return group;
        }

        var entries = new Dictionary<string, List<Result>>();
        foreach (var (file, lines) in files)
        {
            var line = lines.Last()!;
            var data = new StringBuilder(line.Length);
            var isInString = false;
            foreach (var c in line)
            {
                if (c == '"')
                {
                    isInString = !isInString;
                    continue;
                }

                if (isInString && c == ',')
                {
                    data.Append(';');
                    continue;
                }

                data.Append(c);
            }

            var columns = data.ToString().Split(',');

            var groupName = columns[0].Replace(";", ",");
            var benchmarkName = columns[1].Replace(";", ",");
            var elements = double.Parse(columns[2]);
            var throughputValue = columns[3];
            var throughputType = columns[4];
            var time = double.Parse(columns[5]);
            var count = double.Parse(columns[7]);

            var average = time / count;
            var throughput = elements / (average / 1_000_000_000d);
            var span = TimeSpan.FromMilliseconds(average / (1000d * 1000d));

            var entry = new BenchmarkEntry
            {
                Name = benchmarkName,
                Elements = elements,
                ElementUnit = "Element",
                Throughput = throughput,
                Time = average,
                TimeSpan = span
            };
            var group = Group(groupName);
            var benchmark = group.Benchmark(benchmarkName);
            benchmark.Entries.Add(entry);
            benchmark.Elements = entry.Elements;
        }

        // Output the data as .dat files
        var outputCulture = CultureInfo.GetCultureInfo("en-US");
        foreach (var group in groups.Values)
        {
            foreach (var benchmark in group.Benchmarks.Values)
            {
                // Note that the number of elements should be the same for all entries in a benchmark
                var dataFileName = Path.Combine(dataFolder, NormalizeName($"{group.Name}_{benchmark.Name}") + ".dat");
                using var dataFile = File.CreateText(dataFileName);

                benchmark.Entries = benchmark.Entries.OrderBy(entry => entry.Elements).ToList();
                benchmark.DataFile = dataFileName;

                dataFile.WriteLine("#Input Size\tAverage Time (ns)\tThroughput (elements/s)");
                foreach(var entry in benchmark.Entries)
                {
                    dataFile.WriteLine($"{Math.Floor(entry.Elements).ToString(outputCulture)}\t{entry.TimeSpan.TotalMilliseconds.ToString(outputCulture)}\t{entry.Throughput.ToString(outputCulture)}");
                }

                dataFile.Close();
            }
        }
        
        // Generate plots for each group
        foreach (var group in groups.Values)
        {
            var entry = group.Benchmarks.Values.First().Entries.First();
            
            // Time plot
            {
                var plotFileName = Path.Combine(plotsFolder, NormalizeName(group.Name) + ".plt");
                using var plotFile = File.CreateText(plotFileName);

                plotFile.WriteLine(@"set timestamp");
                plotFile.WriteLine(@$"set title ""{group.Name}""");
                plotFile.WriteLine(@"set key default");
                plotFile.WriteLine(@$"set xlabel ""Number of {entry.ElementUnit}s""");
                plotFile.WriteLine(@"set logscale x 2");
                plotFile.WriteLine(@$"set ylabel ""Runtime (ms)""");
                plotFile.WriteLine(@"set logscale y 2");
                plotFile.WriteLine();

                var benches = group.Benchmarks.Values.AsEnumerable();
                var plotFiles = from bench in benches
                    let relativePath = Path.GetRelativePath(plotsFolder, bench.DataFile).Replace("\\", "/")
                    select @$"""{relativePath}"" using 1:2 title ""{bench.Name}"" with lines";
                var plotLine = string.Join(',', plotFiles);
                plotFile.WriteLine(@"plot " + plotLine);

                plotFile.Close();
            }
            
            // Throughput plot
            {
                var plotFileName = Path.Combine(plotsFolder, NormalizeName(group.Name) + "_throughput.plt");
                using var plotFile = File.CreateText(plotFileName);

                plotFile.WriteLine(@"set timestamp");
                plotFile.WriteLine(@$"set title ""{group.Name}""");
                plotFile.WriteLine(@"set key default");
                plotFile.WriteLine(@$"set xlabel ""Number of {entry.ElementUnit}s""");
                plotFile.WriteLine(@"set logscale x 2");
                plotFile.WriteLine(@$"set ylabel ""Throughput in {entry.ElementUnit}/s""");
                plotFile.WriteLine(@"set logscale y 2");
                plotFile.WriteLine();

                var benches = group.Benchmarks.Values.AsEnumerable();
                var plotFiles = from bench in benches
                    let relativePath = Path.GetRelativePath(plotsFolder, bench.DataFile)
                    select @$"""{relativePath}"" using 1:3 title ""{bench.Name}"" with lines";
                var plotLine = string.Join(',', plotFiles);
                plotFile.WriteLine(@"plot " + plotLine);

                plotFile.Close();
            }
        }
        
        // Write aggregated results to the console
        foreach (var group in groups.Values)
        {
            foreach (var benchmark in group.Benchmarks.Values)
            {
                Console.WriteLine($"{group.Name}/{benchmark.Name}");
                foreach(var entry in benchmark.Entries)
                {
                    Console.WriteLine($"{group.Name}/{benchmark.Name}/{Math.Floor(entry.Elements):N0}> {entry.TimeSpan.TotalMilliseconds:N2} ms, {entry.Throughput:N2} {entry.ElementUnit}/s");
                }
                Console.WriteLine();
            }
        }
    }
}
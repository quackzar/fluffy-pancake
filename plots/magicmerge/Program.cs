using System.Text;

namespace magic;

internal static class Program
{
    internal record Result(double Elements, double Elapsed, TimeSpan Span);
    
    internal static void Main(string[] args)
    {
        const string input = "/Users/Frederik/Repositories/magic-pake/plots/target";

        // Find the files
        var files = from file
                    in Directory.GetFiles(input, "*.csv", SearchOption.AllDirectories)
                    where file.Contains($"new{Path.DirectorySeparatorChar}")
                    select (Path.GetRelativePath(input, file), File.ReadAllLines(file));

        // Build the data
        var entries = new Dictionary<string, List<Result>>();
        foreach (var (file, lines) in files)
        {
            var segments = file.Split(Path.DirectorySeparatorChar);
            var key = segments[1];
            var name = segments[2];
            if (!int.TryParse(name, out var elements))
            {
                continue;
            }

            /*
            var count = 0d;
            var sum = 0d;
            foreach (var row in lines.Skip(1))
            {
                var columns = row.Split(',');

                var time = double.Parse(columns[5]);
                sum += time;
                ++count;
            }

            var average = sum / count;
            var span = TimeSpan.FromMilliseconds(average / 1000d);
            //Console.WriteLine($"{key} - {elements,12:N0} - {span.TotalMilliseconds,12:N2}");
            */

            var line = lines.Last()!;
            var data = new StringBuilder(line.Length);
            var isInString = false;
            for (var i = 0; i < line.Length; ++i)
            {
                if (line[i] == '"')
                {
                    isInString = !isInString;
                    continue;
                }

                if (isInString && line[i] == ',')
                {
                    data.Append(';');
                    continue;
                }

                data.Append(line[i]);
            }
            
            var columns = data.ToString().Split(',');
            var time = double.Parse(columns[5]);
            var count = double.Parse(columns[7]);
            var average = time / count;
            var span = TimeSpan.FromMilliseconds(average / (1000d * 1000d));

            var result = new Result(elements, average, span);
            if (!entries.ContainsKey(key))
            {
                entries.Add(key, new List<Result>());
            }
            
            entries[key].Add(result);
        }
        
        // Sort it
        foreach (var key in entries.Keys)
        {
            entries[key] = entries[key].OrderBy(entry => entry.Elements).ToList();
        }
        
        // Print it
        foreach (var key in entries.Keys)
        {
            Console.WriteLine(key);

            foreach (var entry in entries[key])
            {
                var throughput = entry.Elements / (entry.Elapsed / 1000d / 1000d / 1000d);
                //Console.WriteLine($"{entry.Elements,10:N0}  {entry.Span.TotalMilliseconds,10:N2} ms {entry.Elapsed,14:N0} ns    {throughput,10:N0} elements/s");
                Console.WriteLine($"{Math.Floor(entry.Elements)}    {entry.Span.TotalMilliseconds:F2}");
            }
        }
    }
}
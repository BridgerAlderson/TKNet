using System.Collections.Generic;

namespace TKNetUI;

public sealed class BoundedLog
{
    private readonly Queue<string> _lines = new();
    public const int MaxLines = 500;
    public const int MaxLineCharacters = 4096;
    public int RemovedLines { get; private set; }
    public int RemovedCharacters { get; private set; }
    public string Append(string message)
    {
        RemovedLines = RemovedCharacters = 0;
        foreach (string line in message.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            _lines.Enqueue(line.Length > MaxLineCharacters ? line[..MaxLineCharacters] + "…" : line);
            if (_lines.Count > MaxLines)
            {
                RemovedCharacters += _lines.Dequeue().Length + 1; // including the newline
                RemovedLines++;
            }
        }
        return string.Join("\n", _lines) + "\n";
    }
    public void Clear()
    {
        _lines.Clear();
        RemovedLines = RemovedCharacters = 0;
    }
}

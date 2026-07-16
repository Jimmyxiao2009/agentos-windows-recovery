using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentOS;

internal static class TransactionJournal
{
    private const string GenesisHash = "GENESIS";
    private static readonly JsonSerializerOptions LineOptions = new(JsonSupport.Options) { WriteIndented = false };

    public static void Append(string path, string eventType, string data)
    {
        List<JournalEntry> existing = ReadAll(path);
        JournalEntry? previous = existing.LastOrDefault();
        long sequence = previous is null ? 1 : previous.Sequence + 1;
        string previousHash = previous?.Hash ?? GenesisHash;
        DateTimeOffset timestamp = DateTimeOffset.UtcNow;
        string hash = CalculateHash(sequence, timestamp, eventType, data, previousHash);
        JournalEntry entry = new()
        {
            Sequence = sequence,
            Timestamp = timestamp,
            EventType = eventType,
            Data = data,
            PreviousHash = previousHash,
            Hash = hash
        };

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.WriteThrough);
        using StreamWriter writer = new(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true);
        writer.WriteLine(JsonSerializer.Serialize(entry, LineOptions));
        writer.Flush();
        stream.Flush(flushToDisk: true);
    }

    public static JournalVerificationResult Verify(string transactionId, string path)
    {
        try
        {
            List<JournalEntry> entries = ReadAll(path);
            string expectedPrevious = GenesisHash;
            long expectedSequence = 1;
            foreach (JournalEntry entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry.EventType) || entry.Data is null ||
                    string.IsNullOrWhiteSpace(entry.PreviousHash) || !EvidenceIntegrity.IsSha256(entry.Hash))
                {
                    return Invalid(transactionId, entries.Count, $"Journal entry {entry.Sequence} is structurally invalid.");
                }
                if (entry.Sequence != expectedSequence)
                {
                    return Invalid(transactionId, entries.Count, $"Unexpected journal sequence {entry.Sequence}; expected {expectedSequence}.");
                }
                if (!string.Equals(entry.PreviousHash, expectedPrevious, StringComparison.Ordinal))
                {
                    return Invalid(transactionId, entries.Count, $"Journal hash chain is broken at sequence {entry.Sequence}.");
                }
                string expectedHash = CalculateHash(entry.Sequence, entry.Timestamp, entry.EventType, entry.Data, entry.PreviousHash);
                if (!string.Equals(entry.Hash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    return Invalid(transactionId, entries.Count, $"Journal entry {entry.Sequence} has an invalid hash.");
                }
                expectedPrevious = entry.Hash;
                expectedSequence++;
            }
            return new JournalVerificationResult { TransactionId = transactionId, IsValid = true, EntryCount = entries.Count };
        }
        catch (Exception exception)
        {
            return Invalid(transactionId, 0, exception.Message);
        }
    }

    public static bool ContainsEvidenceAnchor(string path, string eventType, string indexHash)
    {
        return ReadAll(path).Any(entry =>
            string.Equals(entry.EventType, eventType, StringComparison.Ordinal) &&
            string.Equals(entry.Data, indexHash, StringComparison.OrdinalIgnoreCase));
    }

    private static List<JournalEntry> ReadAll(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }
        return File.ReadLines(path)
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line => JsonSerializer.Deserialize<JournalEntry>(line, LineOptions)
                ?? throw new InvalidDataException("Journal contains an unreadable entry."))
            .ToList();
    }

    private static string CalculateHash(long sequence, DateTimeOffset timestamp, string eventType, string data, string previousHash)
    {
        string payload = string.Join("\n", sequence, timestamp.ToUniversalTime().ToString("O"), eventType, data, previousHash);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }

    private static JournalVerificationResult Invalid(string transactionId, int count, string error) => new()
    {
        TransactionId = transactionId,
        IsValid = false,
        EntryCount = count,
        Error = error
    };
}

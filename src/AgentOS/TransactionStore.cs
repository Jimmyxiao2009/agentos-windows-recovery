namespace AgentOS;

internal sealed class TransactionStore
{
    public TransactionStore(string? root = null)
    {
        Root = Path.GetFullPath(root ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AgentOS",
            "transactions"));
        Directory.CreateDirectory(Root);
        StoreProtection.HardenRoot(Root);
    }

    public string Root { get; }

    public string TransactionDirectory(string id)
    {
        ValidateTransactionId(id);
        return Path.Combine(Root, id);
    }
    public string ManifestPath(string id) => Path.Combine(TransactionDirectory(id), "manifest.json");
    public string BaselineFilesPath(string id) => Path.Combine(TransactionDirectory(id), "baseline-files.json");
    public string AfterFilesPath(string id) => Path.Combine(TransactionDirectory(id), "after-files.json");
    public string BaselineRegistryPath(string id) => Path.Combine(TransactionDirectory(id), "baseline-registry.json");
    public string AfterRegistryPath(string id) => Path.Combine(TransactionDirectory(id), "after-registry.json");
    public string BaselineServicesPath(string id) => Path.Combine(TransactionDirectory(id), "baseline-services.json");
    public string AfterServicesPath(string id) => Path.Combine(TransactionDirectory(id), "after-services.json");
    public string BaselineScheduledTasksPath(string id) => Path.Combine(TransactionDirectory(id), "baseline-scheduled-tasks.json");
    public string AfterScheduledTasksPath(string id) => Path.Combine(TransactionDirectory(id), "after-scheduled-tasks.json");
    public string BlobDirectory(string id) => Path.Combine(TransactionDirectory(id), "blobs");
    public string JournalPath(string id) => Path.Combine(TransactionDirectory(id), "journal.ndjson");
    public string BaselineEvidenceIndexPath(string id) => Path.Combine(TransactionDirectory(id), "baseline-integrity.json");
    public string AfterEvidenceIndexPath(string id) => Path.Combine(TransactionDirectory(id), "after-integrity.json");
    public string EvidenceMacPath(string id) => Path.Combine(TransactionDirectory(id), StoreProtection.MacFileName);

    public IDisposable AcquireWriterLock()
    {
        string path = Path.Combine(Root, ".writer.lock");
        try
        {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None,
                1, FileOptions.DeleteOnClose);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException("Another modifying AgentOS transaction is active.", exception);
        }
    }

    public void Create(TransactionManifest manifest)
    {
        string directory = TransactionDirectory(manifest.Id);
        if (Directory.Exists(directory))
        {
            throw new InvalidOperationException($"Transaction {manifest.Id} already exists.");
        }

        Directory.CreateDirectory(directory);
        Directory.CreateDirectory(BlobDirectory(manifest.Id));
        Save(manifest);
    }

    public TransactionManifest Load(string id)
    {
        string path = ManifestPath(id);
        if (!File.Exists(path))
        {
            throw new KeyNotFoundException($"Transaction {id} was not found in {Root}.");
        }

        TransactionManifest manifest = JsonSupport.Read<TransactionManifest>(path);
        EvidenceIntegrity.ValidateManifest(manifest, id);
        return manifest;
    }

    public void Save(TransactionManifest manifest)
    {
        EvidenceIntegrity.ValidateManifest(manifest, manifest.Id);
        manifest.UpdatedAt = DateTimeOffset.UtcNow;
        JsonSupport.WriteAtomic(ManifestPath(manifest.Id), manifest);
    }

    public void Audit(TransactionManifest manifest, string eventType, string data)
    {
        TransactionJournal.Append(JournalPath(manifest.Id), eventType, data);
    }

    public IReadOnlyList<TransactionManifest> List()
    {
        List<TransactionManifest> transactions = [];
        foreach (string manifest in Directory.EnumerateFiles(Root, "manifest.json", SearchOption.AllDirectories))
        {
            try
            {
                string id = Path.GetFileName(Path.GetDirectoryName(manifest)!);
                ValidateTransactionId(id);
                TransactionManifest transaction = JsonSupport.Read<TransactionManifest>(manifest);
                EvidenceIntegrity.ValidateManifest(transaction, id);
                transactions.Add(transaction);
            }
            catch
            {
                // A damaged manifest is intentionally skipped here; its directory remains for forensic recovery.
            }
        }

        return transactions.OrderByDescending(transaction => transaction.CreatedAt).ToList();
    }

    public IReadOnlyList<string> ListDamagedDirectories()
    {
        List<string> damaged = [];
        foreach (string directory in Directory.EnumerateDirectories(Root))
        {
            string name = Path.GetFileName(directory);
            if (name.StartsWith(".", StringComparison.Ordinal))
            {
                continue;
            }

            try
            {
                ValidateTransactionId(name);
                string manifestPath = Path.Combine(directory, "manifest.json");
                if (!File.Exists(manifestPath))
                {
                    damaged.Add(name + ": missing manifest.json");
                    continue;
                }

                TransactionManifest transaction = JsonSupport.Read<TransactionManifest>(manifestPath);
                EvidenceIntegrity.ValidateManifest(transaction, name);
            }
            catch (Exception exception)
            {
                damaged.Add(name + ": " + exception.Message);
            }
        }

        return damaged;
    }

    public long SizeBytes()
    {
        long total = 0;
        foreach (string file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
        {
            try { total += new FileInfo(file).Length; } catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return total;
    }

    private static void ValidateTransactionId(string id)
    {
        if (id is not { Length: 32 } || !id.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("A transaction id must be exactly 32 hexadecimal characters.", nameof(id));
        }
    }
}

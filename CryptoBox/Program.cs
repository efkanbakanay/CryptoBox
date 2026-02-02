using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

internal static class Program
{
    private const int EXIT_OK = 0;
    private const int EXIT_BAD_ARGS = 2;
    private const int EXIT_CRYPTO_FAIL = 3;
    private const int EXIT_IO_FAIL = 4;

    private static readonly object ConsoleLock = new();

    public static int Main(string[] args)
    {
        try
        {
            // Argümansız: çift tık -> menü
            if (args.Length == 0)
            {
                RunInteractiveMenu();
                return EXIT_OK;
            }

            if (HasHelp(args))
            {
                PrintGeneralHelp();
                return EXIT_OK;
            }

            string cmd = args[0].Trim().ToLowerInvariant();
            string[] rest = args.Skip(1).ToArray();

            switch (cmd)
            {
                case "help":
                    PrintGeneralHelp();
                    return EXIT_OK;

                case "version":
                    Console.WriteLine("CryptoBox 2.3.0");
                    return EXIT_OK;

                case "encrypt":
                    if (rest.Length == 0 || HasHelp(rest))
                    {
                        PrintEncryptHelp();
                        return EXIT_OK;
                    }
                    return RunEncrypt(rest);

                case "decrypt":
                    if (rest.Length == 0 || HasHelp(rest))
                    {
                        PrintDecryptHelp();
                        return EXIT_OK;
                    }
                    return RunDecrypt(rest);

                case "recover":
                    if (rest.Length == 0 || HasHelp(rest))
                    {
                        PrintRecoverHelp();
                        return EXIT_OK;
                    }
                    return RunRecover(rest);

                default:
                    return UnknownCommand(cmd);
            }

        }
        catch (CryptoException ex)
        {
            Console.Error.WriteLine($"[CRYPTO] {ex.Message}");
            return EXIT_CRYPTO_FAIL;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"[IO] {ex.Message}");
            return EXIT_IO_FAIL;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"[PERMISSION] {ex.Message}");
            return EXIT_IO_FAIL;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"[ARGS] {ex.Message}");
            return EXIT_BAD_ARGS;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] {ex}");
            return 1;
        }
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"Bilinmeyen komut: {cmd}");
        PrintGeneralHelp();
        return EXIT_BAD_ARGS;
    }

    // ---------------- CLI ----------------

    private static int RunEncrypt(string[] args)
    {
        var opts = Options.Parse(args);

        string target = RequirePath(opts.TargetPath, "encrypt");
        target = Path.GetFullPath(target);

        bool isFile = File.Exists(target);
        bool isDir = Directory.Exists(target);
        if (!isFile && !isDir) throw new IOException($"Bulunamadı: {target}");

        string password = ReadPassword("Parola belirle: ");
        string password2 = ReadPassword("Parola tekrar: ");
        if (!SecureEquals(password, password2))
            throw new CryptoException("Parolalar eşleşmiyor.");

        string recoveryKeyText = ResolveRecoveryKeyForEncrypt(opts);
        if (!RecoveryKey.TryParse(recoveryKeyText, out var recoveryKeyBytes))
            throw new CryptoException("Kurtarma anahtarı formatı geçersiz.");

        bool deleteSource = ResolveDeleteChoice(opts, "Şifreleme başarılı olunca orijinal dosyalar silinsin mi? (E/H): ", defaultNo: true);

        string baseRoot = isDir ? target : Path.GetDirectoryName(target)!;
        string outputRoot = ResolveOutputRoot(opts, baseRoot);

        if (opts.DryRun)
        {
            PrintEncryptPlan(target, isFile, isDir, baseRoot, outputRoot, opts, deleteSource);
            return EXIT_OK;
        }

        if (isFile)
        {
            long totalBytes = new FileInfo(target).Length;
            using var progress = ProgressPrinter.Start("Şifreleniyor", totalBytes);
            EncryptOneFile(target, baseRoot, outputRoot, opts.InPlace, password, recoveryKeyBytes, deleteSource, opts.Verify, progress);
        }
        else
        {
            var files = Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories)
                                 .Select(p => new FileInfo(p))
                                 .ToList();

            long totalBytes = files.Sum(f => f.Length);
            int threads = opts.Threads > 0 ? opts.Threads : GetOptimalThreadsForWorkload(files);
            using var progress = ProgressPrinter.Start("Şifreleniyor", totalBytes);

            EncryptDirectory(files, inputDirRoot: target, outputRoot, opts.InPlace, password, recoveryKeyBytes, deleteSource, opts.Verify, threads, progress);
        }

        Console.WriteLine("✅ Şifreleme tamamlandı.");
        return EXIT_OK;
    }

    private static int RunDecrypt(string[] args)
    {
        var opts = Options.Parse(args);

        string target = RequirePath(opts.TargetPath, "decrypt");
        target = Path.GetFullPath(target);

        bool isFile = File.Exists(target);
        bool isDir = Directory.Exists(target);
        if (!isFile && !isDir) throw new IOException($"Bulunamadı: {target}");

        string? mode = opts.Mode?.ToLowerInvariant();
        if (mode is not null && mode != "password" && mode != "recovery")
            throw new ArgumentException("--mode sadece password veya recovery olabilir.");

        bool deleteEncSource = ResolveDeleteChoice(opts, "Çözme başarılı olunca .enc dosyaları silinsin mi? (E/H): ", defaultNo: true);

        string baseRoot = isDir ? target : Path.GetDirectoryName(target)!;
        string outputRoot = ResolveOutputRoot(opts, baseRoot);

        string chosenMode = mode ?? AskMode();
        string? password = null;
        byte[]? recoveryKeyBytes = null;

        if (chosenMode == "password")
        {
            password = ReadPassword("Parola: ");
        }
        else
        {
            string rk = (opts.RecoveryKey ?? ReadLineNonEmpty("Kurtarma anahtarı: ")).Trim();
            if (!RecoveryKey.TryParse(rk, out var rec))
                throw new CryptoException("Kurtarma anahtarı formatı geçersiz.");
            recoveryKeyBytes = rec;
        }

        if (opts.DryRun)
        {
            PrintDecryptPlan(target, isFile, isDir, outputRoot, opts, deleteEncSource);
            return EXIT_OK;
        }

        if (isFile)
        {
            if (!target.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                throw new IOException("Seçilen dosya .enc değil.");

            var header = FileCrypto2.PeekHeader(target);
            using var progress = ProgressPrinter.Start("Çözülüyor", header.OriginalSize);
            DecryptOneFile(target, outputRoot, opts.InPlace, password, recoveryKeyBytes, deleteEncSource, opts.Verify, progress);
        }
        else
        {
            var encFiles = Directory.EnumerateFiles(target, "*.enc", SearchOption.AllDirectories).ToList();
            if (encFiles.Count == 0)
            {
                Console.WriteLine("Klasörde .enc dosyası yok.");
                return EXIT_OK;
            }

            // total: header original sizes (ETA daha doğru)
            long totalBytes = 0;
            var headers = new Dictionary<string, FileCrypto2.HeaderInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in encFiles)
            {
                var h = FileCrypto2.PeekHeader(f);
                headers[f] = h;
                if (h.OriginalSize > 0) totalBytes += h.OriginalSize;
            }

            int threads = opts.Threads > 0 ? opts.Threads : GetOptimalThreadsForWorkload(encFiles.Select(p => new FileInfo(p)).ToList());
            using var progress = ProgressPrinter.Start("Çözülüyor", totalBytes);

            DecryptDirectory(encFiles, headers, outputRoot, opts.InPlace, password, recoveryKeyBytes, deleteEncSource, opts.Verify, threads, progress);
        }

        Console.WriteLine("✅ Çözme tamamlandı.");
        return EXIT_OK;
    }

    private static int RunRecover(string[] args)
    {
        var opts = Options.Parse(args);

        string target = RequirePath(opts.TargetPath, "recover");
        target = Path.GetFullPath(target);

        bool isFile = File.Exists(target);
        bool isDir = Directory.Exists(target);
        if (!isFile && !isDir) throw new IOException($"Bulunamadı: {target}");

        string rkText = (opts.RecoveryKey ?? ReadLineNonEmpty("Kurtarma anahtarı: ")).Trim();
        if (!RecoveryKey.TryParse(rkText, out var recoveryKeyBytes))
            throw new CryptoException("Kurtarma anahtarı formatı geçersiz.");

        string newPw = ReadPassword("Yeni parola belirle: ");
        string newPw2 = ReadPassword("Yeni parola tekrar: ");
        if (!SecureEquals(newPw, newPw2))
            throw new CryptoException("Yeni parolalar eşleşmiyor.");

        if (opts.DryRun)
        {
            PrintRecoverPlan(target, isFile, isDir, opts);
            return EXIT_OK;
        }

        if (isFile)
        {
            if (!target.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                throw new IOException("recover için .enc dosyası seçmelisin.");

            long totalBytes = new FileInfo(target).Length;
            using var progress = ProgressPrinter.Start("Parola yenileniyor", totalBytes);
            RecoverOneFile(target, newPw, recoveryKeyBytes, opts.Verify, progress);
        }
        else
        {
            var encFiles = Directory.EnumerateFiles(target, "*.enc", SearchOption.AllDirectories).ToList();
            if (encFiles.Count == 0)
            {
                Console.WriteLine("Klasörde .enc dosyası yok.");
                return EXIT_OK;
            }

            long totalBytes = encFiles.Select(f => new FileInfo(f).Length).Sum();
            int threads = opts.Threads > 0 ? opts.Threads : GetOptimalThreadsForWorkload(encFiles.Select(p => new FileInfo(p)).ToList());
            using var progress = ProgressPrinter.Start("Parola yenileniyor", totalBytes);

            int ok = 0, fail = 0;
            Parallel.ForEach(encFiles, new ParallelOptions { MaxDegreeOfParallelism = threads }, file =>
            {
                try
                {
                    RecoverOneFile(file, newPw, recoveryKeyBytes, opts.Verify, progress);
                    Interlocked.Increment(ref ok);
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref fail);
                    lock (ConsoleLock)
                        Console.Error.WriteLine($"\n[FAIL] {file} -> {ex.Message}");
                }
            });

            progress.Complete();
            Console.WriteLine($"Parola yenilenen: {ok}, Hatalı: {fail}");
        }

        Console.WriteLine("✅ Parola yenileme tamamlandı.");
        return EXIT_OK;
    }

    // ---------------- Operations (with progress) ----------------

    private static void EncryptDirectory(
        List<FileInfo> files,
        string inputDirRoot,
        string outputRoot,
        bool inplace,
        string password,
        byte[] recoveryKeyBytes,
        bool deleteSource,
        bool verify,
        int threads,
        ProgressPrinter progress)
    {
        int ok = 0, fail = 0;

        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = threads }, fi =>
        {
            try
            {
                EncryptOneFile(fi.FullName, inputDirRoot, outputRoot, inplace, password, recoveryKeyBytes, deleteSource, verify, progress);
                Interlocked.Increment(ref ok);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref fail);
                lock (ConsoleLock)
                    Console.Error.WriteLine($"\n[FAIL] {fi.FullName} -> {ex.Message}");
            }
        });

        progress.Complete();
        Console.WriteLine($"\nŞifrelenen: {ok}, Hatalı: {fail}");
    }

    private static void EncryptOneFile(
        string inputFilePath,
        string baseInputRoot,
        string outputRoot,
        bool inplace,
        string password,
        byte[] recoveryKeyBytes,
        bool deleteSource,
        bool verify,
        ProgressPrinter progress)
    {
        string rel = Path.GetRelativePath(baseInputRoot, inputFilePath);
        string relNormalized = rel.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');

        string outFilePath = inplace
            ? inputFilePath + ".enc"
            : Path.Combine(outputRoot, rel) + ".enc";

        Directory.CreateDirectory(Path.GetDirectoryName(outFilePath)!);

        string tmpPath = outFilePath + ".tmp";

        FileCrypto2.EncryptFile(inputFilePath, tmpPath, password, recoveryKeyBytes, relNormalized,
            onProcessedBytes: progress.AddProcessedBytes);

        if (File.Exists(outFilePath)) File.Delete(outFilePath);
        File.Move(tmpPath, outFilePath);

        if (verify)
            FileCrypto2.VerifyEncFile(outFilePath, password: password, recoveryKeyBytes: null);
        if (deleteSource)
            File.Delete(inputFilePath);
    }

    private static void DecryptDirectory(
        List<string> encFiles,
        Dictionary<string, FileCrypto2.HeaderInfo> headers,
        string outputRoot,
        bool inplace,
        string? password,
        byte[]? recoveryKeyBytes,
        bool deleteEncSource,
        bool verify,
        int threads,
        ProgressPrinter progress)
    {
        int ok = 0, fail = 0;

        Parallel.ForEach(encFiles, new ParallelOptions { MaxDegreeOfParallelism = threads }, enc =>
        {
            try
            {
                DecryptOneFile(enc, outputRoot, inplace, password, recoveryKeyBytes, deleteEncSource, verify, progress);
                Interlocked.Increment(ref ok);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref fail);
                lock (ConsoleLock)
                    Console.Error.WriteLine($"\n[FAIL] {enc} -> {ex.Message}");
            }
        });

        progress.Complete();
        Console.WriteLine($"\nÇözülen: {ok}, Hatalı: {fail}");
    }

    private static void DecryptOneFile(
        string encFilePath,
        string outputRoot,
        bool inplace,
        string? password,
        byte[]? recoveryKeyBytes,
        bool deleteEncSource,
        bool verify,
        ProgressPrinter progress)
    {
        var info = FileCrypto2.PeekHeader(encFilePath);

        string outRoot = inplace ? Path.GetDirectoryName(encFilePath)! : outputRoot;
        string rel = info.OriginalRelativePath.Replace('/', Path.DirectorySeparatorChar);
        string outFilePath = Path.Combine(outRoot, rel);

        Directory.CreateDirectory(Path.GetDirectoryName(outFilePath)!);

        string tmpPath = outFilePath + ".tmp";

        FileCrypto2.DecryptFile(encFilePath, tmpPath, password, recoveryKeyBytes,
            onProcessedBytes: progress.AddProcessedBytes);

        if (File.Exists(outFilePath)) File.Delete(outFilePath);
        File.Move(tmpPath, outFilePath);

        if (verify)
        {
            // İstersen burada SHA256 yazdırabilirsin; ama progress satırını bozmasın diye yazmıyoruz.
            _ = Sha256File(outFilePath);
        }

        if (deleteEncSource)
            File.Delete(encFilePath);
    }

    private static void RecoverOneFile(string encFilePath, string newPassword, byte[] recoveryKeyBytes, bool verify, ProgressPrinter progress)
    {
        string tmp = encFilePath + ".tmp";

        FileCrypto2.RecoverPassword(encFilePath, tmp, newPassword, recoveryKeyBytes,
            onCopiedCipherBytes: progress.AddProcessedBytes);

        if (File.Exists(encFilePath)) File.Delete(encFilePath);
        File.Move(tmp, encFilePath);

        if (verify)
            FileCrypto2.VerifyEncFile(encFilePath, password: newPassword, recoveryKeyBytes: null);
    }

    // ---------------- Interactive Menu ----------------

    private static void RunInteractiveMenu()
    {
        Console.Title = "CryptoBox";
        while (true)
        {
            Console.Clear();
            Console.WriteLine("=== CryptoBox ===");
            Console.WriteLine("1) Şifrele (encrypt)");
            Console.WriteLine("2) Çöz (decrypt)");
            Console.WriteLine("3) Parola kurtar/değiştir (recover)");
            Console.WriteLine("4) Help");
            Console.WriteLine("0) Çıkış");
            Console.WriteLine();
            Console.Write("Seçim: ");
            var choice = (Console.ReadLine() ?? "").Trim();

            try
            {
                switch (choice)
                {
                    case "1":
                        InteractiveEncrypt();
                        break;
                    case "2":
                        InteractiveDecrypt();
                        break;
                    case "3":
                        InteractiveRecover();
                        break;
                    case "4":
                        Console.Clear();
                        PrintGeneralHelp();
                        Pause();
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Geçersiz seçim.");
                        Pause();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("Hata: " + ex.Message);
                Pause();
            }
        }
    }

    private static void InteractiveEncrypt()
    {
        Console.Clear();
        Console.WriteLine("=== ŞİFRELE (encrypt) ===");

        string target = Path.GetFullPath(ReadLineNonEmpty("Dosya/klasör yolu: "));
        bool isFile = File.Exists(target);
        bool isDir = Directory.Exists(target);
        if (!isFile && !isDir) throw new IOException("Yol bulunamadı.");

        bool inplace = AskYesNo("Çıktı aynı yerde mi oluşsun? (E/H): ", defaultNo: true);
        string? outRoot = inplace ? null : ReadLineNonEmpty("Çıktı klasörü (out): ");

        string password = ReadPassword("Parola belirle: ");
        string password2 = ReadPassword("Parola tekrar: ");
        if (!SecureEquals(password, password2)) throw new CryptoException("Parolalar eşleşmiyor.");

        Console.WriteLine();
        bool hasExisting = AskYesNo("Mevcut kurtarma anahtarın var mı? (E/H): ", defaultNo: true);
        string rkText;
        if (hasExisting)
            rkText = ReadLineNonEmpty("Kurtarma anahtarı: ").Trim();
        else
        {
            rkText = RecoveryKey.Generate();
            Console.WriteLine("\n=== KURTARMA ANAHTARI (ÇOK ÖNEMLİ) ===");
            Console.WriteLine(rkText);
            Console.WriteLine("Bunu güvenli yere kaydet. Parola unutulursa bununla kurtarırsın.");
            Console.WriteLine("Devam için ENTER...");
            Console.ReadLine();
        }

        if (!RecoveryKey.TryParse(rkText, out var rkBytes)) throw new CryptoException("Kurtarma anahtarı formatı geçersiz.");

        bool deleteSource = AskYesNo("Başarılı olunca orijinal dosyalar silinsin mi? (E/H): ", defaultNo: true);

        string baseRoot = isDir ? target : Path.GetDirectoryName(target)!;
        string resolvedOut = inplace ? baseRoot : Path.GetFullPath(outRoot!);

        Console.WriteLine();
        Console.WriteLine("İşlem başlıyor...");

        if (isFile)
        {
            long totalBytes = new FileInfo(target).Length;
            using var progress = ProgressPrinter.Start("Şifreleniyor", totalBytes);
            EncryptOneFile(target, baseRoot, resolvedOut, inplace, password, rkBytes, deleteSource, verify: false, progress);
            progress.Complete();
        }
        else
        {
            var files = Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories).Select(p => new FileInfo(p)).ToList();
            long totalBytes = files.Sum(f => f.Length);
            int threads = GetOptimalThreadsForWorkload(files);

            using var progress = ProgressPrinter.Start("Şifreleniyor", totalBytes);
            EncryptDirectory(files, target, resolvedOut, inplace, password, rkBytes, deleteSource, verify: false, threads, progress);
        }

        Console.WriteLine("\n✅ Şifreleme tamamlandı.");
        Pause();
    }

    private static void InteractiveDecrypt()
    {
        Console.Clear();
        Console.WriteLine("=== ÇÖZ (decrypt) ===");

        string target = Path.GetFullPath(ReadLineNonEmpty(".enc dosya/klasör yolu: "));
        bool isFile = File.Exists(target);
        bool isDir = Directory.Exists(target);
        if (!isFile && !isDir) throw new IOException("Yol bulunamadı.");

        bool inplace = AskYesNo("Çıktı aynı yerde mi oluşsun? (E/H): ", defaultNo: true);
        string? outRoot = inplace ? null : ReadLineNonEmpty("Çıktı klasörü (out): ");

        Console.WriteLine("\nÇözme modu: 1) Parola  2) Kurtarma");
        Console.Write("Seçim: ");
        var mode = (Console.ReadLine() ?? "").Trim();

        string? password = null;
        byte[]? rkBytes = null;

        if (mode == "1")
            password = ReadPassword("Parola: ");
        else if (mode == "2")
        {
            string rk = ReadLineNonEmpty("Kurtarma anahtarı: ").Trim();
            if (!RecoveryKey.TryParse(rk, out var b)) throw new CryptoException("Kurtarma anahtarı formatı geçersiz.");
            rkBytes = b;
        }
        else
            throw new ArgumentException("Geçersiz seçim.");

        bool deleteEnc = AskYesNo("Başarılı olunca .enc silinsin mi? (E/H): ", defaultNo: true);

        string baseRoot = isDir ? target : Path.GetDirectoryName(target)!;
        string resolvedOut = inplace ? baseRoot : Path.GetFullPath(outRoot!);

        Console.WriteLine();
        Console.WriteLine("İşlem başlıyor...");

        if (isFile)
        {
            if (!target.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)) throw new IOException("Dosya .enc değil.");
            var h = FileCrypto2.PeekHeader(target);
            using var progress = ProgressPrinter.Start("Çözülüyor", h.OriginalSize);
            DecryptOneFile(target, resolvedOut, inplace, password, rkBytes, deleteEnc, verify: false, progress);
            progress.Complete();
        }
        else
        {
            var encFiles = Directory.EnumerateFiles(target, "*.enc", SearchOption.AllDirectories).ToList();
            if (encFiles.Count == 0) { Console.WriteLine("Klasörde .enc yok."); Pause(); return; }

            long totalBytes = 0;
            var headers = new Dictionary<string, FileCrypto2.HeaderInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in encFiles)
            {
                var hh = FileCrypto2.PeekHeader(f);
                headers[f] = hh;
                if (hh.OriginalSize > 0) totalBytes += hh.OriginalSize;
            }

            int threads = GetOptimalThreadsForWorkload(encFiles.Select(p => new FileInfo(p)).ToList());
            using var progress = ProgressPrinter.Start("Çözülüyor", totalBytes);

            DecryptDirectory(encFiles, headers, resolvedOut, inplace, password, rkBytes, deleteEnc, verify: false, threads, progress);
        }

        Console.WriteLine("\n✅ Çözme tamamlandı.");
        Pause();
    }

    private static void InteractiveRecover()
    {
        Console.Clear();
        Console.WriteLine("=== PAROLA KURTAR/DEĞİŞTİR (recover) ===");

        string target = Path.GetFullPath(ReadLineNonEmpty(".enc dosya/klasör yolu: "));
        bool isFile = File.Exists(target);
        bool isDir = Directory.Exists(target);
        if (!isFile && !isDir) throw new IOException("Yol bulunamadı.");

        string rkText = ReadLineNonEmpty("Kurtarma anahtarı: ").Trim();
        if (!RecoveryKey.TryParse(rkText, out var rkBytes)) throw new CryptoException("Kurtarma anahtarı formatı geçersiz.");

        string newPw = ReadPassword("Yeni parola: ");
        string newPw2 = ReadPassword("Yeni parola tekrar: ");
        if (!SecureEquals(newPw, newPw2)) throw new CryptoException("Yeni parolalar eşleşmiyor.");

        Console.WriteLine();
        Console.WriteLine("İşlem başlıyor...");

        if (isFile)
        {
            if (!target.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)) throw new IOException("Dosya .enc değil.");
            long totalBytes = new FileInfo(target).Length;
            using var progress = ProgressPrinter.Start("Parola yenileniyor", totalBytes);
            RecoverOneFile(target, newPw, rkBytes, verify: false, progress);
            progress.Complete();
        }
        else
        {
            var encFiles = Directory.EnumerateFiles(target, "*.enc", SearchOption.AllDirectories).ToList();
            if (encFiles.Count == 0) { Console.WriteLine("Klasörde .enc yok."); Pause(); return; }

            long totalBytes = encFiles.Select(f => new FileInfo(f).Length).Sum();
            int threads = GetOptimalThreadsForWorkload(encFiles.Select(p => new FileInfo(p)).ToList());
            using var progress = ProgressPrinter.Start("Parola yenileniyor", totalBytes);

            int ok = 0, fail = 0;
            Parallel.ForEach(encFiles, new ParallelOptions { MaxDegreeOfParallelism = threads }, f =>
            {
                try { RecoverOneFile(f, newPw, rkBytes, verify: false, progress); Interlocked.Increment(ref ok); }
                catch (Exception ex) { Interlocked.Increment(ref fail); lock (ConsoleLock) Console.Error.WriteLine($"\n[FAIL] {f} -> {ex.Message}"); }
            });

            progress.Complete();
            Console.WriteLine($"\nParola yenilenen: {ok}, Hatalı: {fail}");
        }

        Console.WriteLine("\n✅ Recover tamamlandı.");
        Pause();
    }

    // ---------------- Auto Threads ----------------
    private static int GetOptimalThreadsForWorkload(List<FileInfo> files)
    {
        int cpu = Environment.ProcessorCount;
        int cap = Math.Clamp(cpu, 2, 8);

        if (files.Count == 0) return 1;
        if (files.Count < 5) return 1;
        if (files.Count < 20) return Math.Min(2, cap);

        int sampleCount = Math.Min(files.Count, 200);
        long total = 0;
        for (int i = 0; i < sampleCount; i++) total += files[i].Length;
        long avg = total / sampleCount;

        if (avg < 1 * 1024 * 1024) return Math.Min(8, cap);
        if (avg < 50L * 1024 * 1024) return Math.Min(6, cap);
        return Math.Min(4, cap);
    }

    // ---------------- Helpers ----------------

    private static bool HasHelp(string[] args)
        => args.Any(a => a.Equals("-h", StringComparison.OrdinalIgnoreCase)
                      || a.Equals("--help", StringComparison.OrdinalIgnoreCase)
                      || a.Equals("/?", StringComparison.OrdinalIgnoreCase));

    private static string RequirePath(string? path, string cmd)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException($"{cmd} için bir dosya/klasör yolu vermelisin.");
        return path!;
    }

    private static string ResolveOutputRoot(Options opts, string defaultRoot)
    {
        if (!string.IsNullOrWhiteSpace(opts.OutPath))
            return Path.GetFullPath(opts.OutPath!);

        if (!opts.InPlace)
        {
            string auto = Path.Combine(defaultRoot, "_crypto_out");
            Directory.CreateDirectory(auto);
            return auto;
        }

        return defaultRoot;
    }

    private static bool ResolveDeleteChoice(Options opts, string question, bool defaultNo)
    {
        if (opts.DeleteSource) return true;
        if (opts.KeepSource) return false;
        if (opts.AssumeYes) return false;
        return AskYesNo(question, defaultNo);
    }

    private static bool AskYesNo(string question, bool defaultNo)
    {
        while (true)
        {
            Console.Write(question);
            var s = Console.ReadLine()?.Trim().ToLowerInvariant();

            if (string.IsNullOrEmpty(s))
                return !defaultNo;

            if (s is "e" or "evet" or "y" or "yes") return true;
            if (s is "h" or "hayır" or "hayir" or "n" or "no") return false;

            Console.WriteLine("Lütfen E veya H gir.");
        }
    }

    private static string ReadLineNonEmpty(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            var s = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(s)) return s.Trim();
        }
    }

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) sb.Length--;
                continue;
            }
            if (!char.IsControl(key.KeyChar))
                sb.Append(key.KeyChar);
        }
        return sb.ToString();
    }

    private static bool SecureEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        bool eq = CryptographicOperations.FixedTimeEquals(ba, bb);
        CryptographicOperations.ZeroMemory(ba);
        CryptographicOperations.ZeroMemory(bb);
        return eq;
    }

    private static void Pause()
    {
        Console.WriteLine();
        Console.Write("Devam etmek için bir tuşa bas...");
        Console.ReadKey(intercept: true);
    }

    private static string Sha256File(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        var hash = sha.ComputeHash(fs);
        return Convert.ToHexString(hash);
    }

    private static string ResolveRecoveryKeyForEncrypt(Options opts)
    {
        if (!string.IsNullOrWhiteSpace(opts.RecoveryKey))
            return opts.RecoveryKey.Trim();

        if (opts.AssumeYes)
        {
            string generated = RecoveryKey.Generate();
            Console.WriteLine("\n=== KURTARMA ANAHTARI (ÇOK ÖNEMLİ) ===");
            Console.WriteLine(generated);
            Console.WriteLine("Bunu güvenli bir yere kaydet. Parola unutulursa bununla kurtarırsın.\n");
            return generated;
        }

        bool has = AskYesNo("Var olan bir kurtarma anahtarın var mı? (E/H): ", defaultNo: true);
        if (has)
            return ReadLineNonEmpty("Kurtarma anahtarı: ").Trim();

        string newKey = RecoveryKey.Generate();
        Console.WriteLine("\n=== KURTARMA ANAHTARI (ÇOK ÖNEMLİ) ===");
        Console.WriteLine(newKey);
        Console.WriteLine("Bunu güvenli bir yere kaydet. Parola unutulursa bununla kurtarırsın.");
        Console.WriteLine("Devam için ENTER...");
        Console.ReadLine();
        Console.WriteLine();
        return newKey;
    }

    private static string AskMode()
    {
        while (true)
        {
            Console.Write("Çözme modu seç (1=Parola, 2=Kurtarma): ");
            var s = Console.ReadLine()?.Trim();
            if (s == "1") return "password";
            if (s == "2") return "recovery";
            Console.WriteLine("Lütfen 1 veya 2 gir.");
        }
    }

    // ---------------- Help + Dry Run ----------------

    private static void PrintGeneralHelp()
    {
        Console.WriteLine(@"
CryptoBox - OS bağımsız dosya/klasör şifreleme (Parola + Kurtarma Anahtarı)

Kullanım:
  CryptoBox encrypt <path> [seçenekler]
  CryptoBox decrypt <path> [seçenekler]
  CryptoBox recover <path> [seçenekler]
  CryptoBox --help
  CryptoBox encrypt --help
  CryptoBox decrypt --help
  CryptoBox recover --help
  CryptoBox version

Komutlar:
  encrypt   Dosya/klasörü .enc olarak şifreler (kalite bozulmaz)
  decrypt   .enc dosyalarını parola veya kurtarma anahtarıyla çözer
  recover   Kurtarma anahtarı ile parolayı yeniler (içeriği yeniden şifrelemez)

Ortak seçenekler:
  --out <path>           Çıktı kök klasörü
  --inplace              Çıktıyı aynı yerde üret
  --delete-source         Başarılı olunca kaynak dosyaları sil
  --keep-source           Kaynak dosyaları tut
  --threads <n>           Paralellik (opsiyonel; verilmezse otomatik)
  --dry-run               Sadece planı göster
  --verify                Kripto doğrulama (HMAC) yap
  --yes                   Soru sormadan varsayılanları kullan
  --recovery-key <key>    Kurtarma anahtarı ver

decrypt için:
  --mode password|recovery (yoksa sorar)
");
    }

    private static void PrintEncryptHelp()
    {
        Console.WriteLine(@"
encrypt:
  CryptoBox encrypt <dosya_veya_klasor> [seçenekler]

Örnek:
  CryptoBox encrypt ""C:\Data"" --out ""D:\Encrypted""
  CryptoBox encrypt ""C:\Data\video.mp4"" --inplace
  CryptoBox encrypt ""C:\Data"" --dry-run
");
    }

    private static void PrintDecryptHelp()
    {
        Console.WriteLine(@"
decrypt:
  CryptoBox decrypt <.enc_dosyasi_veya_klasor> [seçenekler]

Örnek:
  CryptoBox decrypt ""D:\Encrypted"" --out ""D:\Decrypted"" --mode password
  CryptoBox decrypt ""C:\Data\video.mp4.enc"" --inplace --mode recovery
");
    }

    private static void PrintRecoverHelp()
    {
        Console.WriteLine(@"
recover:
  Parola unutulduysa kurtarma anahtarıyla .enc dosyaya yeni parola tanımlar.
  Dosya içeriği yeniden şifrelenmez; sadece parola kilidi yenilenir.

Örnek:
  CryptoBox recover ""D:\Encrypted""
  CryptoBox recover ""C:\Data\video.mp4.enc"" --recovery-key ""CBX-RK1-....""
");
    }

    private static void PrintEncryptPlan(string target, bool isFile, bool isDir, string baseRoot, string outputRoot, Options opts, bool deleteSource)
    {
        Console.WriteLine("=== DRY-RUN (encrypt) ===");
        Console.WriteLine($"Target: {target}");
        Console.WriteLine($"Inplace: {opts.InPlace}");
        Console.WriteLine($"OutRoot: {outputRoot}");
        Console.WriteLine($"DeleteSource: {deleteSource}");
        Console.WriteLine();
        if (isFile)
        {
            string rel = Path.GetRelativePath(baseRoot, target);
            string outPath = opts.InPlace ? target + ".enc" : Path.Combine(outputRoot, rel) + ".enc";
            Console.WriteLine($"[ENC] {target} -> {outPath}");
        }
        else if (isDir)
        {
            var files = Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories).ToList();
            Console.WriteLine($"Bulunan dosya: {files.Count}");
        }
    }

    private static void PrintDecryptPlan(string target, bool isFile, bool isDir, string outputRoot, Options opts, bool deleteEncSource)
    {
        Console.WriteLine("=== DRY-RUN (decrypt) ===");
        Console.WriteLine($"Target: {target}");
        Console.WriteLine($"Inplace: {opts.InPlace}");
        Console.WriteLine($"OutRoot: {outputRoot}");
        Console.WriteLine($"DeleteEncSource: {deleteEncSource}");
        Console.WriteLine();
        if (isFile)
        {
            var info = FileCrypto2.PeekHeader(target);
            string outRoot = opts.InPlace ? Path.GetDirectoryName(target)! : outputRoot;
            string outPath = Path.Combine(outRoot, info.OriginalRelativePath.Replace('/', Path.DirectorySeparatorChar));
            Console.WriteLine($"[DEC] {target} -> {outPath}");
        }
        else if (isDir)
        {
            var files = Directory.EnumerateFiles(target, "*.enc", SearchOption.AllDirectories).ToList();
            Console.WriteLine($"Bulunan .enc: {files.Count}");
        }
    }

    private static void PrintRecoverPlan(string target, bool isFile, bool isDir, Options opts)
    {
        Console.WriteLine("=== DRY-RUN (recover) ===");
        Console.WriteLine($"Target: {target}");
        Console.WriteLine();
        if (isFile) Console.WriteLine($"[RECOVER] {target}");
        else if (isDir)
        {
            var files = Directory.EnumerateFiles(target, "*.enc", SearchOption.AllDirectories).ToList();
            Console.WriteLine($"Bulunan .enc: {files.Count}");
        }
    }

    // ---------------- Options ----------------

    private sealed class Options
    {
        public string? TargetPath { get; set; }
        public string? OutPath { get; set; }
        public bool InPlace { get; set; }
        public bool DeleteSource { get; set; }
        public bool KeepSource { get; set; }
        public bool AssumeYes { get; set; }
        public string? Mode { get; set; }
        public string? RecoveryKey { get; set; }
        public bool DryRun { get; set; }
        public bool Verify { get; set; }
        public int Threads { get; set; } = 0; // 0 = auto

        public static Options Parse(string[] args)
        {
            var o = new Options();
            var list = new List<string>(args);

            for (int i = 0; i < list.Count; i++)
            {
                if (!list[i].StartsWith("-", StringComparison.Ordinal))
                {
                    o.TargetPath = list[i];
                    list.RemoveAt(i);
                    break;
                }
            }

            for (int i = 0; i < list.Count; i++)
            {
                string a = list[i].ToLowerInvariant();
                switch (a)
                {
                    case "--out":
                        if (i + 1 >= list.Count) throw new ArgumentException("--out için path gerekli.");
                        o.OutPath = list[++i];
                        break;
                    case "--inplace":
                        o.InPlace = true; break;
                    case "--delete-source":
                        o.DeleteSource = true; break;
                    case "--keep-source":
                        o.KeepSource = true; break;
                    case "--yes":
                        o.AssumeYes = true; break;
                    case "--mode":
                        if (i + 1 >= list.Count) throw new ArgumentException("--mode için değer gerekli.");
                        o.Mode = list[++i];
                        break;
                    case "--recovery-key":
                        if (i + 1 >= list.Count) throw new ArgumentException("--recovery-key için değer gerekli.");
                        o.RecoveryKey = list[++i];
                        break;
                    case "--dry-run":
                        o.DryRun = true; break;
                    case "--verify":
                        o.Verify = true; break;
                    case "--threads":
                        if (i + 1 >= list.Count) throw new ArgumentException("--threads için sayı gerekli.");
                        if (!int.TryParse(list[++i], out var t) || t < 1 || t > 64)
                            throw new ArgumentException("--threads 1..64 aralığında olmalı.");
                        o.Threads = t;
                        break;
                    default:
                        throw new ArgumentException($"Bilinmeyen seçenek: {list[i]}");
                }
            }

            if (o.DeleteSource && o.KeepSource)
                throw new ArgumentException("--delete-source ve --keep-source birlikte kullanılamaz.");

            return o;
        }
    }
}

// ==================== Progress (percent + speed + ETA) ====================

internal sealed class ProgressPrinter : IDisposable
{
    private readonly long _totalBytes;
    private long _processedBytes;
    private readonly Stopwatch _sw;
    private readonly Timer _timer;
    private readonly string _label;
    private volatile bool _completed;

    private ProgressPrinter(string label, long totalBytes)
    {
        _label = label;
        _totalBytes = Math.Max(1, totalBytes);
        _sw = Stopwatch.StartNew();

        // 4 kez/saniye güncelle
        _timer = new Timer(_ => Render(), null, 0, 250);
    }

    public static ProgressPrinter Start(string label, long totalBytes) => new(label, totalBytes);

    public void AddProcessedBytes(int bytes)
    {
        if (bytes <= 0) return;
        Interlocked.Add(ref _processedBytes, bytes);
    }

    public void Complete()
    {
        _completed = true;
        Render(final: true);
    }

    private void Render(bool final = false)
    {
        long done = Interlocked.Read(ref _processedBytes);
        if (done > _totalBytes) done = _totalBytes;

        double pct = (double)done / _totalBytes * 100.0;
        double seconds = Math.Max(0.001, _sw.Elapsed.TotalSeconds);
        double rate = done / seconds; // bytes/sec
        long remaining = _totalBytes - done;

        TimeSpan eta = rate > 1 ? TimeSpan.FromSeconds(remaining / rate) : TimeSpan.MaxValue;

        string left = $"{_label}: {pct,6:0.0}%";
        string mid = $"{FormatBytes(done)} / {FormatBytes(_totalBytes)}";
        string spd = $"{FormatBytes((long)rate)}/s";
        string etaText = eta == TimeSpan.MaxValue ? "ETA --:--:--" : $"ETA {eta:hh\\:mm\\:ss}";

        string line = $"{left} | {mid} | {spd} | {etaText}";

        lock (typeof(ProgressPrinter))
        {
            Console.Write("\r" + line.PadRight(Console.WindowWidth - 1));
            if (final)
                Console.WriteLine();
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }
        return i == 0 ? $"{bytes} {units[i]}" : $"{v:0.0} {units[i]}";
    }

    public void Dispose()
    {
        try { _timer.Dispose(); } catch { }
    }
}

// ==================== Crypto / RecoveryKey / Engine ====================

internal sealed class CryptoException : Exception
{
    public CryptoException(string message) : base(message) { }
}

internal static class RecoveryKey
{
    private const string Prefix = "CBX-RK1-";
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Generate()
    {
        byte[] data = RandomNumberGenerator.GetBytes(32);
        ushort crc = Crc16(data);

        byte[] all = new byte[34];
        Buffer.BlockCopy(data, 0, all, 0, 32);
        all[32] = (byte)(crc >> 8);
        all[33] = (byte)(crc & 0xFF);

        string b32 = Base32Encode(all);
        var grouped = string.Join("-", Enumerable.Range(0, (b32.Length + 3) / 4)
            .Select(i => b32.Substring(i * 4, Math.Min(4, b32.Length - i * 4))));

        CryptographicOperations.ZeroMemory(data);
        CryptographicOperations.ZeroMemory(all);

        return Prefix + grouped;
    }

    public static bool TryParse(string input, out byte[] key32)
    {
        key32 = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input)) return false;

        input = input.Trim().ToUpperInvariant();
        if (!input.StartsWith(Prefix, StringComparison.Ordinal)) return false;

        string body = input.Substring(Prefix.Length).Replace("-", "");
        byte[] all;
        try { all = Base32Decode(body); }
        catch { return false; }

        if (all.Length != 34) return false;

        byte[] data = new byte[32];
        Buffer.BlockCopy(all, 0, data, 0, 32);

        ushort crcExpected = (ushort)((all[32] << 8) | all[33]);
        ushort crcActual = Crc16(data);

        CryptographicOperations.ZeroMemory(all);

        if (crcExpected != crcActual)
        {
            CryptographicOperations.ZeroMemory(data);
            return false;
        }

        key32 = data;
        return true;
    }

    private static ushort Crc16(byte[] data)
    {
        const ushort poly = 0x1021;
        ushort crc = 0xFFFF;
        foreach (var b in data)
        {
            crc ^= (ushort)(b << 8);
            for (int i = 0; i < 8; i++)
                crc = (crc & 0x8000) != 0 ? (ushort)((crc << 1) ^ poly) : (ushort)(crc << 1);
        }
        return crc;
    }

    private static string Base32Encode(byte[] data)
    {
        var sb = new StringBuilder();
        int buffer = data[0];
        int next = 1;
        int bitsLeft = 8;

        while (bitsLeft > 0 || next < data.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < data.Length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bitsLeft += 8;
                }
                else
                {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }

            int index = (buffer >> (bitsLeft - 5)) & 0x1F;
            bitsLeft -= 5;
            sb.Append(Alphabet[index]);
        }

        return sb.ToString();
    }

    private static byte[] Base32Decode(string input)
    {
        input = input.Trim().ToUpperInvariant();
        var bytes = new List<byte>(input.Length * 5 / 8);

        int buffer = 0;
        int bitsLeft = 0;

        foreach (char c in input)
        {
            int val = Alphabet.IndexOf(c);
            if (val < 0) throw new FormatException("Base32 char invalid.");

            buffer = (buffer << 5) | (val & 0x1F);
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }

        return bytes.ToArray();
    }
}

internal static class FileCrypto2
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("CBX2");
    private const byte Version = 2;

    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int WrappedKeySize = 32;
    private const int GcmTagSize = 16;

    private const int DataKeySize = 32;
    private const int IvCtrSize = 16;
    private const int HmacSize = 32;

    private const int DefaultIterPw = 200_000;
    private const int DefaultIterRec = 200_000;

    private const int BufferSize = 1024 * 1024;

    internal sealed record HeaderInfo(string OriginalRelativePath, long OriginalSize);

    public static HeaderInfo PeekHeader(string encPath)
    {
        using var fs = File.OpenRead(encPath);
        var header = ReadHeader(fs, out _);
        return new HeaderInfo(header.Path, header.OriginalSize);
    }

    public static void EncryptFile(string inputPath, string outEncTmpPath, string password, byte[] recoveryKeyBytes, string originalRelativePath, Action<int>? onProcessedBytes)
    {
        if (!File.Exists(inputPath)) throw new IOException($"Dosya bulunamadı: {inputPath}");

        byte[] dataKey = RandomNumberGenerator.GetBytes(DataKeySize);

        byte[] saltPw = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] noncePw = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] kekPw = DeriveKekFromPassword(password, saltPw, DefaultIterPw);
        byte[] wrappedPw = new byte[WrappedKeySize];
        byte[] tagPw = new byte[GcmTagSize];
        AesGcmEncrypt(kekPw, noncePw, dataKey, wrappedPw, tagPw);

        byte[] saltRec = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonceRec = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] kekRec = DeriveKekFromRecovery(recoveryKeyBytes, saltRec, DefaultIterRec);
        byte[] wrappedRec = new byte[WrappedKeySize];
        byte[] tagRec = new byte[GcmTagSize];
        AesGcmEncrypt(kekRec, nonceRec, dataKey, wrappedRec, tagRec);

        long originalSize = new FileInfo(inputPath).Length;
        byte[] headerBytes = BuildHeaderBytes(
            (uint)DefaultIterPw, (uint)DefaultIterRec,
            saltPw, noncePw, wrappedPw, tagPw,
            saltRec, nonceRec, wrappedRec, tagRec,
            originalRelativePath,
            originalSize
        );

        DeriveEncMacKeys(dataKey, out var encKey, out var macKey);
        byte[] ivCtr = RandomNumberGenerator.GetBytes(IvCtrSize);

        using var input = File.OpenRead(inputPath);
        using var output = File.Create(outEncTmpPath);

        output.Write(headerBytes, 0, headerBytes.Length);
        output.Write(ivCtr, 0, ivCtr.Length);

        using var hmac = new HMACSHA256(macKey);
        hmac.TransformBlock(headerBytes, 0, headerBytes.Length, null, 0);
        hmac.TransformBlock(ivCtr, 0, ivCtr.Length, null, 0);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.KeySize = 256;
        aes.Key = encKey;
        using var ecb = aes.CreateEncryptor();

        byte[] counter = (byte[])ivCtr.Clone();
        byte[] inBuf = new byte[BufferSize];
        byte[] outBuf = new byte[BufferSize];
        byte[] ks = new byte[16];

        int read;
        while ((read = input.Read(inBuf, 0, inBuf.Length)) > 0)
        {
            XorWithCtr(ecb, counter, inBuf, outBuf, read, ks);
            output.Write(outBuf, 0, read);
            hmac.TransformBlock(outBuf, 0, read, null, 0);
            onProcessedBytes?.Invoke(read);
        }

        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        byte[] hmacTag = hmac.Hash!;
        output.Write(hmacTag, 0, hmacTag.Length);
        output.Flush(true);

        ZeroAll(dataKey, saltPw, noncePw, kekPw, wrappedPw, tagPw, saltRec, nonceRec, kekRec, wrappedRec, tagRec, headerBytes, encKey, macKey, ivCtr, counter, inBuf, outBuf, ks, hmacTag);
    }

    public static void DecryptFile(string encPath, string outPlainTmpPath, string? password, byte[]? recoveryKeyBytes, Action<int>? onProcessedBytes)
    {
        if ((password is null) == (recoveryKeyBytes is null))
            throw new ArgumentException("Decrypt için password veya recoveryKeyBytes değerlerinden yalnızca biri verilmelidir.");

        using var input = File.OpenRead(encPath);

        var header = ReadHeader(input, out int headerLen);

        long totalLen = input.Length;
        long hmacPos = totalLen - HmacSize;
        if (hmacPos <= headerLen + IvCtrSize)
            throw new CryptoException("Dosya bozuk (uzunluk).");

        long cipherStart = headerLen + IvCtrSize;
        long cipherLen = hmacPos - cipherStart;

        input.Position = hmacPos;
        byte[] expectedHmac = ReadExactly(input, HmacSize);

        byte[] dataKey = UnwrapDataKey(header, password, recoveryKeyBytes);
        DeriveEncMacKeys(dataKey, out var encKey, out var macKey);

        input.Position = 0;
        byte[] headerExact = ReadExactly(input, headerLen);
        byte[] ivCtr = ReadExactly(input, IvCtrSize);

        VerifyHmacStream(input, cipherStart, cipherLen, headerExact, ivCtr, macKey, expectedHmac);

        input.Position = cipherStart;
        using var output = File.Create(outPlainTmpPath);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.KeySize = 256;
        aes.Key = encKey;
        using var ecb = aes.CreateEncryptor();

        byte[] counter = (byte[])ivCtr.Clone();
        byte[] buf = new byte[BufferSize];
        byte[] ks = new byte[16];

        long remaining = cipherLen;
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buf.Length, remaining);
            int r = input.Read(buf, 0, toRead);
            if (r <= 0) throw new CryptoException("Dosya bozuk (cipher eksik).");

            XorWithCtr(ecb, counter, buf, buf, r, ks);
            output.Write(buf, 0, r);
            remaining -= r;
            onProcessedBytes?.Invoke(r);
        }

        output.Flush(true);

        long written = new FileInfo(outPlainTmpPath).Length;
        if (header.OriginalSize >= 0 && written != header.OriginalSize)
            throw new CryptoException($"Çözme boyutu uyuşmadı. Beklenen {header.OriginalSize}, yazılan {written}.");

        ZeroAll(dataKey, encKey, macKey, headerExact, ivCtr, counter, buf, ks, expectedHmac);
    }

    public static void RecoverPassword(string encPath, string outEncTmpPath, string newPassword, byte[] recoveryKeyBytes, Action<int>? onCopiedCipherBytes)
    {
        using var input = File.OpenRead(encPath);

        var header = ReadHeader(input, out int headerLen);

        long totalLen = input.Length;
        long hmacPos = totalLen - HmacSize;
        if (hmacPos <= headerLen + IvCtrSize)
            throw new CryptoException("Dosya bozuk (uzunluk).");

        long cipherStart = headerLen + IvCtrSize;
        long cipherLen = hmacPos - cipherStart;

        input.Position = hmacPos;
        byte[] expectedOldHmac = ReadExactly(input, HmacSize);

        byte[] dataKey = UnwrapDataKey(header, password: null, recoveryKeyBytes: recoveryKeyBytes);
        DeriveEncMacKeys(dataKey, out _, out var macKey);

        input.Position = 0;
        byte[] oldHeaderExact = ReadExactly(input, headerLen);
        byte[] ivCtr = ReadExactly(input, IvCtrSize);

        VerifyHmacStream(input, cipherStart, cipherLen, oldHeaderExact, ivCtr, macKey, expectedOldHmac);

        byte[] newSaltPw = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] newNoncePw = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] newKekPw = DeriveKekFromPassword(newPassword, newSaltPw, (int)header.IterPw);
        byte[] newWrappedPw = new byte[WrappedKeySize];
        byte[] newTagPw = new byte[GcmTagSize];
        AesGcmEncrypt(newKekPw, newNoncePw, dataKey, newWrappedPw, newTagPw);

        byte[] newHeaderBytes = BuildHeaderBytes(
            header.IterPw, header.IterRec,
            newSaltPw, newNoncePw, newWrappedPw, newTagPw,
            header.SaltRec, header.NonceRec, header.WrappedRec, header.TagRec,
            header.Path,
            header.OriginalSize
        );

        using var output = File.Create(outEncTmpPath);
        output.Write(newHeaderBytes, 0, newHeaderBytes.Length);
        output.Write(ivCtr, 0, ivCtr.Length);

        using var hmacNew = new HMACSHA256(macKey);
        hmacNew.TransformBlock(newHeaderBytes, 0, newHeaderBytes.Length, null, 0);
        hmacNew.TransformBlock(ivCtr, 0, ivCtr.Length, null, 0);

        input.Position = cipherStart;
        byte[] buf = new byte[BufferSize];
        long remaining = cipherLen;

        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buf.Length, remaining);
            int r = input.Read(buf, 0, toRead);
            if (r <= 0) throw new CryptoException("Dosya bozuk (cipher eksik).");

            output.Write(buf, 0, r);
            hmacNew.TransformBlock(buf, 0, r, null, 0);
            remaining -= r;
            onCopiedCipherBytes?.Invoke(r);
        }

        hmacNew.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        byte[] newHmac = hmacNew.Hash!;
        output.Write(newHmac, 0, newHmac.Length);
        output.Flush(true);

        ZeroAll(dataKey, expectedOldHmac, oldHeaderExact, ivCtr, newSaltPw, newNoncePw, newKekPw, newWrappedPw, newTagPw, newHeaderBytes, buf, newHmac);
    }

    public static void VerifyEncFile(string encPath, string? password, byte[]? recoveryKeyBytes)
    {
        if ((password is null) == (recoveryKeyBytes is null))
            throw new ArgumentException("Verify için password veya recoveryKeyBytes değerlerinden yalnızca biri verilmelidir.");

        using var input = File.OpenRead(encPath);
        var header = ReadHeader(input, out int headerLen);

        long totalLen = input.Length;
        long hmacPos = totalLen - HmacSize;
        if (hmacPos <= headerLen + IvCtrSize)
            throw new CryptoException("Dosya bozuk (uzunluk).");

        long cipherStart = headerLen + IvCtrSize;
        long cipherLen = hmacPos - cipherStart;

        input.Position = hmacPos;
        byte[] expectedHmac = ReadExactly(input, HmacSize);

        byte[] dataKey = UnwrapDataKey(header, password, recoveryKeyBytes);
        DeriveEncMacKeys(dataKey, out _, out var macKey);

        input.Position = 0;
        byte[] headerExact = ReadExactly(input, headerLen);
        byte[] ivCtr = ReadExactly(input, IvCtrSize);

        VerifyHmacStream(input, cipherStart, cipherLen, headerExact, ivCtr, macKey, expectedHmac);

        ZeroAll(dataKey, macKey, headerExact, ivCtr, expectedHmac);
    }

    // -------- internal structures --------

    private sealed class Header
    {
        public uint IterPw;
        public uint IterRec;

        public byte[] SaltPw = Array.Empty<byte>();
        public byte[] NoncePw = Array.Empty<byte>();
        public byte[] WrappedPw = Array.Empty<byte>();
        public byte[] TagPw = Array.Empty<byte>();

        public byte[] SaltRec = Array.Empty<byte>();
        public byte[] NonceRec = Array.Empty<byte>();
        public byte[] WrappedRec = Array.Empty<byte>();
        public byte[] TagRec = Array.Empty<byte>();

        public string Path = "";
        public long OriginalSize;
    }

    private static Header ReadHeader(Stream s, out int headerLen)
    {
        long start = s.Position;
        using var br = new BinaryReader(s, Encoding.UTF8, leaveOpen: true);

        byte[] magic = br.ReadBytes(4);
        if (magic.Length != 4 || !magic.SequenceEqual(Magic))
            throw new CryptoException("Bu dosya CryptoBox formatında değil (magic).");

        byte ver = br.ReadByte();
        if (ver != Version) throw new CryptoException($"Desteklenmeyen sürüm: {ver}");

        var h = new Header();
        h.IterPw = br.ReadUInt32();
        h.IterRec = br.ReadUInt32();

        h.SaltPw = br.ReadBytes(SaltSize);
        h.NoncePw = br.ReadBytes(NonceSize);
        h.WrappedPw = br.ReadBytes(WrappedKeySize);
        h.TagPw = br.ReadBytes(GcmTagSize);

        h.SaltRec = br.ReadBytes(SaltSize);
        h.NonceRec = br.ReadBytes(NonceSize);
        h.WrappedRec = br.ReadBytes(WrappedKeySize);
        h.TagRec = br.ReadBytes(GcmTagSize);

        ushort pathLen = br.ReadUInt16();
        if (pathLen == 0 || pathLen > 65535) throw new CryptoException("Path uzunluğu geçersiz.");
        byte[] pathBytes = br.ReadBytes(pathLen);
        if (pathBytes.Length != pathLen) throw new CryptoException("Dosya bozuk (path eksik).");
        h.Path = Encoding.UTF8.GetString(pathBytes);

        h.OriginalSize = br.ReadInt64();

        headerLen = (int)(s.Position - start);
        return h;
    }

    private static byte[] BuildHeaderBytes(
        uint iterPw, uint iterRec,
        byte[] saltPw, byte[] noncePw, byte[] wrappedPw, byte[] tagPw,
        byte[] saltRec, byte[] nonceRec, byte[] wrappedRec, byte[] tagRec,
        string originalRelativePath,
        long originalSize)
    {
        byte[] pathBytes = Encoding.UTF8.GetBytes(originalRelativePath);
        if (pathBytes.Length > ushort.MaxValue) throw new CryptoException("Orijinal yol çok uzun.");

        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write(Magic);
            bw.Write(Version);

            bw.Write(iterPw);
            bw.Write(iterRec);

            bw.Write(saltPw);
            bw.Write(noncePw);
            bw.Write(wrappedPw);
            bw.Write(tagPw);

            bw.Write(saltRec);
            bw.Write(nonceRec);
            bw.Write(wrappedRec);
            bw.Write(tagRec);

            bw.Write((ushort)pathBytes.Length);
            bw.Write(pathBytes);

            bw.Write(originalSize);
        }
        return ms.ToArray();
    }

    private static byte[] UnwrapDataKey(Header h, string? password, byte[]? recoveryKeyBytes)
    {
        if (password != null)
        {
            byte[] kek = DeriveKekFromPassword(password, h.SaltPw, (int)h.IterPw);
            byte[] dataKey = new byte[DataKeySize];
            AesGcmDecrypt(kek, h.NoncePw, h.WrappedPw, h.TagPw, dataKey);
            CryptographicOperations.ZeroMemory(kek);
            return dataKey;
        }

        if (recoveryKeyBytes == null)
            throw new CryptoException("Kurtarma anahtarı gerekli.");

        byte[] kekRec = DeriveKekFromRecovery(recoveryKeyBytes, h.SaltRec, (int)h.IterRec);
        byte[] dataKey2 = new byte[DataKeySize];
        AesGcmDecrypt(kekRec, h.NonceRec, h.WrappedRec, h.TagRec, dataKey2);
        CryptographicOperations.ZeroMemory(kekRec);
        return dataKey2;
    }

    private static byte[] DeriveKekFromPassword(string password, byte[] salt, int iterations)
    {
        if (iterations < 50_000) iterations = 50_000;
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    private static byte[] DeriveKekFromRecovery(byte[] recoveryKey32, byte[] salt, int iterations)
    {
        if (iterations < 50_000) iterations = 50_000;
        using var pbkdf2 = new Rfc2898DeriveBytes(recoveryKey32, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    private static void DeriveEncMacKeys(byte[] dataKey, out byte[] encKey, out byte[] macKey)
    {
        using var h1 = new HMACSHA256(dataKey);
        encKey = h1.ComputeHash(Encoding.ASCII.GetBytes("enc-key-v2"));
        using var h2 = new HMACSHA256(dataKey);
        macKey = h2.ComputeHash(Encoding.ASCII.GetBytes("mac-key-v2"));
        if (encKey.Length != 32 || macKey.Length != 32) throw new CryptoException("Key türetme hatası.");
    }

    private static void AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext32, byte[] ciphertext32, byte[] tag16)
    {
        using var gcm = new AesGcm(key);
        gcm.Encrypt(nonce, plaintext32, ciphertext32, tag16);
    }

    private static void AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext32, byte[] tag16, byte[] plaintextOut32)
    {
        try
        {
            using var gcm = new AesGcm(key);
            gcm.Decrypt(nonce, ciphertext32, tag16, plaintextOut32);
        }
        catch
        {
            throw new CryptoException("Parola/kurtarma anahtarı yanlış veya veri bozuk (AES-GCM doğrulama).");
        }
    }

    private static void VerifyHmacStream(Stream input, long cipherStart, long cipherLen, byte[] headerExact, byte[] ivCtr, byte[] macKey, byte[] expectedHmac)
    {
        using var hmac = new HMACSHA256(macKey);
        hmac.TransformBlock(headerExact, 0, headerExact.Length, null, 0);
        hmac.TransformBlock(ivCtr, 0, ivCtr.Length, null, 0);

        input.Position = cipherStart;
        byte[] buf = new byte[BufferSize];
        long remaining = cipherLen;

        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buf.Length, remaining);
            int r = input.Read(buf, 0, toRead);
            if (r <= 0) throw new CryptoException("Dosya bozuk (cipher eksik).");
            hmac.TransformBlock(buf, 0, r, null, 0);
            remaining -= r;
        }

        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        if (!CryptographicOperations.FixedTimeEquals(hmac.Hash!, expectedHmac))
            throw new CryptoException("Parola/kurtarma anahtarı yanlış veya dosya bozuk (HMAC doğrulama).");

        CryptographicOperations.ZeroMemory(buf);
    }

    private static void XorWithCtr(ICryptoTransform ecbEncryptor, byte[] counter16, byte[] input, byte[] output, int len, byte[] ksBlock16)
    {
        int offset = 0;
        while (offset < len)
        {
            int produced = ecbEncryptor.TransformBlock(counter16, 0, 16, ksBlock16, 0);
            if (produced != 16) throw new CryptoException("CTR keystream üretilemedi.");

            int chunk = Math.Min(16, len - offset);
            for (int i = 0; i < chunk; i++)
                output[offset + i] = (byte)(input[offset + i] ^ ksBlock16[i]);

            offset += chunk;
            IncrementCounter(counter16);
        }
    }

    private static void IncrementCounter(byte[] counter16)
    {
        for (int i = 15; i >= 8; i--)
        {
            counter16[i]++;
            if (counter16[i] != 0) break;
        }
    }

    private static byte[] ReadExactly(Stream s, int n)
    {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int r = s.Read(buf, off, n - off);
            if (r <= 0) throw new CryptoException("Beklenmeyen dosya sonu.");
            off += r;
        }
        return buf;
    }

    private static void ZeroAll(params byte[][] arrays)
    {
        foreach (var a in arrays)
            if (a != null) CryptographicOperations.ZeroMemory(a);
    }
}

using System;
using System.IO;
using System.Threading.Tasks;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Экспресс-замер энтропии Шеннона без чтения всего файла (3.0.0.11).
/// Читает 3 репрезентативных блока по 4 КБ (стандартный кластер NTFS):
/// начало (PE-заголовок и таблица секций), середину (предполагаемая точка кода)
/// и конец (оверлей/дроппер). Вместо 100 МБ с диска читается максимум 12 КБ —
/// менее 0.5 мс даже на старых HDD.
///
/// Энтропия считается ПО КАЖДОМУ блоку отдельно, а возвращается МАКСИМАЛЬНАЯ:
/// структурированный PE-заголовок (низкая энтропия) не «разбавляет» зашифрованное
/// тело, поэтому упакованное/зашифрованное вредоносное ПО детектируется по самой
/// хаотичной секции (середина-код или конечный оверлей).
/// </summary>
public static class FastEntropyScanner
{
    /// <summary>Размер одного блока выборки (4 КБ).</summary>
    public const int ChunkSize = 4096;

    /// <summary>Количество блоков выборки: начало, середина, конец.</summary>
    public const int MaxChunks = 3;

    /// <summary>Максимальный объём данных, участвующий в расчёте (12 КБ).</summary>
    public const int MaxSampleBytes = ChunkSize * MaxChunks;

    /// <summary>
    /// Маркер ошибки/недоступности файла. Энтропия Шеннона не бывает отрицательной,
    /// поэтому -1 однозначно отличает «не удалось прочитать» от «энтропия 0».
    /// </summary>
    public const double ErrorValue = -1.0;

    /// <summary>
    /// Считает энтропию по репрезентативной выборке (начало/середина/конец).
    /// Для больших файлов возвращает МАКСИМАЛЬНУЮ энтропию среди блоков.
    /// Никогда не бросает исключений.
    /// </summary>
    /// <param name="filePath">Путь к файлу.</param>
    /// <returns>Энтропия (0..8 бит/байт) или <see cref="ErrorValue"/> при ошибке/пустом файле.</returns>
    public static double GetFastEntropy(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length == 0)
            {
                return ErrorValue;
            }

            long fileSize = fileInfo.Length;

            // FileShare.ReadWrite: не мешаем браузеру/установщику, который ещё пишет файл.
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (fileSize <= MaxSampleBytes)
                {
                    // Совсем маленький файл — читаем целиком.
                    var small = new byte[(int)fileSize];
                    ReadFully(stream, small);
                    return EntropyCalculator.Compute(small);
                }

                // Большой файл: энтропия по каждому блоку ОТДЕЛЬНО.
                var chunk = new byte[ChunkSize];

                // 1. Начало: PE-заголовок и таблица секций.
                ReadFully(stream, chunk);
                double max = EntropyCalculator.Compute(chunk);

                // 2. Середина: предполагаемая точка кода.
                stream.Seek(fileSize / 2, SeekOrigin.Begin);
                ReadFully(stream, chunk);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));

                // 3. Конец: зашифрованный оверлей/дроппер.
                stream.Seek(-ChunkSize, SeekOrigin.End);
                ReadFully(stream, chunk);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));

                return max;
            }
        }
        catch (IOException)
        {
            // Файл занят/исчез/ещё не дописан — пропускаем.
            return ErrorValue;
        }
        catch (UnauthorizedAccessException)
        {
            // Нет доступа (системный файл и т.п.) — не считаем подозрительным.
            return ErrorValue;
        }
        catch (ArgumentException)
        {
            return ErrorValue;
        }
        catch (NotSupportedException)
        {
            return ErrorValue;
        }
    }

    /// <summary>
    /// Асинхронная версия <see cref="GetFastEntropy"/>. Чтение идёт через
    /// <see cref="Stream.ReadAsync(Memory{byte},System.Threading.CancellationToken)"/>,
    /// расчёт — синхронно по блокам (максимум 12 КБ, микросекунды).
    /// </summary>
    public static async Task<double> GetFastEntropyAsync(
        string filePath, System.Threading.CancellationToken cancellationToken = default)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length == 0)
            {
                return ErrorValue;
            }

            long fileSize = fileInfo.Length;

            using (var stream = new FileStream(
                       filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                       bufferSize: 4096, useAsync: true))
            {
                if (fileSize <= MaxSampleBytes)
                {
                    var small = new byte[(int)fileSize];
                    await ReadFullyAsync(stream, small, cancellationToken).ConfigureAwait(false);
                    return EntropyCalculator.Compute(small);
                }

                var chunk = new byte[ChunkSize];

                await ReadFullyAsync(stream, chunk, cancellationToken).ConfigureAwait(false);
                double max = EntropyCalculator.Compute(chunk);

                stream.Seek(fileSize / 2, SeekOrigin.Begin);
                await ReadFullyAsync(stream, chunk, cancellationToken).ConfigureAwait(false);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));

                stream.Seek(-ChunkSize, SeekOrigin.End);
                await ReadFullyAsync(stream, chunk, cancellationToken).ConfigureAwait(false);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));

                return max;
            }
        }
        catch (OperationCanceledException)
        {
            return ErrorValue;
        }
        catch (IOException)
        {
            return ErrorValue;
        }
        catch (UnauthorizedAccessException)
        {
            return ErrorValue;
        }
        catch (ArgumentException)
        {
            return ErrorValue;
        }
        catch (NotSupportedException)
        {
            return ErrorValue;
        }
    }

    // ---------------------------------------------------------------
    // Энтропия заголовка (3.0.0.44): детект «шифрования на месте»
    // ---------------------------------------------------------------

    /// <summary>
    /// Энтропия ТОЛЬКО первого блока файла (4 КБ). В отличие от <see cref="GetFastEntropy"/>,
    /// который возвращает МАКСИМУМ по трём блокам (для PE/упаковщиков), здесь важен именно
    /// уровень случайности НАЧАЛА файла: шифровальщик перезаписывает файл с нулевого байта,
    /// поэтому высокая энтропия заголовка — признак шифрования на месте, а не переименования
    /// или распаковки (структурированные заголовки текста/PE/ZIP дают низкую энтропию).
    /// Никогда не бросает исключений.
    /// </summary>
    /// <param name="filePath">Путь к файлу.</param>
    /// <returns>Энтропия первого блока (0..8 бит/байт) или <see cref="ErrorValue"/> при ошибке.</returns>
    public static double GetHeaderEntropy(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length == 0)
            {
                return ErrorValue;
            }

            long fileSize = fileInfo.Length;
            int len = (int)Math.Min(fileSize, ChunkSize);
            var buffer = new byte[len];
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                ReadFully(stream, buffer);
            }
            return EntropyCalculator.Compute(buffer);
        }
        catch (IOException) { return ErrorValue; }
        catch (UnauthorizedAccessException) { return ErrorValue; }
        catch (ArgumentException) { return ErrorValue; }
        catch (NotSupportedException) { return ErrorValue; }
    }

    /// <summary>
    /// Асинхронная версия <see cref="GetHeaderEntropy"/> — читает только первый блок 4 КБ
    /// (FileShare.ReadWrite не мешает дописывающему файл процессу). Никогда не бросает исключений.
    /// </summary>
    public static async Task<double> GetHeaderEntropyAsync(
        string filePath, System.Threading.CancellationToken cancellationToken = default)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length == 0)
            {
                return ErrorValue;
            }

            long fileSize = fileInfo.Length;
            int len = (int)Math.Min(fileSize, ChunkSize);
            var buffer = new byte[len];
            using (var stream = new FileStream(
                       filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                       bufferSize: 4096, useAsync: true))
            {
                await ReadFullyAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
            }
            return EntropyCalculator.Compute(buffer);
        }
        catch (OperationCanceledException) { return ErrorValue; }
        catch (IOException) { return ErrorValue; }
        catch (UnauthorizedAccessException) { return ErrorValue; }
        catch (ArgumentException) { return ErrorValue; }
        catch (NotSupportedException) { return ErrorValue; }
    }

    // ---------------------------------------------------------------
    // Адаптивная выборка (3.0.0.42, E2)
    // ---------------------------------------------------------------

    /// <summary>
    /// Нижняя граница «серой зоны» как доля от порога (3.0.0.42, E2): если базовая
    /// выборка 12 КБ дала энтропию в диапазоне [порог × 0.6, порог) — файл попадает
    /// в пограничный случай, и перед вердиктом добираются дополнительные блоки.
    /// </summary>
    public const double GrayZoneLowRatio = 0.6;

    /// <summary>
    /// Результат адаптивного замера (3.0.0.42, E2): итоговая энтропия и признак того,
    /// что для уточнения результата были использованы дополнительные блоки (серый диапазон у порога).
    /// </summary>
    public readonly record struct FastEntropyResult(double Entropy, bool AdaptiveUsed);

    /// <summary>
    /// Адаптивная оценка энтропии (3.0.0.42, E2). Выполняет базовый замер
    /// (<see cref="GetFastEntropyAsync"/>). Если результат попал в «серую зону»
    /// [порог × <see cref="GrayZoneLowRatio"/>, порог) — добирает ещё 3 блока по 4 КБ
    /// (смещение от середины, 75% файла, пред-конец) и возвращает максимум по всем
    /// блокам. Вне серой зоны добора нет — нулевой прирост нагрузки на типовом пути.
    /// Никогда не бросает исключений.
    /// </summary>
    public static async Task<FastEntropyResult> GetAdaptiveEntropyAsync(
        string filePath, double threshold, System.Threading.CancellationToken cancellationToken = default)
    {
        double baseEntropy = await GetFastEntropyAsync(filePath, cancellationToken).ConfigureAwait(false);
        if (baseEntropy < 0)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }

        // Файл целиком ≤ 12 КБ уже был прочитан полностью — добор бессмыслен.
        // Вне серой зоны добор не нужен: ниже — обычный файл, выше — сразу вердикт.
        double grayLow = threshold * GrayZoneLowRatio;
        if (baseEntropy >= threshold || baseEntropy < grayLow)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }

        double max = baseEntropy;
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length <= ChunkSize)
            {
                return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
            }

            long fileSize = fileInfo.Length;
            using (var stream = new FileStream(
                       filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                       bufferSize: 4096, useAsync: true))
            {
                var chunk = new byte[ChunkSize];

                // Блок A: смещение чуть дальше середины (другие секции кода).
                long mid = fileSize / 2;
                stream.Seek(Math.Min(mid + ChunkSize / 2, fileSize - ChunkSize), SeekOrigin.Begin);
                await ReadFullyAsync(stream, chunk, cancellationToken).ConfigureAwait(false);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));

                // Блок B: 75% файла.
                long q = (long)(fileSize * 0.75);
                stream.Seek(Math.Min(q, fileSize - ChunkSize), SeekOrigin.Begin);
                await ReadFullyAsync(stream, chunk, cancellationToken).ConfigureAwait(false);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));

                // Блок C: участок перед концом (оверлей/дроппер у самого хвоста).
                long tail = Math.Max(0, fileSize - 2 * ChunkSize);
                stream.Seek(tail, SeekOrigin.Begin);
                await ReadFullyAsync(stream, chunk, cancellationToken).ConfigureAwait(false);
                max = Math.Max(max, EntropyCalculator.Compute(chunk));
            }

            return new FastEntropyResult(max, AdaptiveUsed: true);
        }
        catch (OperationCanceledException)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }
        catch (IOException)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }
        catch (UnauthorizedAccessException)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }
        catch (ArgumentException)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }
        catch (NotSupportedException)
        {
            return new FastEntropyResult(baseEntropy, AdaptiveUsed: false);
        }
    }

    /// <summary>Читает ровно buffer.Length байт. Если поток оборвался раньше — остаток зануляется.</summary>
    private static void ReadFully(Stream stream, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer.Slice(total));
            if (read == 0)
            {
                // Файл укоротился или ещё дописывается — оставшуюся часть зануляем.
                buffer.Slice(total).Clear();
                break;
            }
            total += read;
        }
    }

    private static async Task ReadFullyAsync(
        Stream stream, Memory<byte> buffer, System.Threading.CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.Slice(total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                buffer.Slice(total).Span.Clear();
                break;
            }
            total += read;
        }
    }
}
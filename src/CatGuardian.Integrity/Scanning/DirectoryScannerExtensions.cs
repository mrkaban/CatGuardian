using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Scanning;

/// <summary>
/// 3.0.0.83: потоковое перечисление файлов через ограниченный Channel.
/// Продюсер (обходчик <see cref="DirectoryScanner.EnumerateFiles"/>) работает в фоне,
/// потребитель (например, Parallel.ForEachAsync) читает канал по мере поступления —
/// пути НЕ материализуются в массив заранее. На дисках с миллионами файлов это
/// убирает сотни МБ пиковой памяти и задержку старта до начала хеширования.
/// </summary>
public static class DirectoryScannerExtensions
{
    /// <summary>
    /// Ёмкость канала: при полном канале продюсер блокируется на записи (backpressure),
    /// поэтому в памяти одновременно находится не более этой величины путей, а не весь
    /// список. 4096 путей (~200 КБ) достаточно для того, чтобы обход диска не тормозил
    /// из-за ожидания потребителя.
    /// </summary>
    private const int ChannelCapacity = 4096;

    /// <summary>
    /// Возвращает файлы, соответствующие правилам из <paramref name="options"/>, ПОТОКОВО:
    /// обходчик-продюсер наполняет bounded-канал, а вызывающий получает пути по мере
    /// их обнаружения (эквивалент <see cref="DirectoryScanner.EnumerateFiles"/> без
    /// предварительной сборки списка в память).
    /// </summary>
    /// <remarks>
    /// Отмена: при отмене <paramref name="ct"/> цикл чтения завершается (OperationCanceledException),
    /// продюсер корректно останавливается через ту же проверку внутри обхода, канал закрывается,
    /// заблокированный писатель разблокируется. Исключения продюсера (кроме отмены) пробрасываются
    /// вызывающему после завершения чтения.
    /// </remarks>
    public static async IAsyncEnumerable<string> EnumerateFilesAsync(
        this DirectoryScanner scanner,
        ScanOptions options,
        [EnumeratorCancellation] CancellationToken ct = default,
        Action<string>? onDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(scanner);
        ArgumentNullException.ThrowIfNull(options);

        // SingleWriter=true: обходчик один; SingleReader=false: несколько потребителей
        // (Parallel.ForEachAsync) могут читать конкурентно. FullMode.Wait даёт backpressure.
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(ChannelCapacity)
        {
            SingleReader = false,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });

        // Продюсер-обходчик: пишет пути в канал. Task.Run с CancellationToken.None —
        // отмену обрабатываем внутри (через ct обхода), чтобы корректно завершить канал.
        var producer = Task.Run(async () =>
        {
            try
            {
                foreach (var file in scanner.EnumerateFiles(options, ct, onDirectory))
                {
                    // Ожидает освобождения места в канале (backpressure); при закрытии
                    // канала (отмена/ошибка потребителя) бросает ChannelClosedException.
                    await channel.Writer.WriteAsync(file, CancellationToken.None).ConfigureAwait(false);
                }
                channel.Writer.TryComplete();
            }
            catch (OperationCanceledException)
            {
                // Отмена обхода — штатное завершение канала без ошибки.
                channel.Writer.TryComplete();
            }
            catch (Exception ex)
            {
                // Ошибка обхода (например, неожиданное исключение вне DirectoryScanner) —
                // доставляем её потребителю через завершение канала.
                channel.Writer.TryComplete(ex);
            }
        }, CancellationToken.None);

        try
        {
            await foreach (var file in channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                yield return file;
            }
        }
        finally
        {
            // Потребитель вышел раньше (отмена/исключение/прерывание итерации):
            // закрываем канал, чтобы продюсер, заблокированный на Write, не висел вечно.
            // TryComplete безвреден, если канал уже завершён продюсером.
            channel.Writer.TryComplete();
        }

        // Пробрасываем исключения продюсера (кроме штатной отмены, обработанной выше).
        await producer.ConfigureAwait(false);
    }
}
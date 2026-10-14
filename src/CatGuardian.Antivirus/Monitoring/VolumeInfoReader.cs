using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>Информация о томе: метка, серийный номер, объём (п.5б).</summary>
public sealed record VolumeInfo(string? VolumeLabel, string? VolumeSerial, long? TotalSizeBytes);

/// <summary>
/// Читает информацию о съёмном томе через Win32 <c>GetVolumeInformationW</c>.
/// Серийный номер тома — устойчивый ключ для «Больше не спрашивать»:
/// буква диска переиспользуется, а серийник у конкретной флешки не меняется.
/// </summary>
public static class VolumeInfoReader
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumeInformationW(
        string lpRootPathName,
        StringBuilder lpVolumeNameBuffer,
        int nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        StringBuilder lpFileSystemNameBuffer,
        int nFileSystemNameSize);

    /// <summary>Возвращает информацию о томе. При любой ошибке — пустые поля (не бросает).</summary>
    public static VolumeInfo Read(string rootPath)
    {
        try
        {
            var name = new StringBuilder(261);
            var fs = new StringBuilder(261);
            if (GetVolumeInformationW(rootPath, name, name.Capacity, out var serial, out _, out _, fs, fs.Capacity))
            {
                var label = name.ToString();
                var serialHex = serial != 0 ? serial.ToString("X8") : null;
                long? size = null;
                try
                {
                    var di = new DriveInfo(rootPath);
                    if (di.IsReady)
                    {
                        size = di.TotalSize;
                    }
                }
                catch
                {
                    // Объём не критичен — остальное уже прочитано.
                }

                return new VolumeInfo(string.IsNullOrWhiteSpace(label) ? null : label, serialHex, size);
            }
        }
        catch
        {
            // Диск может быть ещё не готов в момент события — вернём пустые поля.
        }

        return new VolumeInfo(null, null, null);
    }

    /// <summary>Серийный номер тома (hex) или null, если получить не удалось.</summary>
    public static string? GetVolumeSerial(string rootPath) => Read(rootPath).VolumeSerial;
}
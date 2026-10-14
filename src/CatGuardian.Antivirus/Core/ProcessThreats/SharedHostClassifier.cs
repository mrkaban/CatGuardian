using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace CatGuardian.Antivirus.Core.ProcessThreats;

/// <summary>
/// Классификатор общих CDN/хостинговых сетей (3.0.0.23).
///
/// Используется в схеме «Process-Scoped Mitigation»: если удалённый IP принадлежит
/// крупному CDN (Cloudflare/Akamai/Fastly), глобальное правило брандмауэра НЕ создаётся —
/// майнер-процесс нейтрализуется точечно (NtSuspendProcess PID), чтобы не ломать
/// интернет легитимным программам, работающим через тот же общий адрес.
///
/// Помимо статических CIDR, «разделяемость» IP определяется эвристикой в
/// <see cref="ThreatDomainStore"/> (>= 2 разных заблокированных домена на один IP).
/// Чистый класс с независимой логикой — тестируется без сети.
/// </summary>
public static class SharedHostClassifier
{
    // ---------------------------------------------------------------
    // Статические CIDR-сети крупных CDN (IPv4). Обновляются при релизах.
    // Источники: официальные списки Cloudflare/Akamai/Fastly.
    // ---------------------------------------------------------------

    private static readonly string[] CloudflareCidrs =
    {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    };

    private static readonly string[] AkamaiCidrs =
    {
        "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "23.216.0.0/13",
        "63.208.0.0/12", "69.192.0.0/13", "72.246.0.0/15", "96.6.0.0/15",
        "104.64.0.0/10", "184.24.0.0/13", "184.84.0.0/14",
    };

    private static readonly string[] FastlyCidrs =
    {
        "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16",
    };

    private static readonly List<(uint Network, uint Mask)> CdnNetworks = BuildNetworks();

    private static List<(uint Network, uint Mask)> BuildNetworks()
    {
        var list = new List<(uint, uint)>();
        AddRange(list, CloudflareCidrs);
        AddRange(list, AkamaiCidrs);
        AddRange(list, FastlyCidrs);
        return list;
    }

    private static void AddRange(List<(uint Network, uint Mask)> list, IEnumerable<string> cidrs)
    {
        foreach (var cidr in cidrs)
        {
            if (TryParseCidr(cidr, out var network, out var mask))
            {
                list.Add((network, mask));
            }
        }
    }

    /// <summary>Разбирает «a.b.c.d/nn» в (сеть, маска). Чистый метод — тестируется.</summary>
    public static bool TryParseCidr(string cidr, out uint network, out uint mask)
    {
        network = 0;
        mask = 0;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var slash = cidr.IndexOf('/');
        if (slash <= 0) return false;

        if (!int.TryParse(cidr[(slash + 1)..], out var bits) || bits < 1 || bits > 32) return false;

        if (!IPAddress.TryParse(cidr[..slash], out var ip)) return false;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return false; // IPv6-диапазоны в MVP не учитываем

        var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        mask = bits == 0 ? 0 : uint.MaxValue << (32 - bits);
        network = value & mask;
        return true;
    }

    /// <summary>Преобразует IPv4-адрес в uint (порядок сети). Чистый метод — тестируется.</summary>
    public static bool TryIpToUInt32(IPAddress ip, out uint value)
    {
        value = 0;
        if (ip is null) return false;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return false;
        value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        return true;
    }

    /// <summary>Принадлежит ли IP одной из статических CDN-сетей (Cloudflare/Akamai/Fastly).</summary>
    public static bool IsCdn(IPAddress ip)
    {
        if (ip is null) return false;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv6-CDN в MVP не классифицируем — считаем «не CDN» (осторожное решение).
            return false;
        }

        if (!TryIpToUInt32(ip, out var value)) return false;

        foreach (var (network, mask) in CdnNetworks)
        {
            if ((value & mask) == network) return true;
        }

        return false;
    }

    /// <summary>
    /// Итоговый вердикт «можно ли глобально блокировать IP»: запрещено, если IP —
    /// статический CDN ИЛИ помечен как shared в хранилище доменов. Точечная заморозка
    /// процесса допустима всегда (она не влияет на остальных пользователей сети).
    /// </summary>
    public static bool IsGlobalBlockAllowed(IPAddress ip, ThreatDomainStore? store)
    {
        if (IsCdn(ip)) return false;
        if (store is not null && store.IsShared(ip)) return false;
        return true;
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using CatGuardian.Firewall.Core;
// В .NET 8 появился собственный System.Net.IPNetwork — однозначно указываем на наш.
using IPNetwork = CatGuardian.Firewall.Core.IPNetwork;

namespace CatGuardian.Firewall.Services
{
    /// <summary>
    /// Матчер исключённых IP-адресов/подсетей (3.0.0.18).
    /// Разбирает список строк вида «192.168.1.5» или «10.0.0.0/8» из настройки
    /// «Исключённые IP-адреса» сетевого экрана и отвечает на вопрос «входит ли
    /// адрес/подсеть в исключения». Используется:
    ///   - при применении правил блокировки угроз (пропуск исключённых адресов);
    ///   - при показе списка угроз (пометка исключённых записей);
    ///   - при согласовании уже применённых правил (удаление правил, содержащих
    ///     исключённые адреса).
    /// </summary>
    public sealed class IpExclusionMatcher
    {
        private readonly List<IPNetwork> _networks = new();

        public IReadOnlyList<string> Source { get; }

        public int Count => _networks.Count;

        public IpExclusionMatcher(IEnumerable<string>? excluded)
        {
            Source = excluded?
                .Select(x => (x ?? "").Trim())
                .Where(x => x.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList() ?? new List<string>();

            foreach (var raw in Source)
            {
                if (IPNetwork.TryParse(raw, out var network))
                {
                    _networks.Add(network);
                }
            }
        }

        /// <summary>
        /// true, если указанный IP-адрес входит хотя бы в одно исключение.
        /// Принимает одиночный IPv4/IPv6 (например «192.168.1.5»).
        /// </summary>
        public bool IsExcluded(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (!IPAddress.TryParse(ip.Trim(), out var address)) return false;
            return _networks.Any(n => n.Contains(address));
        }

        /// <summary>
        /// true, если строка является подсетью CIDR (например «10.0.0.0/8»),
        /// полностью покрытой хотя бы одним исключением.
        /// </summary>
        public bool IsCidrExcluded(string? cidr)
        {
            if (string.IsNullOrWhiteSpace(cidr)) return false;
            var value = cidr.Trim();
            if (!value.Contains('/')) return IsExcluded(value);
            if (!IPNetwork.TryParse(value, out var network)) return false;

            // Подсеть исключена, если все её адреса покрыты исключениями.
            // Для практических целей достаточно, чтобы сеть попадала в какую-либо
            // исключённую сеть с ТЕМ ЖЕ или более узким префиксом (полное вхождение).
            var (first, last) = RangeOf(network);
            return _networks.Any(n => n.Contains(first) && n.Contains(last));
        }

        /// <summary>
        /// true, если значение (IP или CIDR) исключено.
        /// </summary>
        public bool IsValueExcluded(string? value)
            => value != null && value.Contains('/') ? IsCidrExcluded(value) : IsExcluded(value);

        /// <summary>
        /// Удаляет из списка адресов те, что попадают в исключения.
        /// Возвращает число удалённых.
        /// </summary>
        public int Filter(List<string> addresses)
        {
            if (addresses is null || addresses.Count == 0 || _networks.Count == 0) return 0;
            int removed = addresses.RemoveAll(a => IsValueExcluded(a));
            return removed;
        }

        private static (IPAddress first, IPAddress last) RangeOf(IPNetwork network)
        {
            var bytes = network.Address.GetAddressBytes();
            var first = new byte[bytes.Length];
            var last = new byte[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
            {
                int bitsCovered = Math.Max(0, Math.Min(8, network.PrefixLength - i * 8));
                if (bitsCovered == 0)
                {
                    first[i] = 0;
                    last[i] = 0xFF;
                }
                else
                {
                    int mask = 0xFF << (8 - bitsCovered);
                    first[i] = (byte)(bytes[i] & mask);
                    last[i] = (byte)((bytes[i] & mask) | (0xFF & ~mask));
                }
            }
            return (new IPAddress(first), new IPAddress(last));
        }
    }
}
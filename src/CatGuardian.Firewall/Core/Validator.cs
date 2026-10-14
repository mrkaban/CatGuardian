using System;
using System.Collections.Generic;
using System.Net;

namespace CatGuardian.Firewall.Core
{
    /// <summary>Исключение при валидации правила.</summary>
    public class RuleValidationException : Exception
    {
        public RuleValidationException(string message) : base(message) { }
    }

    /// <summary>Валидация правил фаервола.</summary>
    public static class Validator
    {
        /// <summary>Проверяет корректность правила. Выбрасывает <see cref="RuleValidationException"/> при ошибках.</summary>
        public static void ValidateRule(FirewallRule rule)
        {
            if (string.IsNullOrWhiteSpace(rule.Name))
                throw new RuleValidationException("Имя правила не может быть пустым");

            // Проверка портов
            if (rule.LocalPorts != null)
                ValidatePorts(rule.LocalPorts, "локальные порты");
            if (rule.RemotePorts != null)
                ValidatePorts(rule.RemotePorts, "удалённые порты");

            // Проверка IP-адресов
            if (rule.LocalAddresses != null)
                ValidateAddresses(rule.LocalAddresses, "локальные адреса");
            if (rule.RemoteAddresses != null)
                ValidateAddresses(rule.RemoteAddresses, "удалённые адреса");

            // Проверка пути приложения
            if (rule.ApplicationPath != null && string.IsNullOrWhiteSpace(rule.ApplicationPath))
                throw new RuleValidationException("Путь к приложению не может быть пустым");

            // Проверка совместимости протокола и портов
            if (rule.Protocol == Protocol.Icmp && (rule.LocalPorts != null || rule.RemotePorts != null))
                throw new RuleValidationException("Для протокола ICMP порты не применяются");
            if (rule.Protocol == Protocol.Any && (rule.LocalPorts != null || rule.RemotePorts != null))
                throw new RuleValidationException("Для указания портов выберите конкретный протокол (TCP или UDP).");
        }

        /// <summary>Проверяет корректность списка портов.</summary>
        private static void ValidatePorts(IReadOnlyList<int> ports, string fieldName)
        {
            foreach (var port in ports)
            {
                if (port < 0 || port > 65535)
                    throw new RuleValidationException($"Некорректный порт {port} в {fieldName}. Допустимый диапазон: 0-65535");
            }
        }

        /// <summary>Проверяет корректность IP-адресов или подсетей.</summary>
        private static void ValidateAddresses(IReadOnlyList<string> addresses, string fieldName)
        {
            foreach (var addr in addresses)
            {
                if (addr == "*")
                    continue;
                if (!TryParseNetworkOrAddress(addr))
                    throw new RuleValidationException($"Некорректный IP-адрес или подсеть '{addr}' в {fieldName}");
            }
        }

        /// <summary>Пытается распарсить строку как IP-адрес или подсеть CIDR.</summary>
        public static bool TryParseNetworkOrAddress(string value)
        {
            value = value.Trim();
            if (value.Contains('/'))
                return IPNetwork.TryParse(value, out _);
            return IPAddress.TryParse(value, out _);
        }
    }

    /// <summary>Простая структура для парсинга подсетей IPv4/IPv6 (поддерживает CIDR).</summary>
    public readonly struct IPNetwork
    {
        public IPAddress Address { get; }
        public int PrefixLength { get; }

        private IPNetwork(IPAddress address, int prefixLength)
        {
            Address = address;
            PrefixLength = prefixLength;
        }

        /// <summary>Парсит строку вида "1.2.3.0/24" или "192.168.1.5" (как /32).</summary>
        public static bool TryParse(string value, out IPNetwork network)
        {
            network = default;
            value = value.Trim();
            var parts = value.Split('/');
            try
            {
                if (!IPAddress.TryParse(parts[0], out var ip))
                    return false;
                int prefix;
                if (parts.Length == 1)
                {
                    prefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                }
                else
                {
                    if (!int.TryParse(parts[1], out prefix))
                        return false;
                    var maxPrefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
                    if (prefix < 0 || prefix > maxPrefix)
                        return false;
                }
                network = new IPNetwork(ip, prefix);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Проверяет, содержит ли подсеть указанный IP-адрес.</summary>
        public bool Contains(IPAddress ip)
        {
            if (ip.AddressFamily != Address.AddressFamily)
                return false;
            var networkBytes = Address.GetAddressBytes();
            var ipBytes = ip.GetAddressBytes();
            int fullBytes = PrefixLength / 8;
            int remainingBits = PrefixLength % 8;
            for (int i = 0; i < fullBytes; i++)
            {
                if (networkBytes[i] != ipBytes[i])
                    return false;
            }
            if (remainingBits > 0)
            {
                int mask = 0xFF << (8 - remainingBits);
                if ((networkBytes[fullBytes] & mask) != (ipBytes[fullBytes] & mask))
                    return false;
            }
            return true;
        }

        public override string ToString()
        {
            return $"{Address}/{PrefixLength}";
        }
    }
}
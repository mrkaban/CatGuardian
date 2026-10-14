using System;
using System.Collections.Generic;
using System.Text;

namespace CatGuardian.Antivirus.Core.Protection;

/// <summary>Тип чувствительных данных, обнаруженных в буфере обмена.</summary>
public enum SensitiveDataType
{
    /// <summary>2FA/OTP-код: 6–8 цифр подряд.</summary>
    TwoFactorCode,
    /// <summary>Номер банковской карты (PAN): 13–19 цифр, контрольная цифра по алгоритму Луна (3.0.0.63).</summary>
    CreditCardNumber,
    /// <summary>Вероятный пароль (эвристика: буквы+цифры, спецсимволы, без пробелов).</summary>
    Password,
    /// <summary>Приватный ключ/секрет: WIF-подобный Base58, 64-символьный hex, PEM-блоки.</summary>
    PrivateKey,
    /// <summary>API-ключ/токен по известным префиксам (sk-, AKIA, ghp_, eyJ, ya29…).</summary>
    ApiSecret,
    /// <summary>Seed-фраза (структурно: 12/15/18/21/24 слов из строчных a-z).</summary>
    SeedPhrase,
}

/// <summary>Результат детекта: тип, человекочитаемое имя и замаскированное превью.</summary>
public sealed record SensitiveDataMatch(SensitiveDataType Type, string DisplayName, string MaskedPreview);

/// <summary>
/// Чистый детектор чувствительных данных в тексте буфера (3.0.0.26, Модуль 6:
/// «Защита буфера обмена / Crypto Clipper Protection»).
///
/// Вектор: стилеры читают буфер обмена (пароли, 2FA-коды, ключи). Модуль пассивно
/// сверяет содержимое буфера с чувствительными паттернами и предупреждает пользователя.
///
/// Честные ограничения (из оговорки ТЗ):
///  - без системного hook невозможно достоверно отличить «фоновое чтение буфера» от
///    легитимного; модуль лишь маркирует факт нахождения чувствительных данных;
///  - детект паролей/seed-фраз эвристический — возможны ложные срабатывания, поэтому
///    модуль помечен экспериментальным;
///  - модуль никогда не изменяет буфер сам; очистка — только по явной кнопке пользователя.
///  - с 3.0.0.63 дополнительно распознаётся номер банковской карты (PAN): 13–19 цифр с
///    разделителями групп (пробел/таб/дефис), валидность — по алгоритму Луна.
///
/// Производительность: <see cref="IsPlausible"/> — дешёвый пре-фильтр без регулярных
/// выражений (вызывается синхронно на WM_CLIPBOARDUPDATE); тяжёлая классификация
/// <see cref="TryDetect"/> — только для правдоподобных строк, в фоновом пуле потоков.
/// Никакого I/O, потоков и внешних зависимостей — покрывается юнит-тестами.
/// </summary>
public static class ClipboardSensitiveDetector
{
    /// <summary>Максимальный анализируемый размер текста буфера (защита от гигантских вставок).</summary>
    public const int MaxAnalyzedLength = 512;

    private static readonly string[] ApiPrefixes =
    {
        // OpenAI / Stripe / прочие sk-
        "sk-", "sk_live_", "sk_test_", "rk_live_",
        // AWS
        "AKIA", "ASIA",
        // Slack
        "xoxb-", "xoxp-", "xapp-", "xoxr-",
        // GitHub
        "ghp_", "gho_", "ghu_", "ghs_", "github_pat_",
        // Google
        "AIza",
        // Yandex
        "ya29.",
        // VK
        "vk1a.",
        // Telegram
        "tg1a_",
        // JWT (base64url, начинается с eyJ)
        "eyJ",
    };

    private static readonly string[] PemMarkers =
    {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN PRIVATE KEY-----",
    };

    /// <summary>
    /// Быстрый пре-фильтр: стоит ли вообще запускать полную классификацию.
    /// Дёшев (без регэкспов), вызывается синхронно на каждое событие буфера.
    /// </summary>
    public static bool IsPlausible(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var s = text!.Trim();
        if (s.Length is < 6 or > MaxAnalyzedLength)
        {
            return false;
        }

        // 2FA: строка из 6–8 цифр — пропускаем сразу.
        if (s.Length <= 8)
        {
            bool digits = true;
            foreach (char c in s)
            {
                if (c is < '0' or > '9')
                {
                    digits = false;
                    break;
                }
            }

            if (digits)
            {
                return true;
            }
        }

        // Компактные приватные ключи: 64 hex или 0x + 64 hex.
        if (s.Length == 64 || s.Length == 66)
        {
            bool hexOk = s.Length == 64;
            if (s.Length == 66)
            {
                hexOk = s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
            }

            if (hexOk)
            {
                int start = s.Length == 66 ? 2 : 0;
                for (int i = start; i < s.Length; i++)
                {
                    if (!Uri.IsHexDigit(s[i]))
                    {
                        hexOk = false;
                        break;
                    }
                }
            }

            if (hexOk)
            {
                return true;
            }
        }

        // Обычное слово без цифр, спецсимволов и пробелов — не пароль и не ключ.
        bool hasDigit = false, hasSpecial = false, hasSpace = false;
        foreach (char c in s)
        {
            if (c == ' ' || c == '\t') hasSpace = true;
            else if (c >= '0' && c <= '9') hasDigit = true;
            else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) hasSpecial = true;
        }

        return hasDigit || hasSpecial || hasSpace;
    }

    /// <summary>
    /// Полная классификация правдоподобного текста. Возвращает null, если ничего
    /// чувствительного не найдено. Вызывать в фоновом пуле потоков.
    /// </summary>
    public static SensitiveDataMatch? TryDetect(string? text)
    {
        if (!IsPlausible(text))
        {
            return null;
        }

        var s = text!.Trim();

        // 1. 2FA / OTP: ровно 6–8 цифр.
        if (s.Length is >= 6 and <= 8)
        {
            bool digits = true;
            foreach (char c in s)
            {
                if (c is < '0' or > '9')
                {
                    digits = false;
                    break;
                }
            }

            if (digits)
            {
                return new SensitiveDataMatch(SensitiveDataType.TwoFactorCode, "2FA-код / одноразовый пароль",
                    MaskTail(s, 2));
            }
        }

        // 1а. Номер банковской карты (3.0.0.63): 13–19 цифр (допускаются пробелы/табы/дефисы
        // между группами), контрольная цифра по алгоритму Луна. Исправляет «нет реакции на
        // номер карты» из теста 3.0.0.53 — раньше PAN ни в одну категорию не попадал.
        if (TryExtractCardDigits(s, out var cardDigits))
        {
            return new SensitiveDataMatch(SensitiveDataType.CreditCardNumber, "Номер банковской карты",
                MaskTail(cardDigits, 4));
        }

        // 2. PEM-блоки приватных ключей (многострочные).
        foreach (var marker in PemMarkers)
        {
            if (s.Contains(marker, StringComparison.Ordinal))
            {
                return new SensitiveDataMatch(SensitiveDataType.PrivateKey, "Приватный ключ (PEM)",
                    "-----BEGIN … PRIVATE KEY-----");
            }
        }

        // 3. Приватные ключи компактной записи:
        //    64 hex / 0x+64 hex / WIF-подобный Base58 (51–52 символа, префикс 5/K/L).
        if (IsHexOfLength(s, 64))
        {
            return new SensitiveDataMatch(SensitiveDataType.PrivateKey, "Приватный ключ (hex)", MaskMiddle(s, 6, 4));
        }

        if (IsWifLike(s))
        {
            return new SensitiveDataMatch(SensitiveDataType.PrivateKey, "Приватный ключ (WIF)", MaskMiddle(s, 6, 4));
        }

        // 4. API-ключи / токены по префиксам.
        foreach (var prefix in ApiPrefixes)
        {
            if (s.StartsWith(prefix, StringComparison.Ordinal) && s.Length >= prefix.Length + 16)
            {
                return new SensitiveDataMatch(SensitiveDataType.ApiSecret, $"API-ключ / токен («{prefix}…»)",
                    MaskMiddle(s, Math.Min(6, s.Length), 4));
            }
        }

        // 5. Seed-фраза: 12/15/18/21/24 слов, все a-z (3–8 символов), не менее 8 уникальных.
        if (TryClassifySeedPhrase(s, out var seedPreview))
        {
            return new SensitiveDataMatch(SensitiveDataType.SeedPhrase, "Seed-фраза восстановления", seedPreview);
        }

        // 6. Пароль (эвристика) — самая ложноположительная категория.
        if (LooksLikePassword(s))
        {
            return new SensitiveDataMatch(SensitiveDataType.Password, "Пароль (вероятно)", MaskMiddle(s, 4, 2));
        }

        return null;
    }

    // ---------------------------------------------------------------
    // Внутренние проверки
    // ---------------------------------------------------------------

    private static bool IsHexOfLength(string s, int length)
    {
        if (s.Length == length + 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        {
            for (int i = 2; i < s.Length; i++)
            {
                if (!Uri.IsHexDigit(s[i])) return false;
            }

            return true;
        }

        if (s.Length != length)
        {
            return false;
        }

        for (int i = 0; i < s.Length; i++)
        {
            if (!Uri.IsHexDigit(s[i])) return false;
        }

        return true;
    }

    /// <summary>WIF-подобная строка: 51–52 Base58-символа, префикс 5/K/L (структурно, без криптопроверки).</summary>
    private static bool IsWifLike(string s)
    {
        if (s.Length is not (51 or 52) || (s[0] != '5' && s[0] != 'K' && s[0] != 'L'))
        {
            return false;
        }

        foreach (char c in s)
        {
            if (Base58Alphabet.IndexOf(c) < 0) return false;
        }

        return true;
    }

    // ---------------------------------------------------------------
    // Номер банковской карты (PAN, 3.0.0.63)
    // ---------------------------------------------------------------

    private const int MinCardDigits = 13;
    private const int MaxCardDigits = 19;

    /// <summary>
    /// Проверяет, что строка похожа на номер банковской карты: только цифры и разделители
    /// групп (пробел/таб/дефис/неразрывный пробел), 13–19 цифр, контрольная сумма Луна.
    /// Возвращает сжатые цифры при успехе (для маскирования превью).
    /// </summary>
    private static bool TryExtractCardDigits(string s, out string digits)
    {
        digits = "";
        if (s.Length < MinCardDigits || s.Length > MaxCardDigits + 9)
        {
            return false;
        }

        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c is >= '0' and <= '9')
            {
                sb.Append(c);
                if (sb.Length > MaxCardDigits)
                {
                    return false;
                }
            }
            else if (c is ' ' or '\t' or '-' or '\u00A0')
            {
                continue; // разделитель групп
            }
            else
            {
                return false; // любой другой символ — не номер карты
            }
        }

        if (sb.Length is < MinCardDigits or > MaxCardDigits)
        {
            return false;
        }

        digits = sb.ToString();
        return IsLuhnValid(digits);
    }

    /// <summary>Алгоритм Луна (ISO/IEC 7812): сверху вниз удваивается каждая вторая цифра
    /// справа (контрольная цифра не удваивается), сумма кратна 10.</summary>
    private static bool IsLuhnValid(string digits)
    {
        int sum = 0;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            // Позиция от правого края (0 — контрольная цифра): нечётные удваиваем.
            if (((digits.Length - 1 - i) & 1) == 1)
            {
                d *= 2;
                if (d > 9)
                {
                    d -= 9;
                }
            }

            sum += d;
        }

        return sum % 10 == 0;
    }

    private static readonly string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private static bool TryClassifySeedPhrase(string s, out string preview)
    {
        preview = "";
        if (s.Length is < 36 or > 250)
        {
            return false;
        }

        string lowered = s.ToLowerInvariant();
        if (lowered != s)
        {
            // Смешанный регистр допустим? Seed-фразы пишутся строчными — строгий режим.
            return false;
        }

        // Разбиение по одинарным пробелам.
        var words = new List<string>();
        var current = new StringBuilder();
        foreach (char c in lowered)
        {
            if (c == ' ')
            {
                if (current.Length > 0)
                {
                    words.Add(current.ToString());
                    current.Clear();
                }
            }
            else if (c >= 'a' && c <= 'z')
            {
                current.Append(c);
            }
            else
            {
                return false; // любой не a-z символ (кроме пробела) — не seed-фраза
            }
        }

        if (current.Length > 0)
        {
            words.Add(current.ToString());
        }

        int count = words.Count;
        if (count is not (12 or 15 or 18 or 21 or 24))
        {
            return false;
        }

        // Каждое слово 3–8 символов; не менее 8 уникальных (фразы не состоят из повторов).
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var word in words)
        {
            if (word.Length is < 3 or > 8)
            {
                return false;
            }

            unique.Add(word);
        }

        if (unique.Count < 8)
        {
            return false;
        }

        preview = string.Join(" ", words.GetRange(0, 3)) + " … (" + count + " слов)";
        return true;
    }

    /// <summary>Эвристика пароля: 8–64 символа, без пробелов, буквы+цифры, и (спецсимвол или длина ≥ 12).</summary>
    private static bool LooksLikePassword(string s)
    {
        if (s.Length is < 8 or > 64)
        {
            return false;
        }

        // Явно не пароль: URL, email, файловые пути.
        if (s.Contains("://", StringComparison.Ordinal)
            || s.StartsWith("www.", StringComparison.OrdinalIgnoreCase)
            || s.StartsWith(@"\\", StringComparison.Ordinal)
            || s.Contains(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int atIndex = s.IndexOf('@');
        if (atIndex > 0 && s.IndexOf('.', atIndex) > atIndex)
        {
            return false; // email-подобная строка
        }

        bool hasLetter = false, hasDigit = false, hasSpecial = false;
        foreach (char c in s)
        {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
                return false; // пароли с пробелами редки; многословные строки уходят в seed-детект
            }

            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') hasLetter = true;
            else if (c >= '0' && c <= '9') hasDigit = true;
            else hasSpecial = true;
        }

        if (!hasLetter || !hasDigit)
        {
            return false;
        }

        // 123456789a — слишком просто; требуем спецсимвол ИЛИ достаточную длину.
        return hasSpecial || s.Length >= 12;
    }

    // ---------------------------------------------------------------
    // Маскирование превью
    // ---------------------------------------------------------------

    private static string MaskMiddle(string s, int head, int tail)
    {
        if (s.Length <= head + tail + 2)
        {
            return MaskTail(s, Math.Max(1, tail));
        }

        return s[..head] + "***" + s[^tail..];
    }

    private static string MaskTail(string s, int visibleTail)
    {
        if (s.Length <= visibleTail + 1)
        {
            return "***";
        }

        return "***" + s[^visibleTail..];
    }
}
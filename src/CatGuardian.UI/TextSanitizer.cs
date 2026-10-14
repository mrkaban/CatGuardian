using System;
using System.Text;

namespace CatGuardian.UI;

/// <summary>
/// v4-2 (3.0.0.50): санитизация строк из журнала событий/алертов перед отображением
/// и копированием в буфер обмена.
///
/// Проблема: сборки ETW-маскарада v1/v2 записывали в guardian.db события с путями,
/// содержащими сотни noncharacters (U+FFF0–U+FFFF) и битые склейки ("C:\Windowssystem32\...").
/// Такие строки зависали при отрисовке и при копировании деталей (ClipboardHelper с ретраями).
///
/// Здесь выполняется точечная «обезвреживающая» обработка:
///  - NUL-символы, суррогатные половины и noncharacters заменяются на '?';
///  - прочие управляющие символы (кроме \t \n \r) тоже заменяются на '?';
///  - строка усекается до <see cref="DefaultMaxLength"/> символов.
/// Быстрый путь: если строка короткая и не содержит подозрительных символов,
/// возвращается как есть без единой аллокации.
/// </summary>
public static class TextSanitizer
{
    /// <summary>Максимальная длина строки при чтении событий и копировании деталей.</summary>
    public const int DefaultMaxLength = 2000;

    /// <summary>
    /// Возвращает очищенную строку (не длиннее <paramref name="maxLength"/>) либо
    /// <c>null</c>, если на вход пришёл <c>null</c>.
    /// </summary>
    public static string? Sanitize(string? value, int maxLength = DefaultMaxLength)
    {
        if (value is null)
        {
            return null;
        }

        // Быстрый путь: короткая чистая строка — возвращаем без аллокаций.
        if (value.Length <= maxLength && IsClean(value))
        {
            return value;
        }

        return Build(value, maxLength);
    }

    /// <summary>
    /// Проверяет, что в строке нет ни одного «опасного» символа
    /// (NUL, суррогаты, noncharacters, управляющие, кроме \t \n \r).
    /// </summary>
    public static bool IsClean(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (IsBad(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBad(char c)
    {
        switch (c)
        {
            case '\t':
            case '\n':
            case '\r':
                return false;
        }

        int o = c;
        return o == 0
            || o < 32
            || o == 127
            || (o >= 0xD800 && o <= 0xDFFF)   // суррогатные половины
            || (o >= 0xFFF0 && o <= 0xFFFF);  // noncharacters
    }

    private static string Build(string value, int maxLength)
    {
        var sb = new StringBuilder(Math.Min(value.Length, maxLength));
        int count = 0;
        foreach (char c in value)
        {
            if (count >= maxLength)
            {
                break;
            }

            sb.Append(IsBad(c) ? '?' : c);
            count++;
        }

        return sb.ToString();
    }
}
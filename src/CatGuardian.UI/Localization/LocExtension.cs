using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Markup;
using CatGuardian.Localization;

namespace CatGuardian.UI.Localization;

/// <summary>
/// 3.0.0.92: XAML-расширение локализации. Использование:
/// <code>
/// <TextBlock Text="{loc:Loc Common.AppName}"/>
/// </code>
/// Ключи — в Strings.resx (русский) / Strings.en.resx (английский) проекта
/// CatGuardian.Localization. При смене языка (LanguageService.SetLanguage)
/// все активные расширения пере-вычисляют значения у своих целей — смена
/// языка применяется сразу, без перезапуска программы.
///
/// Цели хранятся слабыми ссылками: закрытые окна не удерживаются в памяти,
/// мёртвые ссылки вычищаются при очередной смене языка.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class LocExtension : MarkupExtension
{
    private static readonly object Sync = new();
    private static readonly List<WeakReference<LocExtension>> Active = new();

    private string _key = string.Empty;
    private WeakReference<DependencyObject>? _targetRef;
    private DependencyProperty? _targetProperty;

    static LocExtension()
    {
        // Подписка один раз на тип: смена языка обновляет ВСЕ активные привязки.
        // SetLanguage вызывается из UI-потока (настройки панели) — обновление
        // выполняется там же; на всякий случай маршалим через Dispatcher.
        LanguageService.LanguageChanged += () =>
        {
            var app = Application.Current;
            if (app?.Dispatcher is { HasShutdownStarted: false } d && !d.CheckAccess())
                d.BeginInvoke(new Action(RefreshAll));
            else
                RefreshAll();
        };
    }

    public LocExtension() { }

    public LocExtension(string key) => _key = key;

    /// <summary>Ключ строки в Strings.resx / Strings.en.resx.</summary>
    [ConstructorArgument("key")]
    public string Key
    {
        get => _key;
        set => _key = value ?? string.Empty;
    }

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var target = serviceProvider.GetService(typeof(IProvideValueTarget)) as IProvideValueTarget;

        // Цель — DependencyObject со свойством зависимости: регистрируем
        // для динамического обновления и выставляем текущее значение.
        if (target?.TargetObject is DependencyObject dependencyObject
            && target.TargetProperty is DependencyProperty dependencyProperty)
        {
            _targetRef = new WeakReference<DependencyObject>(dependencyObject);
            _targetProperty = dependencyProperty;

            lock (Sync) Active.Add(new WeakReference<LocExtension>(this));
            dependencyObject.SetValue(dependencyProperty, Value);
            return Value;
        }

        // Цель вне дерева зависимостей (Setter стиля, дизайнер) — просто строка.
        return Value;
    }

    /// <summary>Текущий перевод по ключу (отсутствующий ключ виден на экране как сам ключ).</summary>
    private string Value => string.IsNullOrEmpty(_key) ? string.Empty : Tr.T(_key);

    /// <summary>Пере-перевод всех живых целей (после смены языка).</summary>
    private static void RefreshAll()
    {
        lock (Sync)
        {
            for (int i = Active.Count - 1; i >= 0; i--)
            {
                if (!Active[i].TryGetTarget(out var ext) || ext._targetRef is null || !ext._targetRef.TryGetTarget(out var target))
                {
                    Active.RemoveAt(i); // мёртвая ссылка: окно закрыто
                    continue;
                }

                if (ext._targetProperty is not null)
                    target.SetValue(ext._targetProperty, ext.Value);
            }
        }
    }
}

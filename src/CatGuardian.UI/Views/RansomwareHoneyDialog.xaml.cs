using System.Windows;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Диалог-предупреждение (3.0.0.8): пользователь включает защиту от шифровальщиков с
/// использованием приманок, а модуль «Приманки» инспектора файлов выключен.
/// Предлагает включить приманки и перейти к их настройке либо продолжить без них.
/// </summary>
public partial class RansomwareHoneyDialog : Window
{
    /// <summary>true — пользователь согласился включить приманки и перейти в их настройки.</summary>
    public bool EnableHoneypots { get; private set; }

    /// <summary>true — пользователь решил продолжить без приманок (только поведенческий анализ).</summary>
    public bool ContinueWithout { get; private set; }

    public RansomwareHoneyDialog()
    {
        InitializeComponent();
    }

    private void OnEnableAndGo(object sender, RoutedEventArgs e)
    {
        EnableHoneypots = true;
        DialogResult = true;
    }

    private void OnContinueWithout(object sender, RoutedEventArgs e)
    {
        ContinueWithout = true;
        DialogResult = true;
    }
}
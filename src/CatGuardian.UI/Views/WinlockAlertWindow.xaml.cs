using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CatGuardian.Antivirus.Core;
using CatGuardian.Integrity.Ipc;
using CatGuardian.UI;

using CatGuardian.Localization;

namespace CatGuardian.UI.Views;

/// <summary>
/// Окно алерта Winlock Protection (3.0.0.20): превентивная изоляция баннера-
/// блокировщика экрана уже выполнена службой (файл переименован в .bak, запись
/// автозагрузки удалена). Окно информационное: пользователь либо восстанавливает
/// файл и доверяет элементу (вносит ветку в эталон), либо оставляет его
/// изолированным. Решение уходит через <see cref="MonitorPipeClient"/> (WinlockAction).
/// </summary>
public partial class WinlockAlertWindow : Window
{
    private readonly WinlockAlertDto _alert;

    /// <summary>Максимальная длина отображаемого пути; длинные усекаются по центру.</summary>
    private const int MaxPathLength = 76;

    public WinlockAlertWindow(WinlockAlertDto alert)
    {
        InitializeComponent();
        _alert = alert;
        Fill(alert);
    }

    private void Fill(WinlockAlertDto a)
    {
        // P17: динамический баннер — файл перемещён в КАРАНТИН, а не «в .bak»
        // (статичный текст про .bak убран из XAML; fallback .bak — только если карантин не прошёл).
        if (WinlockBannerNote is not null)
        {
            var prefix = "Блокировщик экрана прячет рабочий стол за фальшивым баннером и требует выкуп. ";
            WinlockBannerNote.Text = a.IsQuarantined
                ? prefix + Tr.T("Al2168") // «Файл перемещён в карантин (зашифрован).»
                : a.FileRenamed
                    ? prefix + Tr.T("Al2069") // «.bak»-fallback
                    : prefix + "Запись автозагрузки удалена.";
        }

        // P14: алерт «запись автозапуска баннера удалена автоматически» (P12-A,
        // actionKey «winlock_autoremove:») — ИНФОРМАЦИОННЫЙ: файл уже нейтрализован,
        // кнопки действий не нужны (раньше «Доверять» ничего не делала — «файл
        // восстановлен: False, эталон: False»). Только «ОК/Закрыть».
        if (a.ActionKey.StartsWith("winlock_autoremove:", StringComparison.Ordinal))
        {
            WinlockStatus.Text = Tr.T("Al2167");
            WinlockStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            ActionFile.Text = string.IsNullOrWhiteSpace(a.Details) ? Tr.T("Al2073") + a.Branch + "\\" + a.ValueName + "." : a.Details;
            ActionKill.Text = "";
            ActionKill.Visibility = Visibility.Collapsed;
            ActionEntry.Text = "";
            ActionEntry.Visibility = Visibility.Collapsed;
            SetPath(WinlockFilePath, a.FilePath);
            WinlockZone.Text = "—";
            WinlockBranch.Text = a.Branch;
            WinlockEntryName.Text = a.ValueName.Length > 0 ? a.ValueName : Tr.T("Al2077");
            WinlockSignature.Text = string.IsNullOrEmpty(a.SignatureText) ? "—" : a.SignatureText;
            WinlockClam.Text = "—";
            WinlockRiskRow.Visibility = Visibility.Collapsed;
            if (!string.IsNullOrWhiteSpace(a.Details))
            {
                StatusText.Text = a.Details;
                StatusText.Visibility = Visibility.Visible;
            }
            // Только «ОК/Закрыть».
            BtnWinlockRestore.Visibility = Visibility.Collapsed;
            BtnWinlockKeep.Visibility = Visibility.Collapsed;
            BtnWinlockClose.Content = Tr.T("Al2060");
            RefreshStatusBlockVisibility();
            return;
        }

        // 3.0.1.6 (P1-3): WinlockShield-алерт (actionKey с префиксом «winlock_shield:») —
        // баннер заблокирован детектором Winlock Shield: кнопки «Добавить в доверенные» /
        // «Оставить изолированным» / «Закрыть» (вместо «Восстановить/Оставить изолированным»).
        if (a.ActionKey.StartsWith("winlock_shield:", StringComparison.Ordinal))
        {
            WinlockStatus.Text = Tr.T("Al2167");
            WinlockStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            // P4-D: «Файл перемещён в карантин» — только если карантин РЕАЛЬНО прошёл
            // (IsolatedPath не пуст). В ВМ3 карантин Taskmgr.exe падал с Access denied,
            // а алерт писал «Файл перемещён в карантин (зашифрован)» — ложь.
            if (string.IsNullOrEmpty(a.IsolatedPath))
            {
                ActionFile.Text = Tr.T("Al2180");
                ActionFile.Foreground = (System.Windows.Media.Brush)FindResource("AmberBrush");
            }
            else
            {
                ActionFile.Text = Tr.T("Al2168");
            }
            ActionKill.Text = a.ProcessKilled ? Tr.T("Al2071") : "";
            ActionKill.Visibility = ActionKill.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
            ActionEntry.Text = Tr.T("Al2169");
            ActionEntry.Visibility = Visibility.Visible;

            SetPath(WinlockFilePath, a.FilePath);
            // P6-A (3.0.1.6-p6): пометка кириллического маскарада СРАЗУ под путём
            // (требование пользователя; раньше фраза была только в сводке StatusText).
            if (MasqueradeNames.IsMasqueradePath(a.FilePath))
            {
                WinlockMasqueradeWarning.Text = Tr.T("Al2181");
                WinlockMasqueradeWarning.Visibility = Visibility.Visible;
            }
            else WinlockMasqueradeWarning.Visibility = Visibility.Collapsed;

            // P16: честные значения для shield-алерта (баннер-маскарад):
            // зона — «системный маскарад», запись — имя файла (не «(значение по умолчанию)»).
            WinlockZone.Text = "системный маскарад";
            WinlockBranch.Text = "—";
            WinlockEntryName.Text = System.IO.Path.GetFileName(a.FilePath) ?? "—";
            WinlockSignature.Text = string.IsNullOrEmpty(a.SignatureText) ? "—" : a.SignatureText;
            WinlockClam.Text = "—";
            WinlockRiskRow.Visibility = Visibility.Collapsed;

            // P4-D: детали службы — пометка кириллического маскарада (⚠ пути с кириллицей),
            // сверка SHA-256 системной утилиты с эталоном, факт неудачного карантина.
            if (!string.IsNullOrWhiteSpace(a.Details))
            {
                StatusText.Text = a.Details;
                StatusText.Visibility = Visibility.Visible;
            }

            // Кнопки WinlockShield: «Добавить в доверенные» + «Закрыть».
            // P14: кнопка «Удалить файл» УБРАНА (требование пользователя).
            // P16: «Оставить изолированным» тоже скрыта — файл УЖЕ изолирован службой,
            // подтверждать нечего; остаётся «Добавить в доверенные» (восстановление) + «Закрыть».
            BtnWinlockRestore.Content = Tr.T("Al2160");
            BtnWinlockRestore.ToolTip = Tr.T("Al2163");
            BtnWinlockKeep.Visibility = Visibility.Collapsed;
            BtnWinlockClose.Content = Tr.T("Al2060"); // «Закрыть»
            BtnWinlockClose.ToolTip = null;

            RefreshStatusBlockVisibility();
            return;
        }

        // Статус в шапке отражает ФАКТИЧЕСКИЙ результат изоляции: угроза красным,
        // при частичной неудаче — честное предупреждение вместо «всё сделано».
        // 3.0.0.48 (G3): подмена точки входа Windows (Userinit/Shell) — жёсткий вердикт.
        if (!string.IsNullOrEmpty(a.EntryPointKind))
        {
            WinlockStatus.Text = a.EntryPointKind.Equals("Userinit", StringComparison.OrdinalIgnoreCase)
                ? Tr.T("Al2061")
                : Tr.T("Al2062");
            WinlockStatus.Foreground = (System.Windows.Media.Brush)FindResource("RedBrush");
            // Точка входа показывается в баннере вердикта — видна без прокрутки.
            WinlockEntryPoint.Text = a.EntryPointKind.Equals("Userinit", StringComparison.OrdinalIgnoreCase)
                ? Tr.T("Al2063")
                : Tr.T("Al2064");
            WinlockEntryPoint.Visibility = Visibility.Visible;
        }
        else if (a.EntryDeleted && !a.FileRenamed)
        {
            // 3.0.0.62: формулировка унифицирована — без «проверьте его вручную»
            // (файл изолировать не удалось, но задача панели — показать факт).
            WinlockStatus.Text =
                Tr.T("Al2065") +
                Tr.T("Al2066");
        }
        else
        {
            WinlockStatus.Text =
                Tr.T("Al2065") +
                Tr.T("Al2068");
        }

        // P15: изоляция карантином (зашифрованная .cgq-копия) — показываем «перемещён
        // в карантин», а не «переименован в .bak» (раньше окно лгало про .bak).
        ActionFile.Text = a.IsQuarantined
            ? Tr.T("Al2168")
            : a.FileRenamed
                ? Tr.T("Al2069")
                : Tr.T("Al2070");
        ActionKill.Text = a.ProcessKilled
            ? Tr.T("Al2071")
            : "";
        ActionKill.Visibility = ActionKill.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        // 3.0.0.48 (G3): для подмены точки входа запись НЕ удаляется целиком —
        // значение Winlogon «ремонтируется» (вырезается только вредоносная команда).
        ActionEntry.Text = a.EntryPointRepaired
            ? Tr.T("Al2072")
            : a.EntryDeleted
                ? Tr.T("Al2073") + a.Branch + "\\" + a.ValueName + "."
                : Tr.T("Al2074");
        ActionEntry.Visibility = ActionEntry.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

        SetPath(WinlockFilePath, a.FilePath);
        WinlockZone.Text = string.IsNullOrEmpty(a.RiskZone) ? "—" : a.RiskZone;

        WinlockBranch.Text = a.Branch;
        WinlockEntryName.Text = a.EntryKind switch
        {
            AutoStartEntryKind.TaskScheduler => Tr.T("Al2075") + a.ValueName,
            // 3.0.0.41 (A2): файл в папке Startup.
            AutoStartEntryKind.StartupFolder => Tr.T("Al2076") + a.ValueName,
            _ => a.ValueName.Length > 0 ? a.ValueName : Tr.T("Al2077"),
        };

        WinlockSignature.Text = string.IsNullOrEmpty(a.SignatureText) ? "—" : a.SignatureText;
        WinlockClam.Text = string.IsNullOrEmpty(a.ClamVerdict) ? "—" : a.ClamVerdict;
        if (a.RiskScore > 0)
        {
            WinlockRisk.Text = Tr.TF("Alert.RiskScoreFmt", a.RiskScore);
        }
        else
        {
            WinlockRiskRow.Visibility = Visibility.Collapsed;
        }

        // Восстановление возможно, только если файл реально переименован в .bak.
        if (string.IsNullOrEmpty(a.IsolatedPath))
        {
            BtnWinlockRestore.IsEnabled = false;
            BtnWinlockRestore.ToolTip = Tr.T("Al2078");
        }

        // P17: «Оставить изолированным» — бессмысленная кнопка во всех случаях (файл уже
        // изолирован службой) — скрываем глобально. Остаются «Восстановить и доверять» + «Закрыть».
        BtnWinlockKeep.Visibility = Visibility.Collapsed;

        // Статус-блок не должен выглядеть «пустым квадратом» при открытии окна.
        RefreshStatusBlockVisibility();
    }

    /// <summary>Показывает текст в статус-блоке (блок при этом становится видимым).</summary>
    private void SetActionStatus(string text)
    {
        ActionStatus.Text = text;
        if (StatusBlock is not null) StatusBlock.Visibility = Visibility.Visible;
    }

    /// <summary>Скрывает статус-блок, если в нём нет ни одного сообщения.</summary>
    private void RefreshStatusBlockVisibility()
    {
        if (StatusBlock is null) return;
        var hasContent = StatusText.Visibility == Visibility.Visible ||
                         !string.IsNullOrEmpty(ActionStatus?.Text);
        StatusBlock.Visibility = hasContent ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Устанавливает путь с усечением по центру; полный путь — в ToolTip.</summary>
    private static void SetPath(TextBox box, string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            box.Text = "—";
            box.ToolTip = null;
            return;
        }
        box.Text = AutoStartAlertWindow.CompactPath(path, MaxPathLength);
        box.ToolTip = path;
    }

    // ---------------------------------------------------------------
    // Действия
    // ---------------------------------------------------------------

    /// <summary>Восстановить файл (.bak → исходный путь) и внести ветку в эталон (доверять).
    /// 3.0.1.6 (P1-3): для WinlockShield-алерта — «Добавить в доверенные» (whitelist +
    /// восстановление из карантина).</summary>
    private async void OnWinlockRestore(object sender, RoutedEventArgs e)
    {
        if (_alert.ActionKey.StartsWith("winlock_shield:", StringComparison.Ordinal))
        {
            if (MessageBox.Show(this,
                    Tr.T("Al2163"),
                    "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            {
                return;
            }

            await SendActionAsync(WinlockActionKind.TrustAndRestore, Tr.T("Al2165"));
            return;
        }

        if (MessageBox.Show(this,
                Tr.T("Al2079") +
                Tr.T("Al2080"),
                "Cat Guardian", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }

        await SendActionAsync(WinlockActionKind.RestoreAndTrust, Tr.T("Al2081"));
    }

    /// <summary>Оставить элемент изолированным (файл .bak, запись удалена).
    /// 3.0.1.6 (P1-3): для WinlockShield-алерта — «Удалить файл» (безвозвратно из карантина).</summary>
    private async void OnWinlockKeep(object sender, RoutedEventArgs e)
    {
        // P14: для WinlockShield-алерта «Оставить изолированным» (кнопка «Удалить файл»
        // убрана — безвозвратное удаление из карантина не предлагается).
        if (_alert.ActionKey.StartsWith("winlock_shield:", StringComparison.Ordinal))
        {
            await SendActionAsync(WinlockActionKind.KeepIsolated, Tr.T("Al2170"));
            return;
        }

        await SendActionAsync(WinlockActionKind.KeepIsolated, Tr.T("Al2082"));
    }

    /// <summary>Закрыть окно. 3.0.1.6 (P1-3): для WinlockShield-алерта — «Завершить»:
    /// оставить файл изолированным (процесс уже завершён службой) и закрыть окно.</summary>
    private void OnWinlockClose(object sender, RoutedEventArgs e)
    {
        // P14: «Закрыть» — просто закрывает окно (файл уже изолирован службой,
        // отдельное действие не требуется).
        DialogResult = false;
    }

    /// <summary>Открывает папку изолированного файла в проводнике.</summary>
    private void OnWinlockOpenFolder(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = !string.IsNullOrWhiteSpace(_alert.IsolatedPath) ? _alert.IsolatedPath : _alert.FilePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                SetActionStatus(Tr.T("Al2083"));
                return;
            }
            OpenObjectFolder(path);
            SetActionStatus(Tr.T("Al2084"));
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al2085") + ex.Message);
        }
    }

    /// <summary>«Копировать детали»: все поля алерта Winlock в буфер обмена (как в остальных алерт-окнах).</summary>
    private async void OnCopyAll(object sender, RoutedEventArgs e)
    {
        try
        {
            var text =
                WinlockStatus.Text + "\n" +
                (string.IsNullOrEmpty(_alert.EntryPointKind)
                    ? ""
                    : WinlockEntryPoint.Text + "\n") +
                Tr.T("Al2086") +
                ActionFile.Text + "\n" +
                (ActionKill.Text.Length > 0 ? ActionKill.Text + "\n" : "") +
                ActionEntry.Text + "\n" +
                Tr.T("Al2087") + _alert.FilePath + "\n" +
                Tr.T("Al2088") + (WinlockZone.Text == "—" ? "" : WinlockZone.Text) + "\n" +
                Tr.T("Al2089") + WinlockBranch.Text + "\n" +
                Tr.T("Al2090") + WinlockEntryName.Text + "\n" +
                Tr.T("Al2091") + WinlockSignature.Text + "\n" +
                Tr.T("Al2092") + WinlockClam.Text + "\n" +
                (WinlockRiskRow.Visibility == Visibility.Visible ? Tr.T("Al2093") + WinlockRisk.Text + "\n" : "") +
                Tr.T("Al2094") + _alert.Details;
            // 3.0.0.57: фоновая запись (Win32, без OLE) — UI-поток не блокируется.
            var ok = await ClipboardHelper.TryCopyToClipboardAsync(text);
            SetActionStatus(ok ? Tr.T("Al2095")
                               : Tr.T("Al2096"));
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al2097") + ex.Message);
        }
    }

    /// <summary>Открывает папку объекта в проводнике (файл выделяется, если существует).</summary>
    private static void OpenObjectFolder(string path)
    {
        if (File.Exists(path))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true,
            });
            return;
        }
        var dir = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
        {
            Process.Start("explorer.exe", $"\"{dir}\"");
        }
    }

    /// <summary>
    /// Отправляет решение службе (WinlockAction) и ждёт ФАКТИЧЕСКИЙ результат операции.
    /// Выполняется асинхронно, чтобы окно не «зависало» на время ожидания службы.
    /// </summary>
    private async Task SendActionAsync(WinlockActionKind action, string busyText)
    {
        SetBusy(true);
        try
        {
            SetActionStatus(busyText);
            var dto = new WinlockActionDto
            {
                ActionKey = _alert.ActionKey,
                Action = action,
                FilePath = _alert.FilePath,
                IsolatedPath = _alert.IsolatedPath,
                EntryKind = _alert.EntryKind,
                Branch = _alert.Branch,
                ValueName = _alert.ValueName,
            };

            var (sent, ok, error) = await Task.Run(() =>
                MonitorPipeClient.TrySendWinlockAction(dto, TimeSpan.FromSeconds(35)));

            if (!sent)
            {
                SetActionStatus(Tr.T("Al2098") +
                                (string.IsNullOrEmpty(error) ? Tr.T("Al2099") : error));
                return;
            }

            if (ok)
            {
                // 3.0.1.6 (P1-3): статусы успеха для WinlockShield-действий.
                SetActionStatus(action switch
                {
                    WinlockActionKind.TrustAndRestore => Tr.T("Al2171"),
                    WinlockActionKind.DeleteFile => Tr.T("Al2172"),
                    WinlockActionKind.RestoreAndTrust => Tr.T("Al2100"),
                    _ => Tr.T("Al2101"),
                });
                DialogResult = true;
            }
            else
            {
                SetActionStatus(Tr.T("Al2102") +
                                (string.IsNullOrEmpty(error) ? Tr.T("Al2103") : error) +
                                Tr.T("Al2104"));
            }
        }
        catch (Exception ex)
        {
            SetActionStatus(Tr.T("Al2105") + ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Отключает/включает кнопки действий на время отправки решения службе.</summary>
    private void SetBusy(bool busy)
    {
        if (BtnWinlockRestore is not null) BtnWinlockRestore.IsEnabled = !busy;
        if (BtnWinlockKeep is not null) BtnWinlockKeep.IsEnabled = !busy;
        if (BtnWinlockClose is not null) BtnWinlockClose.IsEnabled = !busy;
        if (BtnWinlockOpenFolder is not null) BtnWinlockOpenFolder.IsEnabled = !busy;
    }
}
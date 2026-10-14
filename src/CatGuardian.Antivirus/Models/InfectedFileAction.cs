namespace CatGuardian.Antivirus.Core.Models;

/// <summary>
/// Действие при обнаружении заражённого файла.
/// </summary>
public enum InfectedFileAction
{
    /// <summary>Переместить в карантин.</summary>
    MoveToQuarantine,

    /// <summary>Только зарегистрировать в журнале, не перемещать.</summary>
    ReportOnly,
}
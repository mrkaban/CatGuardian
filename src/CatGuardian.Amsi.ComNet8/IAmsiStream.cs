using System;
using System.Runtime.InteropServices;

namespace CatGuardian.Amsi.ComNet8;

/// <summary>Атрибуты контента AMSI-потока (enum AMSI_ATTRIBUTE из amsi.h).</summary>
public enum AmsiAttribute : uint
{
    AppName = 0,
    ContentName = 1,
    ContentSize = 2,
    ContentAddress = 3,
    Content = 4,
    ContentType = 5,
    Session = 6,
    Runtime = 7,
}

/// <summary>
/// Неуправляемый интерфейс потока контента <c>IAmsiStream</c> (amsi.h), IID
/// <c>{3E47F2E5-81D4-4D3B-897F-545096770373}</c> (из официального amsi.h Windows SDK).
/// Хост передаёт его в Scan.
///
/// ВАЖНО: параметры буфера объявлены как <see cref="IntPtr"/>, а не <c>byte[]</c>:
/// .NET-маршалинг массива с SizeParamIndex при вызове ЧЕРЕЗ RCW (managed → native) даёт
/// некорректные вызовы (E_INVALIDARG на GetAttribute). Ручное выделение через
/// Marshal.AllocHGlobal + Marshal.Copy соответствует нативному контракту 1-в-1.
/// </summary>
[ComVisible(true)]
[Guid("3E47F2E5-81D4-4D3B-897F-545096770373")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IAmsiStream
{
    /// <summary>Возвращает атрибут контента (размер или сами байты).</summary>
    [PreserveSig]
    int GetAttribute(
        [In] AmsiAttribute attribute,
        [In] uint dataSize,
        [In, Out] IntPtr data,
        [Out] out uint retData);

    /// <summary>Читает блок контента из потока по позиции.</summary>
    [PreserveSig]
    int Read(
        [In] ulong position,
        [In] uint size,
        [In, Out] IntPtr buffer,
        [Out] out uint readSize);
}
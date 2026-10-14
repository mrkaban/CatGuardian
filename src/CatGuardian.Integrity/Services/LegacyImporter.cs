using System;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Services;

/// <summary>
/// Импортирует данные из базы Cat Guardian 1.x (wowlist.db):
/// таблица "ioc" (hash, desk, type) -> новая таблица "ioc".
/// </summary>
public static class LegacyImporter
{
    /// <summary>Читает IOC из legacy-базы и возвращает записи для новой схемы.</summary>
    public static IReadOnlyList<IocRecord> ReadIoc(string legacyDbPath)
    {
        var result = new List<IocRecord>();
        if (string.IsNullOrWhiteSpace(legacyDbPath) || !System.IO.File.Exists(legacyDbPath))
        {
            return result;
        }

        using var connection = new SqliteConnection($"Data Source={legacyDbPath};Mode=ReadOnly");
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT hash, desk, type FROM ioc;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var hash = reader.IsDBNull(0) ? null : reader.GetString(0);
            var desc = reader.IsDBNull(1) ? null : reader.GetString(1);
            var type = reader.IsDBNull(2) ? null : reader.GetString(2);

            if (string.IsNullOrWhiteSpace(hash))
            {
                continue;
            }

            result.Add(new IocRecord
            {
                Hash = hash.Trim().ToLowerInvariant(),
                Algo = NormalizeAlgo(type),
                Description = desc ?? "",
            });
        }

        return result;
    }

    /// <summary>Импортирует IOC из legacy-базы в новую. Возвращает число добавленных записей.</summary>
    public static int ImportIoc(GuardianService service, string legacyDbPath)
    {
        var records = ReadIoc(legacyDbPath);
        if (records.Count == 0)
        {
            return 0;
        }
        service.Ioc.BulkAdd(records);
        return records.Count;
    }

    private static string NormalizeAlgo(string? type)
    {
        if (string.IsNullOrWhiteSpace(type))
        {
            return HashAlgo.Sha256;
        }
        var t = type.Trim().ToLowerInvariant();
        return t switch
        {
            "md5" => HashAlgo.Md5,
            "sha1" => HashAlgo.Sha1,
            _ => HashAlgo.Sha256,
        };
    }
}
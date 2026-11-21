// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Text;
using System.Text.Json;
using TotalDrop.WinUI.Interop;

namespace TotalDrop.WinUI.Services;

/// <summary>
/// Persists user settings locally to <c>%LOCALAPPDATA%\TotalDrop\settings.json</c>
/// using atomic temp-file flush + replace (never cloud-synced via Windows
/// roaming storage, ADR 0016).
/// </summary>
public sealed class SettingsStore
{
    public const string DefaultRendezvousServer = "wss://rendezvous.totaldrop.app";
    public const string DefaultRelayServer = "wss://relay.totaldrop.app/v0/relay";
    public const string DefaultStunServer = "stun.cloudflare.com:3478";

    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly string _directoryPath;

    public string SettingsPath { get; }

    public BridgeNetworkConfigDto Current { get; private set; }

    public bool CanResetServer =>
        !string.Equals(Current.RendezvousServer, DefaultRendezvousServer, StringComparison.Ordinal);

    public SettingsStore(string? directoryOverride = null)
    {
        _directoryPath = string.IsNullOrWhiteSpace(directoryOverride)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "TotalDrop")
            : directoryOverride;
        SettingsPath = Path.Combine(_directoryPath, "settings.json");
        Current = Load();
    }

    public static BridgeNetworkConfigDto CreateDefaultConfig() =>
        new(
            RendezvousServer: DefaultRendezvousServer,
            RelayServer: DefaultRelayServer,
            StunServer: DefaultStunServer,
            PrivacyRelayOnly: false,
            StrongerThreeWordCode: false);

    /// <summary>
    /// Reads <see cref="SettingsPath"/> safely, falling back to
    /// <see cref="CreateDefaultConfig"/> on missing, empty, or corrupt JSON
    /// without throwing. Preserves explicit empty strings (<c>""</c>) for
    /// relay/STUN overrides while defaulting omitted (<see langword="null"/>) fields.
    /// </summary>
    public BridgeNetworkConfigDto Load()
    {
        BridgeNetworkConfigDto defaults = CreateDefaultConfig();
        if (!File.Exists(SettingsPath))
        {
            return defaults;
        }

        try
        {
            byte[] bytes = File.ReadAllBytes(SettingsPath);
            if (bytes.Length == 0)
            {
                return defaults;
            }

            AppSettingsFileDto? parsed = JsonSerializer.Deserialize(
                bytes,
                TotalDropJsonContext.Default.AppSettingsFileDto);
            if (parsed is null)
            {
                return defaults;
            }

            string rendezvous = string.IsNullOrWhiteSpace(parsed.RendezvousServer)
                ? defaults.RendezvousServer
                : parsed.RendezvousServer.Trim();
            string relay = parsed.RelayServer is null
                ? defaults.RelayServer
                : parsed.RelayServer.Trim();
            string stun = parsed.StunServer is null
                ? defaults.StunServer
                : parsed.StunServer.Trim();

            return new BridgeNetworkConfigDto(
                RendezvousServer: rendezvous,
                RelayServer: relay,
                StunServer: stun,
                PrivacyRelayOnly: parsed.PrivacyRelayOnly ?? defaults.PrivacyRelayOnly,
                StrongerThreeWordCode: parsed.StrongerThreeWordCode ?? defaults.StrongerThreeWordCode);
        }
        catch (IOException)
        {
            return defaults;
        }
        catch (UnauthorizedAccessException)
        {
            return defaults;
        }
        catch (JsonException)
        {
            return defaults;
        }
    }

    /// <summary>
    /// Atomically writes <paramref name="config"/> to <see cref="SettingsPath"/>
    /// via a sibling temp file, disk flush, and overwrite move. On failure,
    /// cleans up the temp file and leaves any existing <c>settings.json</c>
    /// untouched.
    /// </summary>
    public bool TrySaveAtomic(BridgeNetworkConfigDto config)
    {
        string tempPath = Path.Combine(_directoryPath, $"settings.{Guid.NewGuid():N}.tmp");
        try
        {
            Directory.CreateDirectory(_directoryPath);
            string json = JsonSerializer.Serialize(
                config,
                TotalDropJsonContext.Default.BridgeNetworkConfigDto);

            using (FileStream fs = new(
                       tempPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.None))
            {
                byte[] utf8 = Utf8NoBom.GetBytes(json);
                fs.Write(utf8, 0, utf8.Length);
                fs.Flush(flushToDisk: true);
            }

            File.Move(tempPath, SettingsPath, overwrite: true);
            Current = config;
            return true;
        }
        catch (IOException)
        {
            TryDeleteSilently(tempPath);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            TryDeleteSilently(tempPath);
            return false;
        }
    }

    /// <summary>
    /// Validates <paramref name="rawUrl"/> strictly via Rust
    /// <c>totaldrop_win_validate_server_url_json</c> before atomically saving.
    /// Invalid URLs are rejected with <c>"settingsServerInvalid"</c> without
    /// touching <c>settings.json</c>.
    /// </summary>
    public bool TrySaveServerUrl(string rawUrl, out string? errorL10nKey)
    {
        errorL10nKey = null;
        string trimmed = (rawUrl ?? string.Empty).Trim();
        if (!NativeBridge.TryValidateServerUrl(trimmed, out _))
        {
            errorL10nKey = "settingsServerInvalid";
            return false;
        }

        BridgeNetworkConfigDto updated = Current with { RendezvousServer = trimmed };
        if (!TrySaveAtomic(updated))
        {
            errorL10nKey = "errorStorage";
            return false;
        }

        return true;
    }

    public bool TryResetServerUrl()
    {
        BridgeNetworkConfigDto updated = Current with { RendezvousServer = DefaultRendezvousServer };
        return TrySaveAtomic(updated);
    }

    public bool TrySetPrivacyMode(bool enabled)
    {
        BridgeNetworkConfigDto updated = Current with { PrivacyRelayOnly = enabled };
        return TrySaveAtomic(updated);
    }

    public bool TrySetStrongerThreeWordCode(bool enabled)
    {
        BridgeNetworkConfigDto updated = Current with { StrongerThreeWordCode = enabled };
        return TrySaveAtomic(updated);
    }

    private static void TryDeleteSilently(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Ignore cleanup errors on failing storage.
        }
        catch (UnauthorizedAccessException)
        {
            // Ignore cleanup errors on failing storage.
        }
    }
}

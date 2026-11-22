// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Text.Json;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

public sealed class SettingsStoreTests
{
    private sealed class TempSettingsDir : IDisposable
    {
        public string Path { get; }

        public TempSettingsDir(string tag)
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"totaldrop-winui-tests-{tag}-{Environment.ProcessId}-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch (IOException)
            {
                // Ignore transient cleanup lock errors.
            }
        }
    }

    [Fact]
    public void T1_F12_01_SaveCustomLoopbackAndPrivacyMode_AtomicRoundTrip()
    {
        using TempSettingsDir tmp = new("t1-f12-01");
        SettingsStore store = new(tmp.Path);

        bool savedUrl = store.TrySaveServerUrl("ws://127.0.0.1:4400", out string? errKey);
        Assert.True(savedUrl, $"TrySaveServerUrl failed with {errKey}");
        Assert.Null(errKey);
        Assert.True(store.TrySetPrivacyMode(true));

        Assert.True(File.Exists(store.SettingsPath));
        string[] tempFiles = Directory.GetFiles(tmp.Path, "*.tmp");
        Assert.Empty(tempFiles);

        string rawJson = File.ReadAllText(store.SettingsPath);
        using JsonDocument doc = JsonDocument.Parse(rawJson);
        Assert.Equal("ws://127.0.0.1:4400", doc.RootElement.GetProperty("rendezvous_server").GetString());
        Assert.True(doc.RootElement.GetProperty("privacy_relay_only").GetBoolean());

        SettingsStore reloaded = new(tmp.Path);
        Assert.Equal("ws://127.0.0.1:4400", reloaded.Current.RendezvousServer);
        Assert.True(reloaded.Current.PrivacyRelayOnly);
    }

    [Fact]
    public void T1_F12_02_ResetServerUrl_RestoresDefaultAndDisablesCanReset()
    {
        using TempSettingsDir tmp = new("t1-f12-02");
        SettingsStore store = new(tmp.Path);

        Assert.True(store.TrySaveServerUrl("ws://127.0.0.1:4400", out string? errKey));
        Assert.Null(errKey);
        Assert.True(store.CanResetServer);

        Assert.True(store.TryResetServerUrl());
        // Offline string/metadata check only — zero network connection.
        Assert.Equal(SettingsStore.DefaultRendezvousServer, store.Current.RendezvousServer);
        Assert.Equal("wss://rendezvous.totaldrop.app", store.Current.RendezvousServer);
        Assert.False(store.CanResetServer);

        SettingsStore reloaded = new(tmp.Path);
        Assert.Equal("wss://rendezvous.totaldrop.app", reloaded.Current.RendezvousServer);
        Assert.False(reloaded.CanResetServer);
    }

    [Fact]
    public void T2_F12_01_MissingEmptyAndCorruptSettings_FallbackToDefaults()
    {
        // (a) Nonexistent settings.json
        using (TempSettingsDir tmpMissing = new("t2-f12-01-missing"))
        {
            SettingsStore s = new(tmpMissing.Path);
            Assert.Equal("wss://rendezvous.totaldrop.app", s.Current.RendezvousServer);
            Assert.False(s.Current.PrivacyRelayOnly);
        }

        // (b) 0-byte empty file
        using (TempSettingsDir tmpEmpty = new("t2-f12-01-empty"))
        {
            File.WriteAllBytes(Path.Combine(tmpEmpty.Path, "settings.json"), []);
            SettingsStore s = new(tmpEmpty.Path);
            Assert.Equal("wss://rendezvous.totaldrop.app", s.Current.RendezvousServer);
            Assert.False(s.Current.PrivacyRelayOnly);
        }

        // (c) Truncated corrupt JSON
        using (TempSettingsDir tmpCorrupt = new("t2-f12-01-corrupt"))
        {
            File.WriteAllText(Path.Combine(tmpCorrupt.Path, "settings.json"), "{\"rendezvous_server\":");
            SettingsStore s = new(tmpCorrupt.Path);
            Assert.Equal("wss://rendezvous.totaldrop.app", s.Current.RendezvousServer);
            Assert.False(s.Current.PrivacyRelayOnly);
        }
    }

    [Fact]
    public void T2_F12_02_InvalidServerUrls_RejectedAndPreserveFileBytes()
    {
        using TempSettingsDir tmp = new("t2-f12-02");
        SettingsStore store = new(tmp.Path);

        Assert.True(store.TrySaveServerUrl("ws://127.0.0.1:4400", out _));
        byte[] beforeBytes = File.ReadAllBytes(store.SettingsPath);

        string[] invalidUrls =
        [
            "wss://",
            "wss://user@host",
            "ws://192.168.1.5:4000",
            "ftp://example.test",
        ];

        foreach (string badUrl in invalidUrls)
        {
            bool ok = store.TrySaveServerUrl(badUrl, out string? errorL10nKey);
            Assert.False(ok, $"Invalid URL '{badUrl}' must be rejected");
            Assert.Equal("settingsServerInvalid", errorL10nKey);

            bool formattedOk = NativeBridge.TryFormatMessage(
                "settingsServerInvalid",
                [],
                "en-US",
                "en-US",
                out string localized,
                out BridgeErrorDto? fmtErr);
            Assert.True(formattedOk, $"TryFormatMessage failed: {fmtErr?.Message}");
            Assert.False(string.IsNullOrWhiteSpace(localized));
        }

        byte[] afterBytes = File.ReadAllBytes(store.SettingsPath);
        Assert.Equal(beforeBytes, afterBytes);
    }
}

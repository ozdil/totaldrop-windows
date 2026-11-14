// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.ViewModels;
using Windows.ApplicationModel.DataTransfer;

namespace TotalDrop.WinUI.Views;

/// <summary>
/// Fluent 2 Receive screen code-behind delegating code parsing, rendezvous
/// pairing, and verified chunk reception to <c>totaldrop_windows_bridge.dll</c>.
/// </summary>
public sealed partial class ReceivePage : Page
{
    public ReceiveViewModel ViewModel { get; private set; } = new();

    public ReceivePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is ReceiveViewModel vm)
        {
            ViewModel = vm;
            Bindings.Update();
        }
    }

    private async void OnPasteClick(object sender, RoutedEventArgs e)
    {
        DataPackageView content = Clipboard.GetContent();
        if (content.Contains(StandardDataFormats.Text))
        {
            string pasted = await content.GetTextAsync();
            ViewModel.CodeInput = pasted.Trim();
            ViewModel.ValidationMessage = string.Empty;
        }
    }

    private void OnConnectClick(object sender, RoutedEventArgs e)
    {
        string typed = ViewModel.CodeInput;
        if (string.IsNullOrWhiteSpace(typed))
        {
            ViewModel.ValidationMessage = "That does not look like a code. It starts with a number, then two or three words.";
            return;
        }

        try
        {
            nint ptr = NativeBridge.ValidateUserInputJson(typed);
            if (ptr != 0)
            {
                try
                {
                    string? json = Marshal.PtrToStringUTF8(ptr);
                    if (!string.IsNullOrEmpty(json))
                    {
                        ValidatedCodeDto? validated = JsonSerializer.Deserialize(
                            json,
                            TotalDropJsonContext.Default.ValidatedCodeDto);
                        if (validated is not null)
                        {
                            ViewModel.CodeInput = validated.DisplayEnglish;
                            ViewModel.ValidationMessage = string.Empty;
                            return;
                        }
                    }
                }
                finally
                {
                    NativeBridge.FreeBridgeString(ptr);
                }
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time XAML preview fallback.
        }

        ViewModel.ValidationMessage = "That does not look like a code. It starts with a number, then two or three words.";
    }

    private void OnAcceptClick(object sender, RoutedEventArgs e)
    {
        ViewModel.IsReceiving = true;
    }

    private void OnDeclineClick(object sender, RoutedEventArgs e)
    {
        ViewModel.HasIncomingOffer = false;
    }
}

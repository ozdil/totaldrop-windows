// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using Microsoft.UI.Xaml;
using TotalDrop.WinUI.Interop;
using WinRT;

namespace TotalDrop.WinUI.ViewModels;

/// <summary>
/// Represents a single selected or offered file/folder item with bidi-isolated
/// display text (`U+2068…U+2069`) and extended-length <c>\\?\</c> backing path.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class TransferItemModel(string safeDisplayName, string extendedPath, string formattedSize)
{
    public string SafeDisplayName { get; } = safeDisplayName;

    public string ExtendedPath { get; } = extendedPath;

    public string FormattedSize { get; } = formattedSize;
}

/// <summary>
/// Trim-safe <see cref="INotifyPropertyChanged"/> base for <c>x:Bind</c> under
/// .NET 9 Native AOT + CsWinRT 2.2 (zero runtime reflection).
/// </summary>
public abstract class ObservableViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    protected void NotifyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

/// <summary>
/// ViewModel for <c>Views/SendPage.xaml</c> bound purely via <c>x:Bind</c>.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class SendViewModel : ObservableViewModel
{
    private bool _useStrongerThreeWordCode;
    private bool _isTransferRunning;
    private string _transferCode = string.Empty;
    private string _verificationWords = string.Empty;
    private int _wholePercent;
    private string _regionalPercentText = "0%";
    private string _statusCaption = "Add the files you want to send. The receiver gets exactly these, nothing else.";
    private string _selectionSummary = "Nothing selected yet";

    public ObservableCollection<TransferItemModel> SelectedItems { get; } = [];

    public bool UseStrongerThreeWordCode
    {
        get => _useStrongerThreeWordCode;
        set => SetField(ref _useStrongerThreeWordCode, value);
    }

    public bool IsTransferRunning
    {
        get => _isTransferRunning;
        set
        {
            if (SetField(ref _isTransferRunning, value))
            {
                NotifyChanged(nameof(ProgressVisibility));
            }
        }
    }

    /// <summary>
    /// English transfer code (e.g. <c>7-harbor-rocket</c>), always rendered
    /// <c>FlowDirection.LeftToRight</c> and spoken with an English voice by
    /// Windows Narrator (ADR 0008, ADR 0016).
    /// </summary>
    public string TransferCode
    {
        get => _transferCode;
        set
        {
            if (SetField(ref _transferCode, value))
            {
                NotifyChanged(nameof(CodeCardVisibility));
            }
        }
    }

    /// <summary>
    /// Four verification words derived from CPace + Noise XXpsk3 + ML-KEM-768,
    /// always rendered <c>FlowDirection.LeftToRight</c>.
    /// </summary>
    public string VerificationWords
    {
        get => _verificationWords;
        set
        {
            if (SetField(ref _verificationWords, value))
            {
                NotifyChanged(nameof(VerificationVisibility));
            }
        }
    }

    /// <summary>
    /// Rounded-down integer percentage (<c>0..100</c>) bound to both
    /// <c>ProgressBar.Value</c> (Windows Narrator RangeValuePattern) and
    /// <see cref="RegionalPercentText"/> (#483).
    /// </summary>
    public int WholePercent
    {
        get => _wholePercent;
        private set => SetField(ref _wholePercent, value);
    }

    public string RegionalPercentText
    {
        get => _regionalPercentText;
        private set => SetField(ref _regionalPercentText, value);
    }

    public string StatusCaption
    {
        get => _statusCaption;
        set => SetField(ref _statusCaption, value);
    }

    public string SelectionSummary
    {
        get => _selectionSummary;
        private set => SetField(ref _selectionSummary, value);
    }

    public Visibility CodeCardVisibility =>
        string.IsNullOrEmpty(_transferCode) ? Visibility.Collapsed : Visibility.Visible;

    public Visibility VerificationVisibility =>
        string.IsNullOrEmpty(_verificationWords) ? Visibility.Collapsed : Visibility.Visible;

    public Visibility ProgressVisibility =>
        _isTransferRunning ? Visibility.Visible : Visibility.Collapsed;

    public void AddValidatedPaths(IEnumerable<string> extendedPaths)
    {
        foreach (string path in extendedPaths)
        {
            string unprefixed = path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)
                ? @"\\" + path.AsSpan(8).ToString()
                : path.StartsWith(@"\\?\", StringComparison.Ordinal)
                    ? path.AsSpan(4).ToString()
                    : path;
            string leaf = Path.GetFileName(unprefixed.TrimEnd('\\'));
            string bidiSafeLeaf = $"\u2068{(string.IsNullOrEmpty(leaf) ? unprefixed : leaf)}\u2069";
            SelectedItems.Add(new TransferItemModel(bidiSafeLeaf, path, string.Empty));
        }

        SelectionSummary = SelectedItems.Count == 0
            ? "Nothing selected yet"
            : string.Create(CultureInfo.CurrentCulture, $"{SelectedItems.Count:N0} items selected");
    }

    public void UpdateProgress(ulong doneBytes, ulong totalBytes, CultureInfo regionalCulture)
    {
        int floorPct = NativeBridge.ComputeWholePercentFloor(doneBytes, totalBytes);
        WholePercent = floorPct;
        RegionalPercentText = (floorPct / 100.0).ToString("P0", regionalCulture.NumberFormat);
    }
}

/// <summary>
/// ViewModel for <c>Views/ReceivePage.xaml</c> bound purely via <c>x:Bind</c>.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class ReceiveViewModel : ObservableViewModel
{
    private string _codeInput = string.Empty;
    private string _validationMessage = string.Empty;
    private string _verificationWords = string.Empty;
    private string _offerSummary = string.Empty;
    private string _destinationFolder = string.Empty;
    private bool _hasIncomingOffer;
    private bool _isReceiving;
    private int _wholePercent;
    private string _regionalPercentText = "0%";

    public ReceiveViewModel()
    {
        _destinationFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");
    }

    public string CodeInput
    {
        get => _codeInput;
        set => SetField(ref _codeInput, value);
    }

    public string ValidationMessage
    {
        get => _validationMessage;
        set
        {
            if (SetField(ref _validationMessage, value))
            {
                NotifyChanged(nameof(ValidationVisibility));
            }
        }
    }

    public string VerificationWords
    {
        get => _verificationWords;
        set
        {
            if (SetField(ref _verificationWords, value))
            {
                NotifyChanged(nameof(VerificationVisibility));
            }
        }
    }

    public string OfferSummary
    {
        get => _offerSummary;
        set => SetField(ref _offerSummary, value);
    }

    public string DestinationFolder
    {
        get => _destinationFolder;
        set => SetField(ref _destinationFolder, value);
    }

    public bool HasIncomingOffer
    {
        get => _hasIncomingOffer;
        set
        {
            if (SetField(ref _hasIncomingOffer, value))
            {
                NotifyChanged(nameof(OfferCardVisibility));
            }
        }
    }

    public bool IsReceiving
    {
        get => _isReceiving;
        set
        {
            if (SetField(ref _isReceiving, value))
            {
                NotifyChanged(nameof(ProgressVisibility));
            }
        }
    }

    public int WholePercent
    {
        get => _wholePercent;
        private set => SetField(ref _wholePercent, value);
    }

    public string RegionalPercentText
    {
        get => _regionalPercentText;
        private set => SetField(ref _regionalPercentText, value);
    }

    public Visibility ValidationVisibility =>
        string.IsNullOrEmpty(_validationMessage) ? Visibility.Collapsed : Visibility.Visible;

    public Visibility VerificationVisibility =>
        string.IsNullOrEmpty(_verificationWords) ? Visibility.Collapsed : Visibility.Visible;

    public Visibility OfferCardVisibility =>
        _hasIncomingOffer ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ProgressVisibility =>
        _isReceiving ? Visibility.Visible : Visibility.Collapsed;

    public void ApplyActivatedCode(string validatedEnglishCode)
    {
        CodeInput = validatedEnglishCode;
        ValidationMessage = string.Empty;
    }

    public void UpdateProgress(ulong doneBytes, ulong totalBytes, CultureInfo regionalCulture)
    {
        int floorPct = NativeBridge.ComputeWholePercentFloor(doneBytes, totalBytes);
        WholePercent = floorPct;
        RegionalPercentText = (floorPct / 100.0).ToString("P0", regionalCulture.NumberFormat);
    }
}

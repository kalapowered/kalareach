# Canonical KR-CBOR-1, as the bridge endpoint carries it.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# The worker decodes strictly and re-encodes what it decoded, byte for byte, so anything written
# here has to be canonical: definite lengths, the shortest integer form, and map keys in canonical
# order. Nothing else on this endpoint is negotiable either, which is why the encoder sorts the
# keys itself rather than trusting a caller to write them in order.

Set-StrictMode -Version 3.0

function New-KrCborWriter {
    [System.Collections.Generic.List[byte]]::new(256)
}

function Write-KrCborHead {
    param([System.Collections.Generic.List[byte]]$Writer, [int]$Major, [uint64]$Value)
    $tag = [byte]($Major -shl 5)
    if ($Value -lt 24) {
        $Writer.Add([byte]($tag -bor [byte]$Value))
    } elseif ($Value -le 0xFF) {
        $Writer.Add([byte]($tag -bor 24)); $Writer.Add([byte]$Value)
    } elseif ($Value -le 0xFFFF) {
        $Writer.Add([byte]($tag -bor 25))
        $Writer.Add([byte](($Value -shr 8) -band 0xFF)); $Writer.Add([byte]($Value -band 0xFF))
    } elseif ($Value -le 0xFFFFFFFF) {
        $Writer.Add([byte]($tag -bor 26))
        for ($shift = 24; $shift -ge 0; $shift -= 8) {
            $Writer.Add([byte](($Value -shr $shift) -band 0xFF))
        }
    } else {
        $Writer.Add([byte]($tag -bor 27))
        for ($shift = 56; $shift -ge 0; $shift -= 8) {
            $Writer.Add([byte](($Value -shr $shift) -band 0xFF))
        }
    }
}

# One value, from the shapes this bridge uses: an unsigned integer, a boolean, null, a string, a
# byte string ([byte[]]), an ordered list ([object[]] or a List) or a map ([hashtable]).
function Write-KrCborValue {
    param([System.Collections.Generic.List[byte]]$Writer, $Value)

    if ($null -eq $Value) { $Writer.Add(0xF6); return }
    if ($Value -is [bool]) { $Writer.Add($(if ($Value) { 0xF5 } else { 0xF4 })); return }
    if ($Value -is [byte[]]) {
        Write-KrCborHead $Writer 2 ([uint64]$Value.Length)
        if ($Value.Length -gt 0) { $Writer.AddRange($Value) }
        return
    }
    if ($Value -is [string]) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        Write-KrCborHead $Writer 3 ([uint64]$bytes.Length)
        if ($bytes.Length -gt 0) { $Writer.AddRange($bytes) }
        return
    }
    if ($Value -is [hashtable]) {
        # Canonical order: the shorter key first, then bytewise.
        $keys = @($Value.Keys) | Sort-Object -Property @{ Expression = { $_.Length } }, @{ Expression = { $_ } }
        Write-KrCborHead $Writer 5 ([uint64]$keys.Count)
        foreach ($key in $keys) {
            Write-KrCborValue $Writer ([string]$key)
            Write-KrCborValue $Writer $Value[$key]
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value)
        Write-KrCborHead $Writer 4 ([uint64]$items.Count)
        foreach ($item in $items) { Write-KrCborValue $Writer $item }
        return
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64] -or
        $Value -is [int64] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [uint16]) {
        $number = [uint64]$Value
        Write-KrCborHead $Writer 0 $number
        return
    }
    throw "kalareach: $($Value.GetType().FullName) has no place on this endpoint"
}

function ConvertTo-KrCbor {
    param($Value)
    $writer = New-KrCborWriter
    Write-KrCborValue $writer $Value
    , $writer.ToArray()
}

# A variant of an externally tagged enum: a name alone, or a single-entry map.
function New-KrVariant {
    param([string]$Name, $Payload)
    if ($PSBoundParameters.ContainsKey('Payload')) { return @{ $Name = $Payload } }
    $Name
}

function Read-KrCborValue {
    param([byte[]]$Bytes, [ref]$At)

    $i = $At.Value
    if ($i -ge $Bytes.Length) { throw 'kalareach: a frame ended mid-value' }
    $initial = $Bytes[$i]; $i++
    $major = $initial -shr 5
    $minor = $initial -band 0x1F
    $value = [uint64]0
    switch ($minor) {
        24 { $value = [uint64]$Bytes[$i]; $i += 1 }
        25 { $value = ([uint64]$Bytes[$i] -shl 8) -bor [uint64]$Bytes[$i + 1]; $i += 2 }
        26 {
            $value = 0
            for ($k = 0; $k -lt 4; $k++) { $value = ($value -shl 8) -bor [uint64]$Bytes[$i + $k] }
            $i += 4
        }
        27 {
            $value = 0
            for ($k = 0; $k -lt 8; $k++) { $value = ($value -shl 8) -bor [uint64]$Bytes[$i + $k] }
            $i += 8
        }
        default {
            if ($minor -ge 28) { throw 'kalareach: a frame used a reserved length' }
            $value = [uint64]$minor
        }
    }

    switch ($major) {
        0 { $At.Value = $i; return $value }
        2 {
            $length = [int]$value
            $bytes = [byte[]]::new($length)
            if ($length -gt 0) { [Array]::Copy($Bytes, $i, $bytes, 0, $length) }
            $At.Value = $i + $length
            return , $bytes
        }
        3 {
            $length = [int]$value
            $text = [System.Text.Encoding]::UTF8.GetString($Bytes, $i, $length)
            $At.Value = $i + $length
            return $text
        }
        4 {
            $items = [System.Collections.Generic.List[object]]::new()
            $cursor = $i
            for ($k = 0; $k -lt [int]$value; $k++) {
                $inner = [ref]$cursor
                $items.Add((Read-KrCborValue $Bytes $inner))
                $cursor = $inner.Value
            }
            $At.Value = $cursor
            return , $items.ToArray()
        }
        5 {
            $map = @{}
            $cursor = $i
            for ($k = 0; $k -lt [int]$value; $k++) {
                $inner = [ref]$cursor
                $key = Read-KrCborValue $Bytes $inner
                $cursor = $inner.Value
                $inner = [ref]$cursor
                $map[[string]$key] = Read-KrCborValue $Bytes $inner
                $cursor = $inner.Value
            }
            $At.Value = $cursor
            return $map
        }
        7 {
            $At.Value = $i
            switch ($minor) {
                20 { return $false }
                21 { return $true }
                22 { return $null }
                default { throw 'kalareach: a frame used a value this endpoint does not carry' }
            }
        }
        default { throw "kalareach: a frame used major type $major" }
    }
}

function ConvertFrom-KrCbor {
    param([byte[]]$Bytes)
    $at = [ref]0
    $value = Read-KrCborValue $Bytes $at
    if ($at.Value -ne $Bytes.Length) { throw 'kalareach: a frame carried trailing bytes' }
    $value
}

# The name and payload of an externally tagged variant, or $null when it is not one.
function Get-KrVariant {
    param($Value)
    if ($Value -is [string]) { return @{ Name = $Value; Payload = $null } }
    if ($Value -is [hashtable] -and $Value.Count -eq 1) {
        $name = @($Value.Keys)[0]
        return @{ Name = [string]$name; Payload = $Value[$name] }
    }
    $null
}

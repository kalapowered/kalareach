# The KalaReach root-editor bridge for PowerShell.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
@{
    RootModule           = 'KalaReach.ShellBridge.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '3f2a9d54-6c1b-4a77-9e3d-0b4c18f5d210'
    Author               = 'Kala Powered'
    CompanyName          = 'Kala Powered'
    Copyright            = '(c) Kala Powered'
    Description          = 'Binds the KalaReach root-editor bridge into the installed PSReadLine: the reader thread answers the fence, a launch and a cancellation, and the configured gesture detaches at an empty root prompt.'
    PowerShellVersion    = '7.4'
    RequiredModules      = @(@{ ModuleName = 'PSReadLine'; ModuleVersion = '2.3.4' })
    FunctionsToExport    = @(
        'Initialize-KalaReachBridge'
        'Enable-KalaReachHooks'
        'Invoke-KalaReachReadLine'
        'Invoke-KalaReachService'
        'Invoke-KalaReachPending'
        'Invoke-KalaReachGesture'
        'Test-KalaReachBridge'
        'Write-KalaReachLoss'
        'Publish-KalaReachQualification'
        'Remove-KalaReachHooks'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('KalaReach', 'PSReadLine', 'shell-integration')
            ProjectUri = 'https://kala.to'
        }
    }
}

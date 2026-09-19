# >>> kalareach shell integration >>>
# Added by KalaReach to the shell's own profile. Nothing outside these two marker lines belongs to
# it, and removing the integration removes exactly this block. No profile is replaced, no module
# path is redirected away from the person's own modules and nothing they wrote is disabled.
#
# The qualified PSReadLine is already selected before this profile runs, so the options and the
# Set-PSReadLineKeyHandler calls below belong to the editor this module binds into. The module
# loads here, before the first prompt, and its user-facing hooks go on after the whole profile has
# run, on top of whatever the person configured rather than in place of it.
#
# In any shell without the bootstrap values, and in every child of a managed root shell, the first
# condition fails and this block does nothing at all.
if ($env:KR_SHELL_BRIDGE -and $env:KR_SHELL_BRIDGE_SECRET) {
    Import-Module KalaReach.ShellBridge -Global -ErrorAction SilentlyContinue
}
# <<< kalareach shell integration <<<

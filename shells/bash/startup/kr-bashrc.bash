# >>> kalareach shell integration >>>
# Added by KalaReach to the shell's own startup file. Nothing outside these two marker lines
# belongs to it, and removing the integration removes exactly this block. The file it goes in is
# .bashrc for an interactive shell, or the first login file the shell actually reads when that file
# does not source .bashrc; nothing here replaces either of them, and no profile is disabled.
#
# The native bridge has already loaded, before this file ran and before the first prompt. What is
# left for this entry is the half that has to run after the user's configuration: it says, once,
# that the user-facing hooks are live, which is what lets the session report itself ready. The
# block belongs at the end of the file for that reason.
#
# In any shell without the packaged builtin, and in every child of a managed root shell, the first
# condition fails and this block does nothing at all.
if builtin kr-bridge status 2>/dev/null; then
    builtin kr-bridge activated
fi
# <<< kalareach shell integration <<<

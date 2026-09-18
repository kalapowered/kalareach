# >>> kalareach shell integration >>>
# Added by KalaReach to the shell's own .zshrc. Nothing outside these two marker lines belongs to
# it, and removing the integration removes exactly this block.
#
# The native bridge has already loaded with the line editor, before the first prompt. What is left
# for this entry is the half that has to run after the user's configuration: it says, once, that
# the user-facing hooks are live, which is what lets the session report itself ready.
#
# In any shell without the packaged builtin, and in every child of a managed root shell, the first
# condition fails and this block does nothing at all.
if builtin kr-bridge status 2>/dev/null; then
    __kalareach_activate() {
        # One shot: the hooks are live from this prompt onwards, and this function takes itself out
        # of the list rather than replacing it.
        precmd_functions=("${(@)precmd_functions:#__kalareach_activate}")
        builtin unfunction __kalareach_activate 2>/dev/null
        builtin kr-bridge activated
    }
    typeset -ga precmd_functions
    precmd_functions+=(__kalareach_activate)
fi
# <<< kalareach shell integration <<<

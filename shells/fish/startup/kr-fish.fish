# >>> kalareach shell integration >>>
# Added by KalaReach as its own file under the shell's conf.d directory. Nothing outside these two
# marker lines belongs to it, and removing the integration removes exactly this file. No profile is
# replaced, no configuration directory is redirected and nothing the person wrote is disabled.
#
# The native bridge has already loaded, before this file ran and before the first prompt. What is
# left for this entry is the half that has to run after the user's configuration: it says, once,
# that the user-facing hooks are live, which is what lets the session report itself ready. Files in
# conf.d run before config.fish, so the work waits for the first prompt, by which time the person's
# own configuration and key bindings are in place and the integration goes on top of them.
#
# In any shell without the packaged builtin, and in every child of a managed root shell, the first
# condition fails and this file does nothing at all.
if builtin kr-bridge status 2>/dev/null
    function __kalareach_activate --on-event fish_prompt
        # One shot: the hooks are live from this prompt onwards, and the handler takes itself out
        # of the list rather than staying to run again.
        functions --erase __kalareach_activate
        builtin kr-bridge activated
    end
end
# <<< kalareach shell integration <<<

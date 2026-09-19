# A plugin installed the way this shell's own documentation says to install one: its own file
# under conf.d, beside the integration's guarded entry rather than inside it.
set -gx STARSHIP_CONFIG $HOME/.config/starship.toml
set -gx STARSHIP_CACHE $HOME/.cache/starship
"$KR_STACK_STARSHIP/starship" init fish | source
echo stack >> $KR_TEST_ORDER

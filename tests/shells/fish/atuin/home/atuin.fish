# The code this prints calls `atuin` by name for every history operation and for its search,
# so the pinned build has to be the one the path finds.
set -gx ATUIN_CONFIG_DIR $HOME/.config/atuin
fish_add_path -g "$KR_STACK_ATUIN"
"$KR_STACK_ATUIN/atuin" init fish --disable-up-arrow | source
echo stack >> $KR_TEST_ORDER

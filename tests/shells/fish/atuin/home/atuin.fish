set -gx ATUIN_CONFIG_DIR $HOME/.config/atuin
"$KR_STACK_ATUIN/atuin" init fish --disable-up-arrow | source
echo stack >> $KR_TEST_ORDER

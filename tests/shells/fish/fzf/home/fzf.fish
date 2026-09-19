fish_add_path -g "$KR_STACK_FZF"
source "$KR_STACK_FZF_SHELL/shell/key-bindings.fish"
fzf_key_bindings
echo stack >> $KR_TEST_ORDER

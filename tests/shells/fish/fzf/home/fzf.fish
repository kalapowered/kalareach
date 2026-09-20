fish_add_path -g "$KR_STACK_FZF"
# One candidate, so what the widget puts in the line is the one it was given.
set -gx FZF_CTRL_T_COMMAND 'printf "kr-fzf-choice\n"'
set -gx FZF_DEFAULT_OPTS "--no-mouse --height=10"
source "$KR_STACK_FZF_SHELL/shell/key-bindings.fish"
fzf_key_bindings
echo stack >> $KR_TEST_ORDER

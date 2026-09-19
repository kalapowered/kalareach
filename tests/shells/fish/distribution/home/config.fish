echo user-top >> $KR_TEST_ORDER

function fish_prompt; printf '%s' 'KR> '; end
set -g fish_greeting
set -g KR_TEST_USER_CONFIGURATION 1
set -g fish_key_bindings fish_default_key_bindings

abbr -a -- gs 'git status'
abbr -a -- ll 'ls -l'

function fish_user_key_bindings
    bind \eq 'commandline -r kr-user-binding-ran'
    bind \e\[H beginning-of-line
    bind \e\[F end-of-line
    bind \e\[3~ delete-char
end

echo user-bottom >> $KR_TEST_ORDER

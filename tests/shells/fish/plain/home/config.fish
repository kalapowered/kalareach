echo user-top >> $KR_TEST_ORDER

function fish_prompt; printf '%s' 'KR> '; end
set -g fish_greeting
set -g KR_TEST_USER_CONFIGURATION 1

function fish_user_key_bindings
    bind \eq 'commandline -r kr-user-binding-ran'
end

echo user-bottom >> $KR_TEST_ORDER

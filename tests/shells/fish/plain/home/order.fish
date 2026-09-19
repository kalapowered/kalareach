# Files under conf.d run before config.fish. This one records that it did, which is what the
# integration's own guarded entry relies on: it waits for the first prompt, by which time the
# person's configuration and key bindings are in place.
echo conf-d >> $KR_TEST_ORDER

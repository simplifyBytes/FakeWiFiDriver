savedcmd_fake_wifi.mod := printf '%s\n'   fake_wifi.o | awk '!x[$$0]++ { print("./"$$0) }' > fake_wifi.mod

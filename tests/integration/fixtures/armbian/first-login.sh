#!/bin/sh
set -eu

if [ -e /var/lib/armbian-first-login-complete ]; then
    exec /bin/sh -c "${SSH_ORIGINAL_COMMAND:-:}"
fi

printf 'Welcome to Armbian!\n\nCreate root password: '
read -r root_password
printf 'Repeat root password: '
read -r repeated_root_password
[ "$root_password" = "$repeated_root_password" ] || exit 1
printf 'root:%s\n' "$root_password" | chpasswd

printf '\nCreating a new user account. Press <Ctrl-C> to abort\n\n'
printf 'Please provide a username (eg. your first name): '
read -r username
printf 'Create user (%s) password: ' "$username"
read -r user_password
printf 'Repeat user (%s) password: ' "$username"
read -r repeated_user_password
[ "$user_password" = "$repeated_user_password" ] || exit 1
useradd --create-home --shell /bin/sh "$username"
printf '%s:%s\n' "$username" "$user_password" | chpasswd
usermod --append --groups sudo "$username"

printf 'Please provide your real name: '
read -r real_name
[ -z "$real_name" ] || exit 1
touch /var/lib/armbian-first-login-complete
printf '\n__ANSIBLE_SSH_BOOTSTRAP_OK__\n'

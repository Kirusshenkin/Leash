#!/bin/sh
# Установка моста Leash для текущего пользователя (macOS, Linux): копирует
# собранный leash-host в постоянное место (манифест Firefox хранит путь к
# нему) и регистрирует его. Вызывается из make install после make host.
# Каталог можно сменить: LEASH_BIN_DIR=/другой/каталог make install.
set -eu

src=target/release/leash-host
dest_dir=${LEASH_BIN_DIR:-$HOME/.local/bin}

[ -x "$src" ] || { echo "нет $src: сначала make host" >&2; exit 1; }
mkdir -p "$dest_dir"
install -m 0755 "$src" "$dest_dir/leash-host"
"$dest_dir/leash-host" install

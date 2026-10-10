#!/bin/sh
# Установка готового моста Leash (macOS arm64/x86_64, Linux x86_64) без сборки:
# скачивает leash-host из GitHub Releases, сверяет SHA-256 с SHA256SUMS
# релиза, кладёт в ~/.local/bin и регистрирует в Firefox.
#
#   curl -fsSL https://raw.githubusercontent.com/Kirusshenkin/leash-firefox-extension/master/scripts/get.sh | sh
#
# LEASH_VERSION=v0.2.0 — конкретный релиз (по умолчанию последний),
# LEASH_BIN_DIR=… — другой каталог.
#
# Файл, скачанный curl, не получает атрибута карантина, поэтому Gatekeeper
# macOS его не останавливает; бинарник, скачанный руками через браузер, будет
# заблокирован — для этого случая есть только сборка из исходников.
set -eu

repo=Kirusshenkin/leash-firefox-extension
version=${LEASH_VERSION:-latest}
dest_dir=${LEASH_BIN_DIR:-$HOME/.local/bin}

case "$(uname -s)/$(uname -m)" in
Darwin/arm64) target=aarch64-apple-darwin ;;
Darwin/x86_64) target=x86_64-apple-darwin ;;
Linux/x86_64) target=x86_64-unknown-linux-musl ;;
*)
	echo "готовой сборки для $(uname -s)/$(uname -m) нет: соберите из исходников (make install)" >&2
	exit 1
	;;
esac

if [ "$version" = latest ]; then
	base=https://github.com/$repo/releases/latest/download
else
	base=https://github.com/$repo/releases/download/$version
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	echo "нужен sha256sum или shasum" >&2
	exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

file=leash-host-$target
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$file" "$base/$file"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

want=$(awk -v f="$file" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
got=$(sha "$tmp/$file")
if [ -z "$want" ] || [ "$want" != "$got" ]; then
	echo "SHA-256 не совпал ($file): ожидался '$want', получен '$got'" >&2
	exit 1
fi

mkdir -p "$dest_dir"
install -m 0755 "$tmp/$file" "$dest_dir/leash-host"
"$dest_dir/leash-host" install

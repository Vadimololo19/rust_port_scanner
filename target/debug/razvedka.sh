#!/bin/bash

if [ $# -ne 1 ] || [ ! -f "$1" ]; then
  echo "Использование: $0 yandex.txt"
  exit 1
fi

FILE=$1

# Извлечь уникальные IPv4, отсортировать
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$FILE" | sort -u >/tmp/ips_unique.txt

echo "Найдено уникальных IP: $(wc -l </tmp/ips_unique.txt)"
echo "Результаты rDNS:"
echo "IP -> hostname"

while IFS= read -r ip; do
  hostname=$(dig +short -x "$ip" | head -n1 | sed 's/\.$//')
  if [ -n "$hostname" ]; then
    echo "$ip -> $hostname"
  else
    echo "$ip -> no rDNS"
  fi
done </tmp/ips_unique.txt

rm /tmp/ips_unique.txt

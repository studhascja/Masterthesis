#!/bin/bash

for f in files/*; do
  echo "Bereinige $f ..."
  sed -e 's/#.*//' -e 's/^[ \t]*//' -e 's/[ \t]*$//' "$f" | grep -v '^$' > "$f.tmp"
  mv "$f.tmp" "$f"
done

echo "Alle Dateien bereinigt."

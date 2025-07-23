for f in files/*; do
sed -i 's#wlp1s0#wlan1#' "$f"

done

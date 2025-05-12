# Cleanup
echo "End script"

# Stop dnsmasq
sudo systemctl stop dnsmasq
echo "Stopped Dnsmasq"

# Start systemd-resolved
sudo systemctl start systemd-resolved
echo "Started systemd-resolved"

exit 0

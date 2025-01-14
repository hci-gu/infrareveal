FROM balenalib/rpi-raspbian:bullseye

RUN apt-get update --fix-missing && apt-get install -y hostapd dbus net-tools iptables dnsmasq net-tools macchanger libc6 iproute2

ADD hostapd.conf /etc/hostapd/hostapd.conf
ADD hostapd /etc/default/hostapd
ADD dnsmasq.conf /etc/dnsmasq.conf

ADD entrypoint.sh /root/entrypoint.sh
ADD ./pocketbase/infra-reveal /root/pb/infra-reveal
RUN chmod +x /root/pb/infra-reveal
WORKDIR /root
ENTRYPOINT ["/root/entrypoint.sh"]


# sudo docker run -it --net host --privileged --restart always -e AP_IFACE="wlan0" -e INTERNET_IFACE="eth0" -e SSID="Infrareveal old" pi-local/proxy:latest -d

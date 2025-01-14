FROM balenalib/rpi-raspbian:bullseye

RUN apt-get update --fix-missing && apt-get install -y hostapd dbus net-tools iptables dnsmasq net-tools macchanger

# install go
# RUN wget https://dl.google.com/go/go1.22.0.linux-armv6l.tar.gz
# RUN tar -C ~/.local/share -xzf go1.22.0.linux-armv6l.tar.gz

# ADD ./pocketbase /pb

# build go app
# RUN /.local/share/go/bin build -o /pb/pocketbase

ADD hostapd.conf /etc/hostapd/hostapd.conf
ADD hostapd /etc/default/hostapd
ADD dnsmasq.conf /etc/dnsmasq.conf

ADD entrypoint.sh /root/entrypoint.sh
ADD ./pocketbase/infra-reveal /root/infra-reveal/pb
WORKDIR /root
ENTRYPOINT ["/root/entrypoint.sh"]


# sudo docker run -it --net host --privileged --restart always -e AP_IFACE="wlan0" -e INTERNET_IFACE="eth0" -e SSID="Infrareveal old" pi-local/proxy:latest -d
# # sudo docker run -it --net host --privileged --restart always -e AP_IFACE="wlan0" -e INTERNET_IFACE="eth0" -e SSID="Infrareveal 3" -v "/home/pi/Documents/RED-test/infra-reveal/pocketbase:/root/pb" infra-reveal:test -d
#
#
# sudo docker run -it --net host --privileged --restart always -e AP_IFACE="wlan0" -e INTERNET_IFACE="eth0" -e SSID="Infrareveal test" infra-reveal:test -d

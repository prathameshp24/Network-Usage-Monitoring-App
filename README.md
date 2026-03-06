# Network-Usage-Monitoring-App
This app tracks your network usage on desktop, and classifies your internet footprints into productive and unproductive
Current app supports Linux.

#Setup
```bash
#Install required rackages
sudo pip3 install -r requirements.txt
```

#Usage
```bash
sudo python3 main.py
```
##Why sudo?
App needs root access since the app will try to sniff the packets which the device is sending and receiving from various interfaces available on the device.

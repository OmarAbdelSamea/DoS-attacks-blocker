# DOS Attack Detector 
## Setup 
1. [install python3](https://www.python.org/downloads) 
2. [install scapy](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)
3. GitHub clone [repo](https://github.com/OmarAbdelSamea/DoS-attacks-blocker)
## Run
1. navigate to repo folder 
2. run __DoS_defender.py__

    `python3 DoS_defender.py`

3. select protocol type 
    - for TCP enter 1 
    - for UDP enter 2
    - for ICMP enter 3
    *the detection rate is low and unrealistic for demonstration purposes*  
 4.  banned IPs will be printed on the screen 
 5.  to enable banned IPs again 
```
sudo iptables -P INPUT ACCEPT
sudo iptables -F

```    

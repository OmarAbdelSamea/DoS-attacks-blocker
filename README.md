# DOS Attack Detector 
## Setup 
1. [Install python3](https://www.python.org/downloads) 
2. [Install scapy](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)
3. Install iptables 
    - for Debien/ubuntu/kali/mint
    
        ` sudo apt-get install iptables `
    
    - for centos/redhat
    
        ` yum install iptables-services `
 
4. Clone GitHub [repo](https://github.com/OmarAbdelSamea/DoS-attacks-blocker)
## Run
1. Navigate to repo directory 
2. Run __DoS_defender.py__

    `sudo python3 DoS_defender.py`

3. Select protocol type:
    - for TCP enter 1 
    - for UDP enter 2
    - for ICMP enter 3
        
        _the detection rate is low and unrealistic for demonstration purposes_
        _if a source sent more than 20 requests in 10 seconds interval, it will be banned_

      ![image](https://user-images.githubusercontent.com/11968453/153318437-74d9fc7d-200a-4759-b3a1-d89b1f8c2651.png)
  
  

 4.  Banned IPs will be printed on the screen.
 
        ![image](https://user-images.githubusercontent.com/11968453/153319373-a96165e0-d521-4208-ad93-27db0be8ca8d.png)
        ![image](https://user-images.githubusercontent.com/11968453/153319386-1da38f9e-38a8-47e7-8c22-389f1fbf6161.png)
        ![image](https://user-images.githubusercontent.com/11968453/153319411-479218c8-dfcc-47a5-afb2-e17b2f741b0a.png)


 

 5.  To enable banned IPs again 
```
sudo iptables -P INPUT ACCEPT
sudo iptables -F

```    



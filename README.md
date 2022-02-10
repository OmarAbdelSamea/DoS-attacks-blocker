# DOS Attack Detector 
## Setup 
1. [Install python3](https://www.python.org/downloads) 
2. [Install scapy](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)
3. Install iptables 

    ```sudo apt-get install iptables```
 
4. Github clone [repo](https://github.com/OmarAbdelSamea/DoS-attacks-blocker)
## Run
1. navigate to repo folder 
2. run __DoS_defender.py__

    `python3 DoS_defender.py`

3. select protocol type:
    - for TCP enter 1 
    - for UDP enter 2
    - for ICMP enter 3
    
        _the detection rate is low and unrealistic for demonstration purposes_

      ![image](https://user-images.githubusercontent.com/11968453/153318437-74d9fc7d-200a-4759-b3a1-d89b1f8c2651.png)
  
  

 4.  banned IPs will be printed on the screen.

# DOS Attack Detector 
## Setup 
1. [Install python3](https://www.python.org/downloads) 
2. [Install scapy](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)
3. Install iptables 

    ```sudo apt-get install iptables```
 
4. Github clone [repo](https://github.com/OmarAbdelSamea/DoS-attacks-blocker)
## Run
1. navigate to repo folder 
2. run __DoS_defender.py__

    `python3 DoS_defender.py`

3. select protocol type:
    - for TCP enter 1 
    - for UDP enter 2
    - for ICMP enter 3
    
        _the detection rate is low and unrealistic for demonstration purposes_

      ![image](https://user-images.githubusercontent.com/11968453/153318437-74d9fc7d-200a-4759-b3a1-d89b1f8c2651.png)
  
  

 4.  banned IPs will be printed on the screen.
![image](https://user-images.githubusercontent.com/11968453/153319099-c62d43e7-93e5-4a00-b81a-6fd9621504f2.png)
![image](https://user-images.githubusercontent.com/11968453/153319116-d6b43b39-c071-490d-b783-a062dbddb303.png)

![image](https://user-images.githubusercontent.com/11968453/153319124-3e9b1d76-82e0-449e-8c7b-e89ebc0b0771.png)

 

 6.  to enable banned IPs again 
```
sudo iptables -P INPUT ACCEPT
sudo iptables -F

```    

 

 6.  to enable banned IPs again 
```
sudo iptables -P INPUT ACCEPT
sudo iptables -F

```    

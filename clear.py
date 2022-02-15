import os

def main(choice):
    if(choice=="1"):
        cmd = "iptables -n -L INPUT | grep DROP  | awk '{print $2\"_\"$4}'"
        proc = os.popen(cmd)
        cmd_output = proc.read()
        cmd_output = cmd_output.split()
        if len(cmd_output) > 0:
            for ip_string in cmd_output:
                type,ip = ip_string.split('_')
                print(f"IP: {ip} with type: {type}")
        else:
            print('iptables is empty')
        print()
    elif(choice =="2"):
        cmd = 'iptables -F'
        os.system(cmd)
        print('unbanned all successfully')
        print()
    elif(choice =="3"):
        cmd = "iptables -n -L INPUT | grep DROP  | awk '{print $2\"_\"$4}'"
        proc = os.popen(cmd)
        cmd_output = proc.read()
        cmd_output = cmd_output.split()
        if len(cmd_output) > 0:
            i=1
            for ip_string in cmd_output:
                type,ip = ip_string.split('_')
                print(f"num :{i} - IP: {ip} with type: {type}")
                i+=1
            number = input('enter the source number: ')
            cmd = f'sudo iptables -D INPUT {number}'
            os.popen(cmd)
        else:
            print('iptables is empty')
        print()
    elif(choice =="4"):
        exit()
    else:
        print("nah")
if __name__ == "__main__":
    print('''
1 show all banned
2 unban all
3 unban only one
4 exit
''')
    while(1):
        choice = input()
        main(choice)
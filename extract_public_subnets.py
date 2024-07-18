#Author : AppsecJay9
#This Script usefull, when need to extract public IP address from large file.
import sys
import re

def is_public_ip(ip):
    private_ranges = [
        (10, 8),
        (172, 12),
        (192, 16)
    ]

    octets = list(map(int, ip.split('.')))
    for prefix, bits in private_ranges:
        if bits == 8:
            if octets[0] == prefix:
                return False
        elif bits == 12:
            if octets[0] == prefix and 16 <= octets[1] < 32:
                return False
        elif bits == 16:
            if octets[0] == prefix and octets[1] == 168:
                return False
    return True

def extract_public_subnets(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        lines = infile.readlines()
        for line in lines:
            match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b', line)
            if match:
                ip_subnet = match.group(0)
                ip = ip_subnet.split('/')[0]
                if is_public_ip(ip):
                    outfile.write(ip_subnet + '\n')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py input_file output_file")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    extract_public_subnets(input_file, output_file)

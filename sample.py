import re
import csv
from collections import defaultdict
def count_requests_per_ip(log_file):
    ip_counts = defaultdict(int)  
    
    with open(log_file, 'r') as file:
        for line in file:
            
            match = re.match(r'(\S+) - - \[.*\] ".*" \d+ \d+', line)
            if match:
                ip = match.group(1)  
                ip_counts[ip] += 1  
                
    return ip_counts
def find_most_accessed_endpoint(log_file):
    endpoint_counts = defaultdict(int)  
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(r'\S+ - - \[.*\] ".* (/\S*) HTTP/1.1" \d+', line)
            if match: 
                endpoint = match.group(1)  
                endpoint_counts[endpoint] += 1 
    
    most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)  
    return most_accessed_endpoint, endpoint_counts[most_accessed_endpoint]
def detect_suspicious_activity(log_file, threshold=10):
    failed_logins = defaultdict(int)  
    
    with open(log_file, 'r') as file:
        for line in file:
          
            if '401' in line or 'Invalid credentials' in line:
                match = re.match(r'(\S+) - - \[.*\] ".*" 401 \d+ .*', line)
                if match:
                    ip = match.group(1) 
                    failed_logins[ip] += 1  
    
    
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips
def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
       
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
       
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow([most_accessed_endpoint[0], f"Accessed {most_accessed_endpoint[1]} times"])
        
        
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])
def display_results(ip_counts, most_accessed_endpoint, suspicious_activity):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")
def main():
    log_file = 'sample.log'  
    
  
    ip_counts = count_requests_per_ip(log_file)
    most_accessed_endpoint = find_most_accessed_endpoint(log_file)
    suspicious_activity = detect_suspicious_activity(log_file)
    
    
    display_results(ip_counts, most_accessed_endpoint, suspicious_activity)
    
   
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()

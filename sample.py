import re
import csv
from collections import defaultdict
def count_requests_per_ip(log_file):
    ip_counts = defaultdict(int)  # Using defaultdict to automatically set missing keys to 0
    
    with open(log_file, 'r') as file:
        for line in file:
            # Extract the IP address from each log line using a regular expression
            match = re.match(r'(\S+) - - \[.*\] ".*" \d+ \d+', line)
            if match:
                ip = match.group(1)  # Extract the IP address
                ip_counts[ip] += 1  # Increment the request count for this IP
                
    return ip_counts
def find_most_accessed_endpoint(log_file):
    endpoint_counts = defaultdict(int)  # Store endpoint access counts
    
    with open(log_file, 'r') as file:
        for line in file:
            # Extract the endpoint (path) from the log using a regular expression
            match = re.match(r'\S+ - - \[.*\] ".* (/\S*) HTTP/1.1" \d+', line)
            if match:
                endpoint = match.group(1)  # Extracting the endpoint path
                endpoint_counts[endpoint] += 1  # Incrementing the count for this endpoint
    
    most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)  # Get the most frequent one
    return most_accessed_endpoint, endpoint_counts[most_accessed_endpoint]
def detect_suspicious_activity(log_file, threshold=10):
    failed_logins = defaultdict(int)  # Store failed login attempts by IP address
    
    with open(log_file, 'r') as file:
        for line in file:
            # Look for failed login attempts (HTTP status 401)
            if '401' in line or 'Invalid credentials' in line:
                match = re.match(r'(\S+) - - \[.*\] ".*" 401 \d+ .*', line)
                if match:
                    ip = match.group(1)  # Extract the IP address
                    failed_logins[ip] += 1  # Increment the failed login count
    
    # Return IPs with failed login attempts exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips
def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Writing IP request counts
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Writing most accessed endpoint info
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow([most_accessed_endpoint[0], f"Accessed {most_accessed_endpoint[1]} times"])
        
        # Writing suspicious activity info
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
    log_file = 'sample.log'  # Make sure the log file is in the same folder or provide the full path
    
    # Perform analysis
    ip_counts = count_requests_per_ip(log_file)
    most_accessed_endpoint = find_most_accessed_endpoint(log_file)
    suspicious_activity = detect_suspicious_activity(log_file)
    
    # Display results
    display_results(ip_counts, most_accessed_endpoint, suspicious_activity)
    
    # Save results to CSV file
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()

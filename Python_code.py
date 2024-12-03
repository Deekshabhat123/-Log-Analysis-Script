import re
import csv
from collections import defaultdict

# Define the threshold for identifying suspicious activity
LOGIN_FAILURE_THRESHOLD = 10


def parse_access_log(log_file_path):
    """
    Reads the log file to gather statistics on IPs, accessed endpoints,
    and failed login attempts.

    Parameters:
    - log_file_path (str): The path to the log file to analyze.

    Returns:
    - dict: Contains IP addresses and their respective request counts.
    - dict: Contains the accessed endpoints and how many times they were accessed.
    - dict: Tracks IP addresses with the number of failed login attempts.
    """
    ip_requests = defaultdict(int)
    endpoint_accesses = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address from the log line using regex
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1  # Increment the request count for the IP

            # Capture the endpoint being accessed
            endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE|PATCH) (\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_accesses[endpoint] += 1  # Count how many times the endpoint is accessed

            # Identify failed login attempts (HTTP 401 status or 'Invalid credentials')
            if '401' in line or 'Invalid credentials' in line:
                failed_logins[ip] += 1  # Track failed login attempts by IP

    return ip_requests, endpoint_accesses, failed_logins


def print_most_frequent_endpoint(endpoint_accesses):
    """
    Prints the most accessed endpoint and the number of times it was accessed.

    Parameters:
    - endpoint_accesses (dict): Mapping of endpoints to their access counts.
    """
    if not endpoint_accesses:
        print("No endpoint accesses detected.")
        return

    most_accessed = max(endpoint_accesses.items(), key=lambda item: item[1])
    print(f"Most Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")


def print_suspicious_activity(failed_logins):
    """
    Prints a list of IP addresses with failed login attempts exceeding the threshold.

    Parameters:
    - failed_logins (dict): Mapping of IP addresses to failed login attempts.
    """
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > LOGIN_FAILURE_THRESHOLD}

    if not suspicious_ips:
        print("No suspicious activity detected.")
        return

    print(f"\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    print("-" * 40)
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")


def print_ip_request_stats(ip_requests):
    """
    Prints the list of IP addresses sorted by their request counts in descending order.

    Parameters:
    - ip_requests (dict): Mapping of IP addresses to request counts.
    """
    if not ip_requests:
        print("No IP requests found.")
        return

    print(f"\nIP Address           Request Count")
    print("-" * 40)
    sorted_ips = sorted(ip_requests.items(), key=lambda item: item[1], reverse=True)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count}")


def save_results_to_csv(ip_requests, endpoint_accesses, failed_logins, output_file='log_analysis_results.csv'):
    """
    Saves the analysis results to a CSV file.

    Parameters:
    - ip_requests (dict): IP addresses and their request counts.
    - endpoint_accesses (dict): Endpoints and their access counts.
    - failed_logins (dict): IP addresses with failed login attempts.
    - output_file (str): Path to the CSV output file.
    """
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Writing IP request counts
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_requests.items(), key=lambda item: item[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])  # Add an empty line for separation

        # Writing most accessed endpoint
        most_accessed = max(endpoint_accesses.items(), key=lambda item: item[1], default=None)
        writer.writerow(['Most Accessed Endpoint'])
        if most_accessed:
            writer.writerow([most_accessed[0], most_accessed[1]])
        else:
            writer.writerow(['None', 0])

        writer.writerow([])  # Add an empty line for separation

        # Writing suspicious activity (failed logins)
        writer.writerow(['Suspicious Activity (Failed Logins)'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in sorted(failed_logins.items(), key=lambda item: item[1], reverse=True):
            if count > LOGIN_FAILURE_THRESHOLD:
                writer.writerow([ip, count])


def main():
    # Define the path to the log file here
    log_file_path = 'access.log'

    # Step 1: Parse the log file to get IP counts, endpoint accesses, and failed login attempts
    ip_requests, endpoint_accesses, failed_logins = parse_access_log(log_file_path)

    # Step 2: Output results to the terminal
    print_ip_request_stats(ip_requests)
    print_most_frequent_endpoint(endpoint_accesses)
    print_suspicious_activity(failed_logins)

    # Step 3: Save the results to a CSV file
    save_results_to_csv(ip_requests, endpoint_accesses, failed_logins)


if __name__ == "__main__":
    main()

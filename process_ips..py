import csv
from collections import defaultdict, Counter

def process_csv(file_path):
    ip_events = defaultdict(list)

    with open(file_path, mode='r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Skip the headers row
        next(csv_reader)  # Skip the empty row
        next(csv_reader)  # Skip the "Query Result" row

        for row_num, row in enumerate(csv_reader, start=1):
            if len(row) >= 13:
                source_ip = row[6].strip()
                attack_event = row[12].strip()
                ip_events[source_ip].append(attack_event)
            else:
                print(f"Row {row_num} in file {file_path} does not have enough data: {row}")

    printed_ips = set()
    results = []

    for ip, events in ip_events.items():
        if ip not in printed_ips:
            event_counts = Counter(events)
            top_4_events = event_counts.most_common(4)
            results.append(f"{ip} : {', '.join(f'{event} ({count})' for event, count in top_4_events)}")
            printed_ips.add(ip)

    return results

# List of CSV file paths
csv_file_paths = [f"C:/Users/hp/IPS/IPS_{i}.csv" for i in range(1, 11)]

# Process each CSV file and print the results
for i, file_path in enumerate(csv_file_paths, start=1):
    results = process_csv(file_path)
    print(f"Results for IPS {i}:")
    for result in results:
        print(result)
print("\n" + "="*50 + "\n")

from datetime import datetime
import subprocess
import json
import requests
import geoip2.database
import tarfile
import os
import time
import sqlite3

# Router IP Address
ROUTER_IP = "192.168.2.1"

# SQLite database configuration
DB_FILE = "../web/DATABASE/netifyDB.sqlite"
NETIFY_FLOW_TABLE = "netify_flow"
NETIFY_PURGE_TABLE = "netify_purge"

# GeoIP database file and license
DOWNLOAD_NEW_DB = "no"  # Set to "yes" to download the new database, set to "no" to skip DB download
license_key = "YOUR-KEY"
database_type = "GeoLite2-City"
download_url = f"https://download.maxmind.com/app/geoip_download?edition_id={database_type}&license_key={license_key}&suffix=tar.gz"
output_folder = "files"
GEOIP_DB_FILE = "../files/GeoLite2-City.mmdb"


if DOWNLOAD_NEW_DB == "yes":
    # Send a GET request to the download URL
    response = requests.get(download_url, stream=True)

    # Check if the request was successful
    if response.status_code == 200:
        # Extract the filename from the response headers
        content_disposition = response.headers.get("content-disposition")
        filename = content_disposition.split("filename=")[1].strip('\"')

        # Create the output folder if it doesn't exist
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        # Open a file for writing in binary mode
        with open(filename, "wb") as f:
            # Iterate over the response content in chunks and write to file
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        # Extract only the GeoLite2-City.mmdb file to the output folder
        with tarfile.open(filename, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-City.mmdb"):
                    member.name = os.path.basename(member.name)
                    tar.extract(member, path=output_folder)

        print(f"Download and extraction complete. Database saved to {output_folder}/GeoLite2-City.mmdb")

        # Delete the .tar.gz file
        os.remove(filename)

        print(f"Deleted {filename} file.")
    else:
        print("Failed to download the database. Please check your license key.")
else:
    print("Skipping GeoLite2-City.mmdb database download.")

# GeoIP database reader
geoip_reader = geoip2.database.Reader(GEOIP_DB_FILE)

# Prometheus metrics URL
prometheus_url = f"http://{ROUTER_IP}:9100/metrics"
mac_host_mapping_file = "../files/mac_host_mapping.txt"

# Fetch metrics data and generate mac_host_mapping.txt
def generate_mac_host_mapping():
    try:
        response = requests.get(prometheus_url)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx and 5xx)
        data = response.text

        mac_host_mapping = {}
        lines = data.split("\n")
        for line in lines:
            if line.startswith('dhcp_lease{'):
                mac_start = line.find('mac="') + len('mac="')
                mac_end = line.find('"', mac_start)
                mac = line[mac_start:mac_end]

                name_start = line.find('name="') + len('name="')
                name_end = line.find('"', name_start)
                name = line[name_start:name_end]

                ip_start = line.find('ip="') + len('ip="')
                ip_end = line.find('"', ip_start)
                ip = line[ip_start:ip_end]

                mac_host_mapping[mac] = (name, ip)

        with open(mac_host_mapping_file, "w") as file:
            for mac, (hostname, ip) in mac_host_mapping.items():
                file.write(f"{mac.lower()} {hostname} {ip}\n")

    except requests.RequestException as e:
        print("An error occurred while fetching data from Prometheus:")
        print(e)
        # Create a blank file in case of HTTP request errors
        open(mac_host_mapping_file, "w").close()

# Generate mac_host_mapping.txt
generate_mac_host_mapping()

# Read mac_host_mapping.txt and create mapping dictionary
mac_host_mapping = {}
with open(mac_host_mapping_file, "r") as file:
    lines = file.readlines()
    for line in lines:
        line = line.strip()
        if line:
            mac, hostname, ip = line.split(" ", 2)
            mac_host_mapping[mac] = (hostname, ip)

# Create SQLite database connection
db = sqlite3.connect(DB_FILE)
cursor = db.cursor()

# Create Netify Flow table if it doesn't exist
create_table_query = """
CREATE TABLE IF NOT EXISTS netify_flow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeinsert TEXT,
    hostname TEXT,
    local_ip TEXT,
    local_mac TEXT,
    local_port INTEGER,
    fqdn TEXT,    
    dest_ip TEXT,
    dest_mac TEXT,
    dest_port INTEGER,
    dest_type TEXT,
    detected_protocol_name TEXT,
    detected_app_name TEXT,
    digest INTEGER,
    first_seen_at INTEGER,
    first_update_at INTEGER,
    vlan_id INTEGER,
    interface TEXT,
    internal INTEGER,
    ip_version INTEGER,
    last_seen_at INTEGER,
    type TEXT,
    dest_country TEXT,
    dest_state TEXT,
    dest_city TEXT,
    risk_score TEXT,
    risk_score_client TEXT,
    risk_score_server TEXT
);
"""
cursor.execute(create_table_query)
db.commit()



# Create Netify purge table if it doesn't exist
create_table_query = """
CREATE TABLE IF NOT EXISTS netify_purge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeinsert TEXT,
    digest INTEGER,
    detection_packets INTEGER,
    last_seen_at INTEGER,
    local_bytes INTEGER,
    local_packets INTEGER,
    other_bytes INTEGER,
    other_packets INTEGER,
    total_bytes INTEGER,
    total_packets INTEGER,
    interface TEXT,
    internal INTEGER,
    reason TEXT,
    type TEXT
);
"""
cursor.execute(create_table_query)
db.commit()



# Netcat command
netcat_process = subprocess.Popen(
    ["nc", ROUTER_IP, "7150"],
    stdout=subprocess.PIPE,
    universal_newlines=True
)


# Process the data stream for Netify_Flow
for line in netcat_process.stdout:
    # Check if the line contains both "established" and "local_ip"
    if "established" in line and "local_ip" in line:
        # Parse JSON data
        data = json.loads(line)

        flow_data = data.get("flow", {})
        detected_protocol_name = flow_data.get("detected_protocol_name", "Unknown")
        first_seen_at = flow_data.get("first_seen_at", 0)
        first_update_at = flow_data.get("first_update_at", 0)
        ip_version = flow_data.get("ip_version", 0)
        last_seen_at = flow_data.get("last_seen_at", 0)
        local_ip = flow_data.get("local_ip", "Unknown")
        local_mac = flow_data.get("local_mac", "Unknown")
        local_port = flow_data.get("local_port", 0)
        dest_ip = flow_data.get("other_ip", "Unknown")
        dest_mac = flow_data.get("other_mac", "Unknown")
        dest_port = flow_data.get("other_port", 0)
        dest_type = flow_data.get("other_type", "Unknown")
        vlan_id = flow_data.get("vlan_id", 0)
        interface = data.get("interface", "Unknown")
        internal = data.get("internal", False)
        type = data.get("type", "Unknown")
        detected_app_name = flow_data.get("detected_application_name", "Unknown")
        digest = flow_data.get("digest", "Unknown")

        # Check the structure of 'risks_data'
        risks_data = flow_data.get("risks", {})
        print("risks_data:", risks_data)

        # Extract risk scores
        risk_score = risks_data.get("ndpi_risk_score", 0)
        risk_score_client = risks_data.get("ndpi_risk_score_client", 0)
        risk_score_server = risks_data.get("ndpi_risk_score_server", 0)

        print(f"Risk Score: {risk_score}")
        print(f"Risk Score Client: {risk_score_client}")
        print(f"Risk Score Server: {risk_score_server}")


        # Check if 'host_server_name' exists in the data
        fqdn = flow_data.get("host_server_name", local_ip)
        #print(f"Here is the fqdn: {fqdn}")

        ssl_data = flow_data.get("ssl", {})
        client_sni = ssl_data.get("client_sni", "no_ssl")
        # Check if SSL field exists and has the 'client_sni' attribute, set the FQDN to the SNI
        if "client_sni" in ssl_data:
            fqdn = ssl_data["client_sni"]
            client_sni = ssl_data["client_sni"]
            #print(f"Here is the client_sni set for the fqdn: {fqdn}")

        # Check if local_mac exists in mac_host_mapping
        hostname, _ = mac_host_mapping.get(local_mac, (local_ip, ""))

        # Retrieve location information using GeoIP (You can uncomment this once you have the GeoIP functionality set up)
        try:
            response = geoip_reader.city(dest_ip)
            dest_country = response.country.name
            dest_state = response.subdivisions.most_specific.name
            dest_city = response.city.name
        except geoip2.errors.AddressNotFoundError:
            dest_country = "Unknown"
            dest_state = "Unknown"
            dest_city = "Unknown"

        # Get current timestamp
        time_insert = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # SQL query to insert data into the table
        insert_query = f"""
        INSERT INTO {NETIFY_FLOW_TABLE} (
            timeinsert, hostname, local_ip, local_mac, local_port, fqdn, dest_ip, dest_mac, dest_port, dest_type,
            detected_protocol_name, detected_app_name, digest, first_seen_at, first_update_at, vlan_id, interface, internal, ip_version,
            last_seen_at, type, dest_country, dest_state, dest_city, risk_score, risk_score_client, risk_score_server
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """

        # Execute the SQL query
        cursor.execute(insert_query, (
            time_insert, hostname, local_ip, local_mac, local_port, fqdn, dest_ip, dest_mac, dest_port, dest_type,
            detected_protocol_name, detected_app_name, digest, first_seen_at, first_update_at, vlan_id, interface, internal, ip_version,
            last_seen_at, type, dest_country, dest_state, dest_city, risk_score, risk_score_client, risk_score_server
        ))
        db.commit()



# Check if the line contains both "digest" and "flow_purge"
    if "digest" in line and "flow_purge" in line:
        data = json.loads(line)
        flow_data = data["flow"]  # Extract the flow data

        detection_packets = flow_data.get("detection_packets", 0)
        last_seen_at = flow_data.get("last_seen_at", 0)
        local_bytes = flow_data.get("local_bytes", 0)
        local_packets = flow_data.get("local_packets", 0)
        other_bytes = flow_data.get("other_bytes", 0)
        other_packets = flow_data.get("other_packets", 0)
        total_bytes = flow_data.get("total_bytes", 0)
        total_packets = flow_data.get("total_packets", 0)
        interface = data["interface"]
        internal = data["internal"]
        reason = data.get("reason", "Unknown")
        detected_app_name = flow_data.get("detected_application_name", "Unknown")
        digest = flow_data.get("digest", "Unknown")
        type = data["type"]

        # Get current timestamp
        time_insert = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # SQL query to insert data into the table
        insert_query = f"""
        INSERT INTO netify_purge (
            timeinsert, detection_packets, digest, last_seen_at, local_bytes, local_packets,
            other_bytes, other_packets, total_bytes, total_packets,
            interface, internal, reason, type
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """

        # Prepare the data for insertion
        insert_data = (
            time_insert, detection_packets, digest, last_seen_at, local_bytes, local_packets,
            other_bytes, other_packets, total_bytes, total_packets,
            interface, internal, reason, type
        )

        # Execute the SQL query
        cursor.execute(insert_query, insert_data)
        db.commit()





# Close the GeoIP database reader
#geoip_reader.close()

# Close SQLite cursor and connection
cursor.close()
db.close()

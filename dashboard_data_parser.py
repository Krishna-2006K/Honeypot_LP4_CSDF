# Import library dependencies.
import pandas as pd
import re
import requests
from pathlib import Path

# This file parses the various log files. The log files have different "formats" or information provided, so needed to create unique parsers for each.
# Each of these parsers takes the log file, gathers the specific information provided in the log, then returns the data in columns/rows Pandas dataframe type.

# Parser for the creds file. Returns IP Address, Username, Password.
def parse_creds_audits_log(creds_audits_log_file):
    data = []

    if Path(creds_audits_log_file).exists():
        with open(creds_audits_log_file, 'r') as file:
            for line in file:
                line_clean = line.strip()
                if not line_clean:
                    continue
                parts = line_clean.split(', ')
                if len(parts) >= 3:
                    ip_address = parts[0]
                    username = parts[1]
                    password = parts[2]
                    data.append([ip_address, username, password])

    df = pd.DataFrame(data, columns=["ip_address", "username", "password"])
    return df

# Parser for commands entered during SSH session.
def parse_cmd_audits_log(cmd_audits_log_file):

    data = []
    
    if Path(cmd_audits_log_file).exists():
        with open(cmd_audits_log_file, 'r') as file:
            # Regular expression to extract IP address and command
            pattern = re.compile(r"Command b'([^']*)'executed by (\d+\.\d+\.\d+\.\d+)")
            for line in file:
                line_clean = line.strip()
                if not line_clean:
                    continue
                match = pattern.search(line_clean)
                if match:
                    command, ip = match.groups()
                    data.append({'IP Address': ip, 'Command': command})
    
    df = pd.DataFrame(data, columns=['IP Address', 'Command'] if not data else None) 

    return df

# Calculator to generate top 10 values from a dataframe. Supply a column name, counts how often each value occurs, stores in "count" column, then return dataframe with value/count.
def top_10_calculator(dataframe, column):
    if dataframe is not None and column in dataframe.columns and not dataframe[column].empty:
        top_10_df = dataframe[column].value_counts().reset_index().head(10)
        top_10_df.columns = [column, "count"]
        return top_10_df

    return pd.DataFrame(columns=[column, "count"])

# Takes an IP address as string type, uses the Cleantalk API to look up IP Geolocation.
def get_country_code(ip):

    data_list = []
    # According to the CleanTalk API docs, API calls are rate limited to 1000 per 60 seconds.
    url = f"https://api.cleantalk.org/?method_name=ip_info&ip={ip}"
    try:
        response = requests.get(url, timeout=5)
        api_data = response.json()
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get('data', {})
            country_info = ip_data.get(ip, {})
            data_list.append({'IP Address': ip, 'Country_Code': country_info.get('country_code', 'Unknown')})
        elif response.status_code == 429:
            print(f"[!] CleanTalk IP->Geolocation Rate Limited Exceeded.")
            data_list.append({'IP Address': ip, 'Country_Code': 'Unknown'})
        else:
            data_list.append({'IP Address': ip, 'Country_Code': 'Unknown'})
    except Exception as e:
        print(f"[!] Request failed: {e}")
        data_list.append({'IP Address': ip, 'Country_Code': 'Unknown'})

    return data_list

# Takes a dataframe with the IP addresses, converts each IP address to country geolocation code.
def ip_to_country_code(dataframe):

    data = []

    if dataframe is not None and 'ip_address' in dataframe.columns:
        for ip in dataframe['ip_address']:
            get_country = get_country_code(ip)
            if get_country:
                parse_get_country = get_country[0].get("Country_Code", "Unknown")
                data.append({"IP Address": ip, "Country_Code": parse_get_country})
    
    df = pd.DataFrame(data, columns=["IP Address", "Country_Code"] if not data else None)
    return df
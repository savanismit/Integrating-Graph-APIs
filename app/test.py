import json

with open("./json_files/apis.json") as f:
    apis = json.load(f)

url = apis.get('create_contact', {})
print(url)

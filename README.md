# phish2MISP

We are happy to announce the release of Phish2MISP a small python script that can be used to gather information related to a phishing site and add it as an event in MISP.

We have often had the case of phishing sites that needs to be added to MISP as an event, and spending time on gathering the relevant attributes.

With Phish2MISP we have tried to make this as easy as possible.  


Configuration of the script is done in the keys file
```
misp_url = 'https://<MISP_SERVER>/'
misp_key = '<MISP_API_KEY>'
misp_verifycert = True
misp_tags = ['tlp:amber', 'misp-galaxy:financial-fraud="Phishing"']

misp_distribution = 3 # 0 = Organisation only, 1 = This community only, 2 = Connected communities, 3 = All communities, 4 = Sharing Group
sharing_group_id = 1 # Only to be used in combination with misp_distribution = 4

misp_threat_level_id = 1 # 0 = Undefined, 1 = Low, 2 = Medium, 3 = High
misp_analysis = 0 # 0 = Completed, 1 = Ongoing, 2 = Initial

auto_publish = False

make_screenshot = True

proxies = {
}
```

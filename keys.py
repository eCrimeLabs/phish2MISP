#!/usr/bin/env python3
# -*- coding: utf-8 -*-

misp_url = 'https://<MISP_SERVER>/'
misp_key = '<MISP_API_KEY>'
misp_verifycert = True
misp_tags = ['tlp:amber', 'misp-galaxy:financial-fraud="Phishing"']

misp_distribution = 0 # 0 = Organisation only, 1 = This community only, 2 = Connected communities, 3 = All communities, 4 = Sharing Group
sharing_group_id = 1 # Only to be used in combination with misp_distribution = 4

misp_threat_level_id = 1 # 0 = Undefined, 1 = Low, 2 = Medium, 3 = High
misp_analysis = 0 # 0 = Completed, 1 = Ongoing, 2 = Initial

auto_publish = False

make_screenshot = True

proxies = {
}

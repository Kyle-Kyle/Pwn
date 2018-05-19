import requests

headers = {}
headers['User-agent'] = 'Twitterbot'
r = requests.get('http://vxctf.fflm.ml', headers=headers)
print r.content

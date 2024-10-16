# import requests
# import json
# import zipfile
# import io
# from urllib.parse import urlparse

# print(urlparse("https://us-east1.cloud.twistlock.com/us-2-158320372/api/v32.05").netloc)

# url = "https://us-east1.cloud.twistlock.com/us-2-158320372/api/v32.05/defenders/serverless/bundle"
# runtime = "python3.10"
# payload = '{{"provider": "aws", "runtime": "{}"}}'.format(runtime)
# print(payload)
# payload1 = '{"provider": "aws", "runtime": ["python3.12"]}'
# headers = {
#   'Content-Type': 'application/octet-stream',
#   'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidHVsZUBwYWxvYWx0b25ldHdvcmtzLmNvbSIsInJvbGUiOiJhZG1pbiIsInJvbGVQZXJtcyI6W1syNTUsMjU1LDI1NSwyNTUsMjU1LDk1XSxbMjU1LDI1NSwyNTUsMjU1LDI1NSw5NV1dLCJzZXNzaW9uVGltZW91dFNlYyI6NjAwLCJzYWFzVG9rZW4iOiJleUpoYkdjaU9pSklVekkxTmlKOS5leUpoWTJObGMzTkxaWGxKWkNJNklqQTRaak0yWW1Nd0xUQmtaR1V0TkdRME5DMWhNekUyTFRrM01qWXpZVEEyWW1abU1pSXNJbk4xWWlJNkluUjFiR1ZBY0dGc2IyRnNkRzl1WlhSM2IzSnJjeTVqYjIwaUxDSm1hWEp6ZEV4dloybHVJanBtWVd4elpTd2ljSEpwYzIxaFNXUWlPaUk1TURJMU9Ua3pORFE1TnpVM05Ua3pOakFpTENKcGNFRmtaSEpsYzNNaU9pSXpOQzR4TXprdU1qUTVMakU1TWlJc0ltbHpjeUk2SW1oMGRIQnpPaTh2WVhCcE1pNXdjbWx6YldGamJHOTFaQzVwYnlJc0luSmxjM1J5YVdOMElqb3dMQ0pwYzBGalkyVnpjMHRsZVV4dloybHVJanAwY25WbExDSjFjMlZ5VW05c1pWUjVjR1ZFWlhSaGFXeHpJanA3SW1oaGMwOXViSGxTWldGa1FXTmpaWE56SWpwbVlXeHpaWDBzSW5WelpYSlNiMnhsVkhsd1pVNWhiV1VpT2lKVGVYTjBaVzBnUVdSdGFXNGlMQ0pwYzFOVFQxTmxjM05wYjI0aU9tWmhiSE5sTENKc1lYTjBURzluYVc1VWFXMWxJam94TnpFNU16Z3hOalF6TlRFNExDSmhkV1FpT2lKb2RIUndjem92TDJGd2FUSXVjSEpwYzIxaFkyeHZkV1F1YVc4aUxDSjFjMlZ5VW05c1pWUjVjR1ZKWkNJNk1Td2lZWFYwYUMxdFpYUm9iMlFpT2lKUVFWTlRWMDlTUkNJc0luTmxiR1ZqZEdWa1EzVnpkRzl0WlhKT1lXMWxJam9pUVZCUU1pQlFjbWx6YldFZ1EyeHZkV1FnUTNWemRHOXRaWElnVTNWalkyVnpjeUJNWVdJdElEVTBNVGd4TmpReE5qY3dNVGczT1Rnd05EZ2lMQ0p6WlhOemFXOXVWR2x0Wlc5MWRDSTZNVEl3TENKMWMyVnlVbTlzWlVsa0lqb2laak0xWXprNU9EZ3RNV1poTVMwMFpUYzVMV0U0TldFdE5ETXhZV1UxTldJeE1qUTRJaXdpYUdGelJHVm1aVzVrWlhKUVpYSnRhWE56YVc5dWN5STZabUZzYzJVc0ltVjRjQ0k2TVRjeE9UTTRNamswTWl3aWFXRjBJam94TnpFNU16Z3lNelF5TENKMWMyVnlibUZ0WlNJNkluUjFiR1ZBY0dGc2IyRnNkRzl1WlhSM2IzSnJjeTVqYjIwaUxDSjFjMlZ5VW05c1pVNWhiV1VpT2lKVGVYTjBaVzBnUVdSdGFXNGlmUS5vTE15aUhMMDJETEM0MWt1RDNmUDdGVDZTTEVNZFFOQ0FqQVR1dTU5d2ZVIiwiaXNzIjoidHdpc3Rsb2NrIiwiZXhwIjoxNzE5Mzg1OTQyfQ.R-pmXKMXe4glvRw9rm80LV_LkV5b3uaDvXTFrSG3W4g'
# }
# response = requests.post(url, headers=headers, data=payload)
# print(response)
# with open("zip_file.zip", 'wb') as fd:
#     fd.write(response.content)
#     # for chunk in response.iter_content(chunk_size=512):
#     #     fd.write(chunk)

str = "registry-auth.twistlock.com/tw_eyxo2yrkxqb38jnog3souxhfutdoakrg/twistlock/defender:defender_32_06_132"
print(str[-9:])
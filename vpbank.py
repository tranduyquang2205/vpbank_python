import requests
import json
import random
from datetime import datetime
import uuid
import re
import os
class VPBank:
    def __init__(self,username, password, account_number):
        self.bank_list = None
        self.file = f"db/users/{username}.json"
        self.username = username
        self.password = password
        self.account_number = account_number
        self.tokenKey = None
        self.csrf = None 
        self.cookie = None
        self.is_login = False
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.tokenKey = None
            self.csrf = None 
            self.cookie = None
            self.is_login = False
            self.save_data()
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
            self.save_data()
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'tokenKey': self.tokenKey,
            'csrf': self.csrf,
            'cookie': self.cookie,
            'is_login': self.is_login,
        }
        with open(f"db/users/{self.username}.json", 'w') as file:
            json.dump(data, file)
    def parse_data(self):
        with open(f"db/users/{self.username}.json", 'r') as file:
            data = json.load(file)
            self.username = data['username']
            self.password = data['password']
            self.account_number = data['account_number']
            self.tokenKey = data['tokenKey']
            self.csrf = data['csrf']
            self.cookie = data['cookie']
            self.is_login = data['is_login']
    def find_id_by_bank_code(self, array, bank_code):
        for item in array:
            if item['AccBankSmartLinkID'] == bank_code:
                return item['BankID']
        return None

    def generate_request_id(self, length=15):
        return ''.join(str(random.randint(0, 9)) for _ in range(length))

    def login(self):
        request_id = self.generate_request_id()
        url = 'https://neo.vpbank.com.vn/cb/odata/ns/authenticationservice/SecureUsers?action=init'

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Accept': 'application/json',
            'Accept-Language': 'vi',
            'Accept-Encoding': 'gzip, deflate, br',
            'X-Security-Request': 'required',
            'sap-cancel-on-close': 'false',
            'Content-Type': 'application/json',
            'Captcha': '',
            'ServiceChannel': '',
            'TrackingId': '',
            'device-id': 'B4D079A6-655E-408B-94EF-91E357A82BAC',
            'device-os': 'Windows 10 - Mozilla Firefox',
            'device-version': 'Firefox 114',
            'description': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'notify-token-key-id': 'NONE',
            'sap-contextid-accept': 'header',
            'DataServiceVersion': '2.0',
            'MaxDataServiceVersion': '2.0',
            'Origin': 'https://neo.vpbank.com.vn',
            'Connection': 'keep-alive',
            'Referer': 'https://neo.vpbank.com.vn/main.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'X-Request-ID': request_id,
        }

        payload = {
            "Id": "",
            "UserName": self.username,
            "AppType": "Consumers",
            "ChannelType": "Web",
            "Password": self.password,
            "UserLocale": {
                "Country": "VN",
                "Language": "vi"
            }
        }

        response = requests.post(url, headers=headers, data=json.dumps(payload))
        cookie_string = response.cookies

        tokenKey = response.headers.get('TokenKey')
        csrf = response.headers.get('x-csrf-token')

        body = json.loads(response.text)
        self.tokenKey = tokenKey
        self.csrf = csrf 
        self.cookie = cookie_string
        if body.get('d'):
            if body['d']['TRUSTED_DEVICE_ENABLED']:
                return {
                    'code': 302,
                    'status': True,
                    'message': 'Vui lòng nhập mã xác thực từ điện thoại',
                    'data':{
                         'tokenKey': tokenKey,
                         'csrf': csrf
                    }

                }
            else:
                self.is_login = True
                return {
                    'code': 200,
                    'status': True,
                    'message': 'Đăng nhập thành công',
                    'data':{
                         'tokenKey': tokenKey,
                         'csrf': csrf
                    }
                }
        else:
            return {
                'code': 444,
                'success': False,
                'message': 'Tài khoản hoặc mật khẩu không đúng'
                }

    def import_otp(self, otp):
        request_id = self.generate_request_id()
        url = 'https://neo.vpbank.com.vn/cb/odata/services/retailuserservice/AuthorizeTrustedDevice'

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Accept': 'application/json',
            'Accept-Language': 'vi',
            'X-Security-Request': 'required',
            'sap-cancel-on-close': 'true',
            'channelType': 'Web',
            'TokenKey': self.tokenKey,
            'Pragma': 'no-cache',
            'Expires': '-1',
            'X-Request-ID': request_id,
            'AuthorizationToken': otp,
            'sap-contextid-accept': 'header',
            'x-csrf-token': self.csrf,
            'DataServiceVersion': '2.0',
            'MaxDataServiceVersion': '2.0',
            'Connection': 'keep-alive',
            'Referer': 'https://neo.vpbank.com.vn/main.html',
        }
        response = requests.get(url, headers=headers,cookies=self.cookie)
        result = response.json()
        if 'error' in result:
            return {
                'code': 401,
                'success': False,
                'message': 'Mã không hợp lệ hoặc đã hết hạn (Unauthorized)!'
                }
        elif 'd' in result and 'StatusCode' in result['d'] and result['d']['StatusCode'] == 0:
            return {
                    'code': 200,
                    'status': True,
                    'message': 'Đăng nhập thành công',
                    'data':{
                         'tokenKey': self.tokenKey,
                         'csrf': self.csrf,
                         'cookie': self.cookie
                    }
                }
        return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 

    def list_account(self):
        request_id = self.generate_request_id()
        url = 'https://neo.vpbank.com.vn/cb/odata/services/accountservice/Accounts?%24top=500'

        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'vi',
            'Cache-Control': 'no-cache,no-store,must-revalidate',
            'Connection': 'keep-alive',
            'DataServiceVersion': '2.0',
            'Expires': '-1',
            'MaxDataServiceVersion': '2.0',
            'Pragma': 'no-cache',
            'Referer': 'https://neo.vpbank.com.vn/main.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'TokenKey': self.tokenKey,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'X-Request-ID': request_id,
            'X-Security-Request': 'required',
            'channelType': 'Web',
            'sap-cancel-on-close': 'true',
            'sap-contextid-accept': 'header',
            'sec-ch-ua': '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': 'Windows',
            'x-csrf-token': self.csrf
        }

        response = requests.get(url, headers=headers,cookies=self.cookie)
        return json.loads(response.text)
    def get_balance(self):
            if not self.is_login:
                login = self.login()
                if not login['success']:
                    return login
                    
            result = self.list_account()
            if 'd' in result and 'results' in result['d']:
                for account in result['d']['results']:
                    if self.account_number == account['Number']:
                        if int(account['AvailableBalance']) < 0:
                            return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                    'data': {
                                        'balance':int(account['AvailableBalance'])
                                    }
                                    } 
                        else:
                            return {'code':200,'success': True, 'message': 'Thành công',
                                    'data':{
                                        'account_number':self.account_number,
                                        'balance':int(account['AvailableBalance'])
                            }}
                return {'code':404,'success': False, 'message': 'account_number not found!'} 
            else: 
                return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 
    def check_history(self, start, end):
        if not self.is_login:
                login = self.login()
                if not login['success']:
                    return login
        request_id = self.generate_request_id()
        random_string = str(uuid.uuid4()).split('-')
        batch_header = "batch_" + random_string[1] + "-" + random_string[2] + "-" + random_string[3]
        try:
            list_account = self.list_account()
        except Exception as e:
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'}  
        
        url = 'https://neo.vpbank.com.vn/cb/odata/services/accountservice/$batch'

        batch_request = f'''--{batch_header}
Content-Type: application/http
Content-Transfer-Encoding: binary

GET DepositAccounts('{list_account['d']['results'][0]['Id']}')?$expand=DepositAccountTransactions&fromDate={start}&toDate={end} HTTP/1.1
sap-cancel-on-close: true
channelType: Web
TokenKey: {self.tokenKey}
Pragma: no-cache
Expires: -1
Cache-Control: no-cache,no-store,must-revalidate
X-Request-ID: {request_id}
sap-contextid-accept: header
Accept: application/json
x-csrf-token: {self.csrf}
Accept-Language: vi
DataServiceVersion: 2.0
MaxDataServiceVersion: 2.0


--{batch_header}--
'''

        headers = {
            'Accept': 'multipart/mixed',
            'Accept-Language': 'vi',
            'Cache-Control': 'no-cache,no-store,must-revalidate',
            'Connection': 'keep-alive',
            'Content-Type': f'multipart/mixed;boundary={batch_header}',
            'DataServiceVersion': '2.0',
            'Expires': '-1',
            'MaxDataServiceVersion': '2.0',
            'Origin': 'https://neo.vpbank.com.vn',
            'Pragma': 'no-cache',
            'Referer': 'https://neo.vpbank.com.vn/main.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'TokenKey': self.tokenKey,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'X-Request-ID': request_id,
            'X-Security-Request': 'required',
            'channelType': 'Web',
            'sap-cancel-on-close': 'true',
            'sap-contextid-accept': 'header',
            'sec-ch-ua': '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': 'Windows',
            'x-csrf-token': self.csrf
        }

        response = requests.post(url, headers=headers, data=batch_request,cookies=self.cookie)
        
        pattern = r'\n({.+)\n'
        matches = re.search(pattern, response.text)
        body = json.loads(matches[1])
        if 'd' in body and 'DepositAccountTransactions' in body['d']:
            return {'code':200,'success': True, 'message': 'Thành công',
                            'data':{
                                'transactions':body['d']['DepositAccountTransactions']['results'],
                    }}
        else:
            return  {
                        "success": False,
                        "code": 503,
                        "message": "Service Unavailable!"
                    },

    def check_account_name(self, account_number, bank_code):
        bank_id = self.find_id_by_bank_code(self.bank_list['d']['results'], bank_code)
        request_id = self.generate_request_id()
        random_string = str(datetime.now().strftime("%Y%m%d%H%M%S%f"))
        batch_header = f"batch_{random_string[:4]}-{random_string[4:8]}-{random_string[9:]}"
        list_account = self.list_account()
        url = 'https://neo.vpbank.com.vn/cb/odata/services/accountservice/$batch'

        batch_request = f'''--{batch_header}
Content-Type: application/http
Content-Transfer-Encoding: binary

GET GetAccountDetailsByID?Id='{account_number}-70'&BankID='11' HTTP/1.1
sap-cancel-on-close: true
channelType: Web
TokenKey: {self.tokenKey}
Pragma: no-cache
Expires: -1
Cache-Control: no-cache,no-store,must-revalidate
X-Request-ID: {request_id}
sap-contextid-accept: header
Accept: application/json
x-csrf-token: {self.csrf}
Accept-Language: vi
DataServiceVersion: 2.0
MaxDataServiceVersion: 2.0

--{batch_header}--
'''

        headers = {
            'Accept': 'multipart/mixed',
            'Accept-Language': 'vi',
            'Cache-Control': 'no-cache,no-store,must-revalidate',
            'Connection': 'keep-alive',
            'Content-Type': f'multipart/mixed;boundary={batch_header}',

            'DataServiceVersion': '2.0',
            'Expires': '-1',
            'MaxDataServiceVersion': '2.0',
            'Origin': 'https://neo.vpbank.com.vn',
            'Pragma': 'no-cache',
            'Referer': 'https://neo.vpbank.com.vn/main.html',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'TokenKey': self.tokenKey,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'X-Request-ID': request_id,
            'X-Security-Request': 'required',
            'channelType': 'Web',
            'sap-cancel-on-close': 'true',
            'sap-contextid-accept': 'header',
            'sec-ch-ua': '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': 'Windows',
            'x-csrf-token': self.csrf
        }

        response = requests.post(url, headers=headers, data=batch_request,cookies=self.cookie)

        body = json.loads(response.text)

        if body['d']['DepositAccountTransactions']:
            return json.dumps(body['d']['DepositAccountTransactions'])
        else:
            return json.dumps({'status': 'error', 'message': 'Đã xảy ra lỗi!'})


# username = "0886438795"
# password = "Dqxkv2205.,"
# account_number = "296813408"
# fromDate="06/01/2024"
# toDate= "07/03/2024"
# vpbank = VPBank(username, password,account_number)
# login = vpbank.login()
# from api_response import APIResponse
# print(APIResponse.json_format(login))
# if 'Vui lòng nhập mã xác thực từ điện thoại' in login['message']:
#     otp = input("\n")
#     if otp:
#         import_otp = vpbank.import_otp(otp)
#         print(import_otp)
# elif 'Đăng nhập thành công' in login['message']:
#     balance = vpbank.get_balance()
#     print(balance)

#     history = vpbank.check_history(fromDate,toDate)
#     print(history)
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from vpbank import VPBank
import sys
import traceback
from api_response import APIResponse

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}
class LoginDetails(BaseModel):
    username: str
    password: str
    account_number: str
    
@app.post('/login', tags=["login"])
def login_api(input: LoginDetails):
    try:
        vpbank = VPBank(input.username, input.password,input.account_number)
        login = vpbank.login()
        return APIResponse.json_format(login)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response,True)

class ConfirmLoginDetails(BaseModel):
    username: str
    password: str
    account_number: str
    otp: str
    
@app.post('/confirm_login', tags=["confirm_login"])
def login_api(input: ConfirmLoginDetails):
    try:
        vpbank = VPBank(input.username, input.password,input.account_number)
        import_otp = vpbank.import_otp(input.otp)
        return APIResponse.json_format(import_otp)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response,True)

@app.post('/get_balance', tags=["get_balance"])
def get_balance_api(input: LoginDetails):
    try:
        vpbank = VPBank(input.username, input.password,input.account_number)
        balance = vpbank.get_balance()
        return APIResponse.json_format(balance)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response,True)
    
class Transactions(BaseModel):
    username: str
    password: str
    account_number: str
    from_date: str
    to_date: str
    
@app.post('/get_transactions', tags=["get_transactions"])
def get_transactions_api(input: Transactions):
    try:
        vpbank = VPBank(input.username, input.password,input.account_number)
        transactions = vpbank.check_history(input.from_date,input.to_date)
        return APIResponse.json_format(transactions)
    except Exception as e:
        response = str(e)
        print(traceback.format_exc())
        print(sys.exc_info()[2])
        return APIResponse.json_format(response,True)
    
if __name__ == "__main__":
    uvicorn.run(app ,host='0.0.0.0', port=3000)
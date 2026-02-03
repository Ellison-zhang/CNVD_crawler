from cnvd_browser_client import CNVDBrowserClient
import json
import os

def login_and_save_cookies():
    print("启动浏览器进行登录...")
    # headless=False 允许用户看到浏览器并处理验证码
    client = CNVDBrowserClient(headless=False)
    client.start()
    
    try:
        # 这里不传用户名密码，让用户自己在浏览器输入，或者你可以修改这里传入
        cookies = client.login()
        
        # 将 cookies 保存为 json
        with open("cookies.json", "w") as f:
            json.dump(cookies, f)
            
        print("Cookies 已保存到 cookies.json")
        
        # 同时也打印出 cookie string 方便直接复制
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        print(f"Cookie String: {cookie_str}")
        
    except Exception as e:
        print(f"登录过程中出错: {e}")
    finally:
        client.stop()

if __name__ == "__main__":
    login_and_save_cookies()

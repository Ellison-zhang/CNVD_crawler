from pathlib import Path
from typing import Optional
from playwright.sync_api import sync_playwright
import time
import ddddocr


class CNVDBrowserClient:
    def __init__(self, download_dir="downloads", headless=True, proxy=None):
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.headless = headless
        self.proxy = proxy
        self.ocr = ddddocr.DdddOcr(show_ad=False)

        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    def start(self):
        self.playwright = sync_playwright().start()
        
        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-crash-reporter",
            "--disable-breakpad",
        ]
        
        user_data_path = self.download_dir.parent / "browser_user_data"
        
        context_config = {
            "user_data_dir": str(user_data_path),
            "headless": self.headless,
            "args": launch_args,
            "env": {"HOME": str(self.download_dir.parent / "browser_tmp_home")},
            "accept_downloads": True,
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        
        if self.proxy:
            context_config["proxy"] = {"server": f"http://{self.proxy}"} if "://" not in self.proxy else {"server": self.proxy}

        self.context = self.playwright.chromium.launch_persistent_context(**context_config)
        self.browser = None
        
        if len(self.context.pages) > 0:
            self.page = self.context.pages[0]
        else:
            self.page = self.context.new_page()

    def stop(self):
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def ensure_clearance(self):
        """
        访问首页，确保 __jsl_clearance_s 已生成
        """
        self.page.goto("https://www.cnvd.org.cn/", timeout=30000)
        self.page.wait_for_load_state("networkidle")

        cookies = self.context.cookies()
        if not any(c["name"].startswith("__jsl_clearance") for c in cookies):
            # 如果没有 clearance cookie，可能是需要验证码，等待用户手动处理
            print("未能自动获取 __jsl_clearance_s，请在浏览器中手动完成验证...")
            input("完成后按回车继续...")
            
        cookies = self.context.cookies()
        if not any(c["name"].startswith("__jsl_clearance") for c in cookies):
             raise RuntimeError("未能通过 CNVD JS 校验")

    def login(self, username=None, password=None):
        """
        登录 CNVD，支持手动处理验证码
        """
        self.ensure_clearance()
        
        self.page.goto("https://www.cnvd.org.cn/user/login")
        self.page.wait_for_load_state("networkidle")
        
        if username:
            try:
                # 尝试自动填充，如果选择器不对可能会失败，忽略错误让用户手动填
                self.page.fill("input[name='email']", username)
                self.page.fill("input[name='password']", password)
            except Exception as e:
                print(f"自动填充失败: {e}")
        
        print("尝试自动识别验证码...")
        if self.solve_captcha():
             print("自动提交验证码完成，请检查是否登录成功。")
             self.page.wait_for_timeout(2000) # 等待登录跳转
        else:
             print("自动识别验证码失败或未找到元素，请手动处理...")

        print("请在浏览器中确认登录状态...")
        input("登录成功后按回车继续...")
        
        # 登录后保存 cookies，供 requests 使用
        cookies = self.context.cookies()
        cookie_dict = {c['name']: c['value'] for c in cookies}
        return cookie_dict


    def refresh_captcha(self):
        """刷新验证码"""
        try:
            print("尝试刷新验证码...")
            # 1. 优先尝试点击图片本身 (通常最有效且稳定)
            captcha_img = self.page.query_selector("#cap-img") or \
                          self.page.query_selector("img[src*='captcha']") or \
                          self.page.query_selector("img[src*='Captcha']") or \
                          self.page.query_selector("#captcha_img") or \
                          self.page.query_selector(".captcha") or \
                          self.page.query_selector("img[onclick*='captcha']") or \
                          self.page.query_selector("#vcode") or \
                          self.page.query_selector("#chkcode") or \
                          self.page.query_selector("img[src*='code']")
            
            if captcha_img:
                print("找到验证码图片，尝试点击刷新...")
                captcha_img.click()
                self.page.wait_for_timeout(2000)  # 等待刷新
                return True

            # 2. 如果找不到图片，尝试寻找 '换一张' 链接/按钮
            # 使用 xpath 模糊匹配文本，兼容性更好
            refresh_btn = self.page.query_selector("//*[contains(text(), '换一张')]") or \
                          self.page.query_selector("#update")
            
            if refresh_btn:
                print("找到'换一张'按钮，尝试点击...")
                refresh_btn.click()
                self.page.wait_for_timeout(2000)
                return True

            print("未找到验证码图片或刷新按钮，无法刷新")
            return False
        except Exception as e:
            print(f"刷新验证码失败: {e}")
            return False

    def solve_captcha(self):
        """尝试识别并填写验证码"""
        try:
            # 尝试定位验证码图片
            # 常见选择器
            captcha_img = self.page.query_selector("#cap-img") or \
                          self.page.query_selector("img[src*='captcha']") or \
                          self.page.query_selector("img[src*='Captcha']") or \
                          self.page.query_selector("#captcha_img") or \
                          self.page.query_selector(".captcha") or \
                          self.page.query_selector("img[onclick*='captcha']") or \
                          self.page.query_selector("#vcode") or \
                          self.page.query_selector("#chkcode") or \
                          self.page.query_selector("img[src*='code']")
            
            if not captcha_img:
                print("未找到验证码图片元素")
                return False

            src = captcha_img.get_attribute("src")
            print(f"找到验证码图片，src: {src}")

            # 截图
            timestamp = int(time.time())
            img_path = self.download_dir / f"captcha_{timestamp}.png"
            captcha_img.screenshot(path=img_path)

            # 识别
            with open(img_path, 'rb') as f:
                img_bytes = f.read()
            res = self.ocr.classification(img_bytes)
            print(f"验证码识别结果: {res}")
            
            # 如果识别结果为空，可能没识别出来
            if not res:
                return False

            # 寻找输入框
            input_box = self.page.query_selector("input[placeholder*='验证码']") or \
                        self.page.query_selector("input[name*='captcha']") or \
                        self.page.query_selector("input[name*='code']") or \
                        self.page.query_selector("#captcha") or \
                        self.page.query_selector("#ans") or \
                        self.page.query_selector("input[name='ans']")
            
            if input_box:
                input_box.fill(res)
                print(f"已填入验证码: {res}")
                
                # 寻找提交按钮 - 这里的逻辑可能比较脆弱，因为不同页面的提交按钮不一样
                # 有些页面是回车提交，有些是点击按钮
                # 如果是登录页，通常有登录按钮
                login_btn = self.page.query_selector("#login_btn") or \
                            self.page.query_selector("input[type='submit']") or \
                            self.page.query_selector("button[type='submit']") or \
                            self.page.query_selector(".login_btn")
                
                if login_btn:
                    # 点击提交
                    print("找到提交按钮，尝试点击...")
                    login_btn.click()
                    return True
            else:
                print("未找到验证码输入框")
            
            return False
        except Exception as e:
            print(f"自动识别验证码出错: {e}")
            return False


    def download(self, url: str, filename: Optional[str] = None) -> Path:
        """
        下载 CNVD 文件
        """
        self.ensure_clearance()

        with self.page.expect_download(timeout=30000) as download_info:
            self.page.goto(url)
        download = download_info.value

        if not filename:
            filename = download.suggested_filename

        save_path = self.download_dir / filename
        download.save_as(save_path)

        return save_path

if __name__ == '__main__':
    # 使用 headless=False 以便手动处理验证码
    client = CNVDBrowserClient(headless=False)
    client.start()
    try:
        # 如果需要登录，取消下面的注释并填入账号密码
        # cookies = client.login("your_email", "your_password")
        # print("Cookies:", cookies)
        
        client.ensure_clearance()
        client.download("https://www.cnvd.org.cn/shareData/download/463")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # client.stop() # 注释掉以保持浏览器打开，或者在确认完成后关闭
        pass

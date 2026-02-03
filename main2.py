import re
import os
import json
import execjs
import requests
import hashlib
import random
import argparse
import pandas as pd

from time import sleep
from bs4 import BeautifulSoup
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from cnvd_browser_client import CNVDBrowserClient

requests.packages.urllib3.disable_warnings()
from lxml import etree
from datetime import datetime


def get_current_time():
    """获取当前时间并格式化"""
    return datetime.now().strftime("%Y/%m/%d %H:%M:%S")


def get_jsl_clearance_s(jsl_data):
    """生成JSL clearance"""
    chars = len(jsl_data['chars'])
    for i in range(chars):
        for j in range(chars):
            jsl_clearance_s = jsl_data['bts'][0] + jsl_data['chars'][i:(i + 1)] + jsl_data['chars'][j:(j + 1)] + \
                              jsl_data['bts'][1]
            if getattr(hashlib, jsl_data['ha'])(jsl_clearance_s.encode('utf-8')).hexdigest() == jsl_data['ct']:
                return jsl_clearance_s


def request_cnvd(url, params, proxies, cookies):
    """发送请求"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36',
        }
        return requests.get(url, params=params, cookies=cookies, headers=headers, proxies=proxies, verify=False,
                            timeout=30)
    except requests.exceptions.Timeout:
        print(f'[{get_current_time()}][!] 请求超时，等待30秒后重试')
        sleep(30)
        return request_cnvd(url, params, proxies, cookies)
    except requests.exceptions.SSLError as e:
        print(f'[{get_current_time()}][!] SSL错误: {e}')
        with open('error.txt', 'a', encoding='utf-8') as f:
            f.write(f'{get_current_time()} - {str(e)}\n\n')
        sleep(60)
        return request_cnvd(url, params, proxies, cookies)
    except Exception as e:
        print(f'[{get_current_time()}][!] 请求异常: {e}')
        sleep(30)
        return request_cnvd(url, params, proxies, cookies)


def cnvd_jsl(url, params, proxies, cookies = '__jsluid_s=c26fea7805b3f7d3247e91b56cceefd9; JSESSIONID=02A97E64638474A257B647E61FDFACE9; puk=c374668cc2c92ea819f844bafcc78c776b55b64f9125040f3cfc2c4c2261e2b21d97c4bf74896ee0521e4981d194619b7d83d975882ec465deebb4e7e81b3a5b924107627b6c404e0fdc2430a231b15cfc21df0b2f9db57bdd253b0d1b9f8da5bcb7017879ae91c40ac38974d066834b; __jsl_clearance_s=1768465492.285|1|8TjYU5nuHwai1gqP%2BGIhtDWVvsA%3D'):
    """处理CNVD的JSL验证"""
    r = request_cnvd(url, params, proxies, cookies)
    print(r.text)
    if r.status_code == 521:
        if re.findall('document.cookie=(.*?);location.', r.text):
            cookies = r.cookies.get_dict()
            __jsl_clearance_s = \
                execjs.eval(re.findall('document.cookie=(.*?);location.', r.text)[0]).split(';')[0].split('=')[1]
            cookies['__jsl_clearance_s'] = __jsl_clearance_s
            r = request_cnvd(url, params, proxies, cookies)

            if r.text.find(';location.href=location.pathname+location.search') != -1:
                js_code = r.text.replace('<script>document.cookie=', '').replace(
                    ';location.href=location.pathname+location.search</script>', '')
                js_code = execjs.eval(js_code).split(';')[0].split('=')[1]
                cookies['__jsl_clearance_s'] = js_code
            else:
                try:
                    jsl_data = json.loads(re.findall('go\((\{.*?\})\)', r.text)[0])
                    cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
                except Exception as e:
                    print(f'[{get_current_time()}][!] 获取jsl_data失败: {e}')
                    sleep(60)
                    return cnvd_jsl(url, params=params, proxies=proxies, cookies=cookies)

            r = request_cnvd(url, params, proxies, cookies)

        if re.findall('go\((\{.*?\})\)', r.text):
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)', r.text)[0])
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = request_cnvd(url, params, proxies, cookies)

    elif r.status_code == 403:
        next_time = random.randint(60, 120)
        print(f'[{get_current_time()}][!] 检测到疑似攻击，等待{next_time}秒')
        sleep(next_time)
        return cnvd_jsl(url, params=params, proxies=proxies, cookies=cookies)

    # elif r.status_code == 404:
    #     next_time = random.randint(60, 120)
    #     print(f'[{get_current_time()}][!] IP被封禁，等待{next_time}秒')
    #     sleep(next_time)
    #     return cnvd_jsl(url, params=params, proxies=proxies, cookies=cookies)


    return r, cookies


def replace_list(data_list):
    """清洗列表数据"""
    return [data.strip() for data in data_list if data and data.strip()]


def get_data(data_html, url):
    """解析CNVD详情页"""
    import time

    item = {
        "parse_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "path": url,
        "spider_time": int(time.time() * 1000)
    }

    # 名称
    name_list = data_html.xpath('//div[@class="blkContainerSblk"]//h1/text()')
    if not name_list:
         # 尝试另一种常见的详情页结构
         name_list = data_html.xpath('//h1/text()')
    item["name"] = name_list[0] if name_list else None

    # CNVD-ID
    cnvd_list = data_html.xpath('//tbody//td[contains(text(),"CNVD-ID")]/following-sibling::td//text()')
    if not cnvd_list:
         cnvd_list = data_html.xpath('//td[contains(text(),"CNVD-ID")]/following-sibling::td//text()')
    cnvd_list = replace_list(cnvd_list)
    item["cnvd"] = cnvd_list[0] if cnvd_list else None

    # 公开日期
    publish_list = data_html.xpath('//tbody//td[contains(text(),"公开日期")]/following-sibling::td//text()')
    if not publish_list:
        publish_list = data_html.xpath('//td[contains(text(),"公开日期")]/following-sibling::td//text()')
    publish_list = replace_list(publish_list)
    item["publish"] = publish_list[0] if publish_list else None

    # 危害级别和CVSS
    severity_and_cvss_list = data_html.xpath('//tbody//td[contains(text(),"危害级别")]/following-sibling::td//text()')
    if not severity_and_cvss_list:
        severity_and_cvss_list = data_html.xpath('//td[contains(text(),"危害级别")]/following-sibling::td//text()')
    severity_and_cvss_list = replace_list(severity_and_cvss_list)
    severity = None
    cvss_vector = None
    if severity_and_cvss_list:
        severity = severity_and_cvss_list[0][0] if severity_and_cvss_list[0] else None
        try:
            cvss_vector = severity_and_cvss_list[1]
        except:
            pass
    item["severity"] = severity
    item["cvss_vector"] = cvss_vector

    # 影响产品
    product_list = data_html.xpath('//tbody//td[contains(text(),"影响产品")]/following-sibling::td//text()')
    if not product_list:
        product_list = data_html.xpath('//td[contains(text(),"影响产品")]/following-sibling::td//text()')
    product_list = replace_list(product_list)
    item["product"] = json.dumps(product_list, ensure_ascii=False) if product_list else None

    # CVE ID
    cve_list = data_html.xpath('//td[contains(text(),"CVE ID")]/following-sibling::td//text()')
    cve_list = replace_list(cve_list)
    item["cve"] = cve_list[0].strip() if cve_list else None

    # 漏洞描述
    description_list = data_html.xpath('//td[contains(text(),"漏洞描述")]/following-sibling::td//text()')
    description_list = replace_list(description_list)
    item["description"] = "".join(description_list).strip() if description_list else None

    # 漏洞类型
    flaw_type_list = data_html.xpath('//tbody//td[contains(text(),"漏洞类型")]/following-sibling::td//text()')
    if not flaw_type_list:
        flaw_type_list = data_html.xpath('//td[contains(text(),"漏洞类型")]/following-sibling::td//text()')
    flaw_type_list = replace_list(flaw_type_list)
    item["flaw_type"] = flaw_type_list[0].strip() if flaw_type_list else None

    # 参考链接
    reference_list = data_html.xpath('//tbody//td[contains(text(),"参考链接")]/following-sibling::td//text()')
    if not reference_list:
        reference_list = data_html.xpath('//td[contains(text(),"参考链接")]/following-sibling::td//text()')
    reference_list = replace_list(reference_list)
    item["reference"] = "\n".join(reference_list).strip() if reference_list else None

    # 漏洞解决方案
    solution_list = data_html.xpath('//tbody//td[contains(text(),"漏洞解决方案")]/following-sibling::td//text()')
    if not solution_list:
        solution_list = data_html.xpath('//td[contains(text(),"漏洞解决方案")]/following-sibling::td//text()')
    solution_list = replace_list(solution_list)
    solution = None
    if solution_list:
        solution = "\n".join(solution_list)
        if solution.strip().startswith("http"):
            solution = "厂商已发布了漏洞修复程序，请及时关注更新：" + solution_list[0].strip()
    item["solution"] = solution

    # 厂商补丁
    patch_list = data_html.xpath('//tbody//td[contains(text(),"厂商补丁")]/following-sibling::td//text()')
    if not patch_list:
        patch_list = data_html.xpath('//td[contains(text(),"厂商补丁")]/following-sibling::td//text()')
    patch_list = replace_list(patch_list)
    item["patch"] = patch_list[0].strip() if patch_list else None

    # 验证信息
    verify_list = data_html.xpath('//tbody//td[contains(text(),"验证信息")]/following-sibling::td//text()')
    if not verify_list:
        verify_list = data_html.xpath('//td[contains(text(),"验证信息")]/following-sibling::td//text()')
    verify_list = replace_list(verify_list)
    item["verify"] = verify_list[0].strip() if verify_list else None

    # 报送时间
    submit_time_list = data_html.xpath('//tbody//td[contains(text(),"报送时间")]/following-sibling::td//text()')
    if not submit_time_list:
        submit_time_list = data_html.xpath('//td[contains(text(),"报送时间")]/following-sibling::td//text()')
    submit_time_list = replace_list(submit_time_list)
    item["submit_time"] = submit_time_list[0] if submit_time_list else None

    # 收录时间
    open_time_list = data_html.xpath('//td[contains(text(),"收录时间")]/following-sibling::td//text()')
    open_time_list = replace_list(open_time_list)
    item["open_time"] = open_time_list[0] if open_time_list else None

    # 更新时间
    update_time_list = data_html.xpath('//tbody/tr[13]/td[2]//text()')
    update_time_list = replace_list(update_time_list)
    item["update_time"] = update_time_list[0] if update_time_list else None

    # 生成data_summary
    summary_item = {k: (v if v is not None else "") for k, v in item.items()}
    data_str = (
            summary_item["path"] + summary_item.get("cnvd", "") + summary_item.get("cve", "") +
            summary_item.get("name", "") + summary_item.get("severity", "") +
            summary_item.get("product", "") + summary_item.get("flaw_type", "") +
            summary_item.get("submit_time", "") + summary_item.get("publish", "") +
            summary_item.get("reference", "") + summary_item.get("solution", "") +
            summary_item.get("patch", "") + summary_item.get("description", "")
    )
    item["data_summary"] = hashlib.md5(data_str.encode("utf-8")).hexdigest()

    return item


class CNVDDatabase:
    """数据库操作类"""

    def __init__(self, db_url='mysql+pymysql://root:8ik,lp-=@192.168.110.15:3306/new_vuln_data'):
        try:
            self.engine = create_engine(db_url, pool_pre_ping=True, pool_recycle=3600)
            Session = sessionmaker(bind=self.engine)
            self.session = Session()
            print(f'[{get_current_time()}][+] 数据库连接成功')
        except Exception as e:
            print(f'[{get_current_time()}][!] 数据库连接失败: {e}')
            raise

    def check_cnvd_exists(self, cnvd_id):
        """检查单个CNVD编号是否存在"""
        try:
            query = text("SELECT cnvd FROM lib_vul_identifier WHERE cnvd = :cnvd_id LIMIT 1")
            result = self.session.execute(query, {"cnvd_id": cnvd_id}).fetchone()
            return result is not None
        except Exception as e:
            print(f'[{get_current_time()}][!] 查询数据库出错 ({cnvd_id}): {e}')
            return False

    def batch_check_cnvd_exists(self, cnvd_ids):
        """批量检查CNVD编号是否存在"""
        try:
            if not cnvd_ids:
                return set()

            # 构建IN查询
            placeholders = ','.join([f':id{i}' for i in range(len(cnvd_ids))])
            query = text(f"SELECT cnvd FROM lib_vul_identifier WHERE cnvd IN ({placeholders})")
            params = {f'id{i}': cnvd_id for i, cnvd_id in enumerate(cnvd_ids)}

            result = self.session.execute(query, params).fetchall()
            return set(row[0] for row in result)
        except Exception as e:
            print(f'[{get_current_time()}][!] 批量查询数据库出错: {e}')
            return set()

    def close(self):
        """关闭数据库连接"""
        try:
            self.session.close()
            print(f'[{get_current_time()}][+] 数据库连接已关闭')
        except Exception as e:
            print(f'[{get_current_time()}][!] 关闭数据库连接出错: {e}')


def read_cnvd_from_csv(csv_file):
    """从CSV文件读取CNVD编号"""
    try:
        # 尝试不同的编码读取
        try:
            df = pd.read_csv(csv_file, encoding='utf-8')
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(csv_file, encoding='gbk')
            except:
                df = pd.read_csv(csv_file, encoding='gb2312')

        # 尝试多种可能的列名
        cnvd_column = None
        possible_columns = ['cnvd', 'CNVD', 'cnvd_id', 'CNVD_ID', 'cnvd-id', 'CNVD-ID',
                            'CNVD ID', 'cnvd id', 'CNVD编号', 'cnvd编号']

        for col in possible_columns:
            if col in df.columns:
                cnvd_column = col
                break

        if cnvd_column is None:
            # 如果没有匹配的列名，使用第一列
            cnvd_column = df.columns[0]
            print(f'[{get_current_time()}][!] 未找到标准CNVD列名，使用第一列: {cnvd_column}')

        print(f'[{get_current_time()}][+] 使用列: {cnvd_column}')

        # 读取并清洗数据
        cnvd_list = df[cnvd_column].dropna().astype(str).str.strip().tolist()

        # 过滤有效的CNVD编号（格式：CNVD-YYYY-XXXXX）
        valid_cnvds = []
        invalid_count = 0
        for cnvd in cnvd_list:
            if re.match(r'CNVD-\d{4}-\d+', cnvd, re.IGNORECASE):
                valid_cnvds.append(cnvd.upper())
            else:
                invalid_count += 1

        print(f'[{get_current_time()}][+] 从CSV读取到 {len(cnvd_list)} 条记录')
        print(f'[{get_current_time()}][+] 有效CNVD编号: {len(valid_cnvds)} 个')
        if invalid_count > 0:
            print(f'[{get_current_time()}][!] 无效记录: {invalid_count} 个')

        return valid_cnvds

    except FileNotFoundError:
        print(f'[{get_current_time()}][!] 文件不存在: {csv_file}')
        return []
    except Exception as e:
        print(f'[{get_current_time()}][!] 读取CSV文件出错: {e}')
        return []


def download_cnvd_detail(cnvd_id, client, output_dir='CNVD'):
    """下载单个CNVD详情"""
    import time

    try:
        # 检查本地是否已存在
        if os.path.exists(f"{output_dir}/{cnvd_id}.json"):
            print(f'[{get_current_time()}][→] {cnvd_id} - 本地文件已存在')
            return True, "本地已存在"

        # 等待
        wait_time = random.randint(2, 5)
        print(f'[{get_current_time()}][↓] {cnvd_id} - 等待 {wait_time} 秒后下载')
        time.sleep(wait_time)

        # 请求详情页
        url = f'https://www.cnvd.org.cn/flaw/show/{cnvd_id}'
        try:
            client.page.goto(url, timeout=60000)
            # 等待内容加载，可以加一些 wait_for_selector
            client.page.wait_for_load_state("domcontentloaded")
            content = client.page.content()
            title = client.page.title()
            
            # 检测是否是验证码页面
            # CNVD 的验证码页面特征可能包含 '验证码'、'安全检查' 等
            # 或者如果没找到正常的详情页元素，比如 '漏洞信息详情'
            if "创宇盾" in content and "可疑的攻击行为" in content:
                print(f'[{get_current_time()}][!] 检测到创宇盾拦截: 您的IP最近有可疑的攻击行为')
                return False, "IP被拦截"

            if "验证码" in title or "安全检查" in title or "请输入验证码" in content or "疑似攻击" in content or "403 Forbidden" in title:
                 print(f'\n[{get_current_time()}][!] 检测到验证码，尝试自动识别...')
                 
                 for retry in range(3):
                     print(f"[{get_current_time()}] 第 {retry+1} 次尝试自动识别...")
                     try:
                         if client.solve_captcha():
                             client.page.wait_for_timeout(3000)
                             
                             try:
                                 title = client.page.title()
                                 content = client.page.content()
                                 if "验证码" not in title and "安全检查" not in title and "请输入验证码" not in content:
                                     print(f"[{get_current_time()}] 自动识别成功！")
                                     break
                             except:
                                 pass
                             
                             print(f"[{get_current_time()}] 似乎未通过，刷新验证码重试...")
                             client.refresh_captcha()
                         else:
                             print(f"[{get_current_time()}] 识别过程失败，刷新验证码重试...")
                             client.refresh_captcha()
                     except Exception as e:
                         print(f"自动识别出错: {e}")
                         client.refresh_captcha()

                 # 检查是否已通过
                 try:
                     client.page.wait_for_load_state("domcontentloaded", timeout=5000)
                     title = client.page.title()
                     content = client.page.content()
                 except:
                     pass

                 if "验证码" not in title and "安全检查" not in title and "请输入验证码" not in content:
                      print(f"[{get_current_time()}] 自动识别成功或已跳过，继续...")
                 else:
                      print(f'[{get_current_time()}][!] 验证未通过，请手动完成...')
                      # 循环等待直到用户处理完毕（页面不再是验证码页面）
                      while True:
                          # 简单的等待用户按回车可能会阻塞太久，不如每隔几秒检查一下
                          # 这里还是用 input 阻塞比较稳妥，让用户明确告知已完成
                          input(f"[{get_current_time()}] 在浏览器中完成验证后，请按回车继续...")
                          
                          # 刷新页面或重新获取内容
                          # 用户可能在浏览器里已经跳转回去了，或者还在验证码页
                          # 我们假设用户处理完验证码后，页面会自动跳转或用户手动刷新到了详情页
                          # 为了保险，我们重新 reload 一下当前页，或者如果 URL 变了就不用 reload
                          
                          # 获取当前 URL
                          current_url = client.page.url
                          if cnvd_id not in current_url:
                              # 如果当前不在详情页，尝试重新跳转
                              print(f"[{get_current_time()}] 尝试重新跳转到详情页...")
                              client.page.goto(url, timeout=60000)
                          else:
                              client.page.reload()
                          
                          client.page.wait_for_load_state("domcontentloaded")
                          content = client.page.content()
                          title = client.page.title()
                          
                          if "验证码" not in title and "安全检查" not in title and "请输入验证码" not in content:
                              print(f"[{get_current_time()}] 验证似乎已通过，继续...")
                              break
                          else:
                              print(f"[{get_current_time()}] 似乎仍未通过验证，请重试...")

        except Exception as e:
            print(f'[{get_current_time()}][!] {cnvd_id} - 页面请求失败: {e}')
            return False, f"页面请求失败: {e}"

        # 检查是否有内容
        if not content or len(content) < 500:
            print(f'[{get_current_time()}][!] {cnvd_id} - 页面内容过短或为空 ({len(content)} bytes)')
            # 尝试刷新一次
            print(f'[{get_current_time()}][!] 尝试刷新页面...')
            client.page.reload()
            client.page.wait_for_load_state("domcontentloaded")
            client.page.wait_for_timeout(3000)
            content = client.page.content()
            
            if not content or len(content) < 500:
                print(f'[{get_current_time()}][!] 刷新后仍然无效，保存调试文件...')
                with open(f"detail_fail_{cnvd_id}.html", "w", encoding="utf-8") as f:
                    f.write(content)
                return False, "页面内容为空"

        if '您访问的页面不存在' in content or '页面未找到' in content or 'Not Found' in content:
            print(f'[{get_current_time()}][!] {cnvd_id} - 页面不存在')
            return False, "页面不存在"

        # 解析并保存
        os.makedirs(output_dir, exist_ok=True)
        resp_html = etree.HTML(content)
        item = get_data(resp_html, url)

        # 验证是否成功解析
        if not item.get('cnvd'):
            print(f'[{get_current_time()}][!] {cnvd_id} - 解析失败，未获取到CNVD-ID')
            # 有可能是反爬导致页面没加载出来，打印一下标题看看
            title = client.page.title()
            print(f'[{get_current_time()}][!] 页面标题: {title}')
            
            # 保存失败的HTML以便调试
            with open(f"detail_parse_fail_{cnvd_id}.html", "w", encoding="utf-8") as f:
                f.write(content)
                
            return False, "解析失败"

        with open(f"{output_dir}/{cnvd_id}.json", "w", encoding='utf8') as f:
            json.dump(item, f, ensure_ascii=False, indent=4)

        print(f'[{get_current_time()}][✓] {cnvd_id} - 下载成功')
        return True, "下载成功"

    except Exception as e:
        print(f'[{get_current_time()}][✗] {cnvd_id} - 下载失败: {e}')
        return False, str(e)


def crawl_from_csv(csv_file, db_url, proxy=None, check_db=True, batch_size=100, output_dir='CNVD'):
    """
    从CSV文件读取CNVD编号并下载

    Args:
        csv_file: CSV文件路径
        db_url: 数据库连接URL
        proxy: 代理配置
        check_db: 是否检查数据库
        batch_size: 批量查询数据库的大小
        output_dir: 输出目录
    """
    import time

    print(f'\n[{get_current_time()}][+] ========== 从CSV文件批量下载CNVD ==========\n')

    # 读取CSV
    cnvd_list = read_cnvd_from_csv(csv_file)
    if not cnvd_list:
        print(f'[{get_current_time()}][!] 没有找到有效的CNVD编号')
        return

    # 去重
    cnvd_list = list(set(cnvd_list))
    print(f'[{get_current_time()}][+] 去重后共 {len(cnvd_list)} 个唯一CNVD编号\n')

    # 检查数据库
    need_download = []
    if check_db:
        print(f'[{get_current_time()}][+] 开始检查数据库...')
        try:
            db = CNVDDatabase(db_url)

            # 批量查询
            exists_in_db = set()
            for i in range(0, len(cnvd_list), batch_size):
                batch = cnvd_list[i:i + batch_size]
                exists_batch = db.batch_check_cnvd_exists(batch)
                exists_in_db.update(exists_batch)
                print(f'[{get_current_time()}][+] 已检查 {min(i + batch_size, len(cnvd_list))}/{len(cnvd_list)}')

            db.close()

            # 筛选需要下载的
            for cnvd_id in cnvd_list:
                if cnvd_id not in exists_in_db:
                    need_download.append(cnvd_id)

            print(f'[{get_current_time()}][+] 数据库中已存在: {len(exists_in_db)} 个')
            print(f'[{get_current_time()}][+] 需要下载: {len(need_download)} 个\n')

        except Exception as e:
            print(f'[{get_current_time()}][!] 数据库操作失败: {e}')
            print(f'[{get_current_time()}][+] 将下载所有CNVD\n')
            need_download = cnvd_list
    else:
        need_download = cnvd_list
        print(f'[{get_current_time()}][+] 跳过数据库检查，直接下载所有CNVD\n')

    if not need_download:
        print(f'[{get_current_time()}][+] 所有CNVD都已存在于数据库，无需下载')
        return

    # 初始化浏览器客户端
    print(f'[{get_current_time()}][+] 初始化浏览器...')
    # headless=False 允许手动处理验证码
    client = CNVDBrowserClient(headless=False)
    client.start()
    
    try:
        # 预先访问一次首页，确保能打开，用户可以趁机处理下验证
        print(f'[{get_current_time()}][+] 预热浏览器，访问首页...')
        try:
            client.ensure_clearance()
        except Exception:
            # 如果 ensure_clearance 失败（例如超时等待用户输入），也不要紧，继续后面的流程
            pass
            
        print(f'[{get_current_time()}][+] 准备开始下载，如果在过程中遇到验证码，请在浏览器中手动处理...')

        # 统计
        success_count = 0
        failed_count = 0
        skip_count = 0
        failed_list = []
        need_download = sorted(need_download)
        
        # 开始下载
        for idx, cnvd_id in enumerate(need_download, 1):
            print(
                f'\n[{get_current_time()}][+] ===== 进度: {idx}/{len(need_download)} ({idx * 100 // len(need_download)}%) =====')
            if os.path.exists(
                    f'{output_dir}/{cnvd_id}.json'
            ):
                skip_count += 1
                print(f'[{get_current_time()}][✓] {cnvd_id} - 本地已存在，跳过')
                continue
                
            # 使用 client 下载
            success, reason = download_cnvd_detail(cnvd_id, client, output_dir)

            if success:
                if reason == "本地已存在":
                    skip_count += 1
                else:
                    success_count += 1
            else:
                failed_count += 1
                failed_list.append((cnvd_id, reason))
                
            time.sleep(random.randint(5, 8))
            # 每10个等待一下
            if idx % 10 == 0 and idx < len(need_download):
                wait_time = random.randint(10, 20)
                print(f'\n[{get_current_time()}][+] 已处理 {idx} 个，等待 {wait_time} 秒...')
                time.sleep(wait_time)

    except Exception as e:
        print(f'[{get_current_time()}][!] 发生错误: {e}')
        import traceback
        traceback.print_exc()
    finally:
        print(f'[{get_current_time()}][+] 关闭浏览器...')
        client.stop()

    # 输出统计

    # 输出统计
    print(f'\n\n[{get_current_time()}][+] ========== 下载完成 ==========')
    print(f'[{get_current_time()}][+] 总CNVD数: {len(cnvd_list)}')
    if check_db:
        print(f'[{get_current_time()}][+] 数据库已存在: {len(cnvd_list) - len(need_download)}')
    print(f'[{get_current_time()}][+] 需要下载: {len(need_download)}')
    print(f'[{get_current_time()}][+] 下载成功: {success_count}')
    print(f'[{get_current_time()}][+] 本地已存在: {skip_count}')
    print(f'[{get_current_time()}][+] 下载失败: {failed_count}')

    # 保存失败列表
    if failed_list:
        print(f'\n[{get_current_time()}][!] 以下CNVD下载失败:')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        failed_file = f'failed_cnvd_{timestamp}.txt'
        with open(failed_file, 'w', encoding='utf-8') as f:
            f.write(f'下载时间: {get_current_time()}\n')
            f.write(f'失败数量: {len(failed_list)}\n\n')
            for cnvd_id, reason in failed_list:
                print(f'  - {cnvd_id}: {reason}')
                f.write(f'{cnvd_id}\t{reason}\n')
        print(f'[{get_current_time()}][+] 失败列表已保存到: {failed_file}')


def parse_cnvd_list(html_content):
    """解析CNVD列表页，提取CNVD编号和日期"""
    soup = BeautifulSoup(html_content, 'lxml')
    items = []
    
    for tr in soup.find_all('tr'):
        # 通过链接获取CNVD ID，比纯文本更准确
        a_tag = tr.find('a', href=re.compile(r'/flaw/show/CNVD-\d+-\d+'))
        
        if a_tag:
            href = a_tag['href']
            # 提取ID
            cnvd_id = href.split('/')[-1]
            # 有些链接可能带有额外参数，清理一下
            if '?' in cnvd_id:
                cnvd_id = cnvd_id.split('?')[0]
            
            # 在同一行查找日期
            text = tr.get_text(" ", strip=True)
            date_match = re.search(r'\d{4}-\d{2}-\d{2}', text)
            date = date_match.group(0) if date_match else "Unknown"
            
            items.append({
                'cnvd_id': cnvd_id,
                'date': date
            })
            
    # 去重
    unique_items = []
    seen = set()
    for item in items:
        if item['cnvd_id'] not in seen:
            unique_items.append(item)
            seen.add(item['cnvd_id'])
            
    return unique_items


def crawl_todays_cnvds(db_url, output_dir='CNVD'):
    """
    获取当天的CNVD详情
    流程：
    1. 访问指定页面 (CNVD-2026-00713) 并通过验证码
    2. 访问列表页获取前100条
    3. 筛选当天的记录
    4. 下载详情
    """
    import time
    print(f'\n[{get_current_time()}][+] ========== 开始获取当天CNVD数据 ==========\n')
    
    # 初始化浏览器
    client = CNVDBrowserClient(headless=False, proxy="192.168.110.12:11111")
    client.start()
    
    try:
        # 跳过列表抓取，直接加载本地列表文件
        print(f'[{get_current_time()}][+] 跳过列表抓取，直接加载本地列表文件...')
        list_file = "cnvd_list_20260203_155354.json"
        with open(list_file, "r", encoding="utf-8") as f:
            cnvd_items = json.load(f)
        print(f'[{get_current_time()}][+] 已加载 {len(cnvd_items)} 条记录')
        
        # 3. 直接获取所有记录 (不再筛选日期)
        target_cnvds = [item['cnvd_id'] for item in cnvd_items]
        print(f'[{get_current_time()}][+] 目标记录数: {len(target_cnvds)}')
        
        for item in cnvd_items[:5]: # 打印前5个看看日期
            print(f"  - {item['cnvd_id']}: {item['date']}")
            
        if not target_cnvds:
            print(f'[{get_current_time()}][!] 没有找到记录，程序结束')
            pass 
            
        # 4. 下载详情
        if target_cnvds:
            print(f'[{get_current_time()}][+] 步骤3: 开始下载 {len(target_cnvds)} 条详情...')
            success_count = 0
            for i, cnvd_id in enumerate(target_cnvds, 1):
                print(f'\n[{get_current_time()}][+] 处理 {i}/{len(target_cnvds)}: {cnvd_id}')
                success, reason = download_cnvd_detail(cnvd_id, client, output_dir)
                
                if not success and reason == "IP被拦截":
                    print(f'[{get_current_time()}][!] IP被拦截，休眠2分钟...')
                    time.sleep(120)
                    continue
                    
                if success:
                    success_count += 1
                # 稍微等待一下，避免太快
                time.sleep(random.randint(3, 6))
            print(f'\n[{get_current_time()}][+] 任务完成，成功下载: {success_count}/{len(target_cnvds)}')
        
    except Exception as e:
        print(f'[{get_current_time()}][!] 发生错误: {e}')
        import traceback
        traceback.print_exc()
    finally:
        print(f'[{get_current_time()}][+] 关闭浏览器...')
        client.stop()


def main():

    print(f'[{get_current_time()}][+] 开始处理...')
    # 配置代理
    try:
        # 使用新的流程
        crawl_todays_cnvds(
            db_url='mysql+pymysql://root:8ik,lp-=@192.168.110.15:3306/new_vuln_data',
            output_dir='CNVD'
        )
        
        # 原有的CSV流程（已注释）
        # crawl_from_csv(
        #     csv_file='vuln_cnvd_id.csv',
        #     db_url='mysql+pymysql://root:8ik,lp-=@192.168.110.15:3306/new_vuln_data',
        #     check_db=True,
        #     batch_size=100,
        #     output_dir='CNVD'
        # )
    except KeyboardInterrupt:
        print(f'\n[{get_current_time()}][!] 用户中断，程序退出')
    except Exception as e:
        print(f'\n[{get_current_time()}][!] 程序异常: {e}')
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()

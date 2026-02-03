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


def cnvd_jsl(url, params, proxies, cookies):
    """处理CNVD的JSL验证"""
    r = request_cnvd(url, params, proxies, cookies)

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

    elif r.status_code == 404:
        next_time = random.randint(60, 120)
        print(f'[{get_current_time()}][!] IP被封禁，等待{next_time}秒')
        sleep(next_time)
        return cnvd_jsl(url, params=params, proxies=proxies, cookies=cookies)

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
    item["name"] = name_list[0] if name_list else None

    # CNVD-ID
    cnvd_list = data_html.xpath('//tbody//td[contains(text(),"CNVD-ID")]/following-sibling::td//text()')
    cnvd_list = replace_list(cnvd_list)
    item["cnvd"] = cnvd_list[0] if cnvd_list else None

    # 公开日期
    publish_list = data_html.xpath('//tbody//td[contains(text(),"公开日期")]/following-sibling::td//text()')
    publish_list = replace_list(publish_list)
    item["publish"] = publish_list[0] if publish_list else None

    # 危害级别和CVSS
    severity_and_cvss_list = data_html.xpath('//tbody//td[contains(text(),"危害级别")]/following-sibling::td//text()')
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
    flaw_type_list = replace_list(flaw_type_list)
    item["flaw_type"] = flaw_type_list[0].strip() if flaw_type_list else None

    # 参考链接
    reference_list = data_html.xpath('//tbody//td[contains(text(),"参考链接")]/following-sibling::td//text()')
    reference_list = replace_list(reference_list)
    item["reference"] = "\n".join(reference_list).strip() if reference_list else None

    # 漏洞解决方案
    solution_list = data_html.xpath('//tbody//td[contains(text(),"漏洞解决方案")]/following-sibling::td//text()')
    solution_list = replace_list(solution_list)
    solution = None
    if solution_list:
        solution = "\n".join(solution_list)
        if solution.strip().startswith("http"):
            solution = "厂商已发布了漏洞修复程序，请及时关注更新：" + solution_list[0].strip()
    item["solution"] = solution

    # 厂商补丁
    patch_list = data_html.xpath('//tbody//td[contains(text(),"厂商补丁")]/following-sibling::td//text()')
    patch_list = replace_list(patch_list)
    item["patch"] = patch_list[0].strip() if patch_list else None

    # 验证信息
    verify_list = data_html.xpath('//tbody//td[contains(text(),"验证信息")]/following-sibling::td//text()')
    verify_list = replace_list(verify_list)
    item["verify"] = verify_list[0].strip() if verify_list else None

    # 报送时间
    submit_time_list = data_html.xpath('//tbody//td[contains(text(),"报送时间")]/following-sibling::td//text()')
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


def download_cnvd_detail(cnvd_id, proxy, cookies, output_dir='CNVD'):
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
        r, cookies = cnvd_jsl(f'https://www.cnvd.org.cn/flaw/show/{cnvd_id}',
                              params={}, proxies=proxy, cookies=cookies)

        # 检查是否成功
        if r.status_code != 200:
            print(f'[{get_current_time()}][!] {cnvd_id} - 请求失败，状态码: {r.status_code}')
            return False, f"状态码 {r.status_code}"

        # 检查是否有内容
        if '您访问的页面不存在' in r.text or '页面未找到' in r.text or 'Not Found' in r.text:
            print(f'[{get_current_time()}][!] {cnvd_id} - 页面不存在')
            return False, "页面不存在"

        # 解析并保存
        os.makedirs(output_dir, exist_ok=True)
        resp_html = etree.HTML(r.text)
        item = get_data(resp_html, f'https://www.cnvd.org.cn/flaw/show/{cnvd_id}')

        # 验证是否成功解析
        if not item.get('cnvd'):
            print(f'[{get_current_time()}][!] {cnvd_id} - 解析失败，未获取到CNVD-ID')
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

    # 配置代理
    if proxy is None:
        proxy = {
            "http": "http://192.168.60.78:7897",
            "https": "http://192.168.60.78:7897",
        }

    # 初始化cookies
    print(f'[{get_current_time()}][+] 初始化Cookie...')
    cookies = {}
    params = {'flag': True, 'numPerPage': 100, 'offset': 0, 'max': 100}
    r1, cookies = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)

    retry_init = 0
    while r1.text.find(';location.href=location.pathname+location.search') != -1:
        retry_init += 1
        if retry_init > 10:
            print(f'[{get_current_time()}][!] Cookie初始化失败，退出')
            return
        wait_time = random.randint(3, 8)
        print(f'[{get_current_time()}][+] 等待 {wait_time} 秒后重试初始化')
        sleep(wait_time)
        r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)

    print(f'[{get_current_time()}][+] Cookie初始化成功\n')
    print(f'[{get_current_time()}][+] 开始下载...\n')

    # 统计
    success_count = 0
    failed_count = 0
    skip_count = 0
    failed_list = []

    # 开始下载
    for idx, cnvd_id in enumerate(need_download, 1):
        print(
            f'\n[{get_current_time()}][+] ===== 进度: {idx}/{len(need_download)} ({idx * 100 // len(need_download)}%) =====')

        success, reason = download_cnvd_detail(cnvd_id, proxy, cookies, output_dir)

        if success:
            if reason == "本地已存在":
                skip_count += 1
            else:
                success_count += 1
        else:
            failed_count += 1
            failed_list.append((cnvd_id, reason))

        # 每10个等待一下
        if idx % 10 == 0 and idx < len(need_download):
            wait_time = random.randint(10, 20)
            print(f'\n[{get_current_time()}][+] 已处理 {idx} 个，等待 {wait_time} 秒...')
            time.sleep(wait_time)

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


def main():
    parser = argparse.ArgumentParser(
        description='CNVD漏洞数据批量下载工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python cnvd_csv_downloader.py --csv cnvd_list.csv
  python cnvd_csv_downloader.py --csv cnvd_list.csv --proxy http://127.0.0.1:7890
  python cnvd_csv_downloader.py --csv cnvd_list.csv --no-db-check
  python cnvd_csv_downloader.py --csv cnvd_list.csv --output /data/cnvd
        """
    )

    parser.add_argument('--csv', type=str, required=True, help='包含CNVD编号的CSV文件路径')
    parser.add_argument('--db-url', type=str,
                        default='mysql+pymysql://root:8ik,lp-=@192.168.110.15:3306/new_vuln_data',
                        help='数据库连接URL')
    parser.add_argument('--proxy', type=str, help='代理地址，格式: http://ip:port')
    parser.add_argument('--no-db-check', action='store_true', help='跳过数据库检查，直接下载所有CNVD')
    parser.add_argument('--output', type=str, default='CNVD', help='输出目录，默认为CNVD')
    parser.add_argument('--batch-size', type=int, default=100, help='批量查询数据库的大小，默认100')

    args = parser.parse_args()
    print(f'[{get_current_time()}][+] 开始处理 {args.csv}...')
    # 配置代理
    try:
        crawl_from_csv(
            csv_file=args.csv,
            db_url=args.db_url,
            proxy=args.proxy,
            check_db=not args.no_db_check,
            batch_size=args.batch_size,
            output_dir=args.output
        )
    except KeyboardInterrupt:
        print(f'\n[{get_current_time()}][!] 用户中断，程序退出')
    except Exception as e:
        print(f'\n[{get_current_time()}][!] 程序异常: {e}')
        import traceback
        traceback.print_exc()

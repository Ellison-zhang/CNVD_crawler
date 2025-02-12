import re
import os
import json
import html
import execjs
import requests
import hashlib
import random

from time import sleep
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()
from lxml import etree
from datetime import datetime


def get_current_time():
    # 获取当前时间并格式化时间
    return datetime.now().strftime("%Y/%m/%d %H:%M:%S")


def get_jsl_clearance_s(jsl_data):
    chars = len(jsl_data['chars'])
    for i in range(chars):
        for j in range(chars):
            jsl_clearance_s = jsl_data['bts'][0] + jsl_data['chars'][i:(i + 1)] + jsl_data['chars'][j:(j + 1)] + \
                              jsl_data['bts'][1]
            if getattr(hashlib, jsl_data['ha'])(jsl_clearance_s.encode('utf-8')).hexdigest() == jsl_data['ct']:
                # print('get_jsl_clearance_s结果为：',jsl_clearance_s)
                return jsl_clearance_s


def request_cnvd(url, params, proxies, cookies):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36', }
        return requests.get(url, params=params, cookies=cookies, headers=headers, proxies=proxies, verify=False, )
    except requests.exceptions.SSLError as e:
        print(f'[{get_current_time()}][!] 请求失败，错误信息为：', e)
        with open('error.txt', 'w', encoding='utf-8') as f:
            f.write(str(e) + '\n\n')
        print(f'[{get_current_time()}][!] 等待60秒后重试')
        sleep(60)
        return request_cnvd(url, params, proxies, cookies)


def cnvd_jsl(url, params, proxies, cookies):
    r = request_cnvd(url, params, proxies, cookies)
    if r.status_code == 521:
        if re.findall('document.cookie=(.*?);location.', r.text):
            # print('jsl_1')
            cookies = r.cookies.get_dict()
            __jsl_clearance_s = \
            execjs.eval(re.findall('document.cookie=(.*?);location.', r.text)[0]).split(';')[0].split('=')[1]
            cookies['__jsl_clearance_s'] = __jsl_clearance_s
            r = request_cnvd(url, params, proxies, cookies)
            # print(r.text[::100])
            jsl_data = None
            if r.text.find(';location.href=location.pathname+location.search') != -1:
                '''<script>document.cookie=('_')+('_')+('j')+('s')+('l')+('_')+('c')+('l')+('e')+('a')+('r')+('a')+('n')+('c')+('e')+('_')+('s')+('=')+(-~{}+'')+(7+'')+(3+'')+(1+[0]-(1)+'')+((1<<1)+'')+(1+4+'')+(1+[0]-(1)+'')+(-~(8)+'')+(-~(4)+'')+(2+4+'')+('.')+(-~[7]+'')+((2)*[2]+'')+((2)*[4]+'')+('|')+('-')+(-~[]+'')+('|')+('e')+('X')+('s')+('w')+('h')+('Y')+('L')+('c')+('w')+('K')+('%')+(1+1+'')+('F')+('r')+('A')+('%')+(+!+[]*2+'')+('B')+('E')+('k')+('D')+('T')+('h')+('m')+('K')+('d')+('R')+('t')+('M')+('V')+(3+5+'')+('%')+((2^1)+'')+('D')+(';')+(' ')+('M')+('a')+('x')+('-')+('a')+('g')+('e')+('=')+(-~[2]+'')+(6+'')+(~~false+'')+((+[])+'')+(';')+(' ')+('P')+('a')+('t')+('h')+('=')+('/')+(';')+(' ')+('S')+('a')+('m')+('e')+('S')+('i')+('t')+('e')+('=')+('N')+('o')+('n')+('e')+(';')+(' ')+('S')+('e')+('c')+('u')+('r')+('e');location.href=location.pathname+location.search</script>
                直接执行设置cookie
                '''
                # print('jsl_1_1')
                js_code = r.text.replace('<script>document.cookie=', '').replace(
                    ';location.href=location.pathname+location.search</script>', '')
                js_code = execjs.eval(js_code).split(';')[0].split('=')[1]
                # print(js_code)
                cookies['__jsl_clearance_s'] = js_code

            else:
                # print('jsl_1_2')
                # print(r.text)
                try:
                    jsl_data = json.loads(re.findall('go\((\{.*?\})\)', r.text)[0])
                except Exception as e:
                    # 创宇盾页面
                    print(f'[{get_current_time()}][!] 获取jsl_data失败，错误信息为：', e)
                    print(f'[{get_current_time()}][!] 当前页面内容为：', r.text)
                    with open('error.html', 'w', encoding='utf-8') as f:
                        f.write(r.text + '\n\n\n\n\n\n\n\n\n\n\n\n\n')
                    print(f'[{get_current_time()}][!] 等待60秒后重试')
                    sleep(60)
                    return cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxies,
                                    cookies=cookies)
                # print(jsl_data)
                cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            # print('当前cookie是',cookies)
            r = request_cnvd(url, params, proxies, cookies)
        if re.findall('go\((\{.*?\})\)', r.text):
            # print('jsl_2')
            jsl_data = json.loads(re.findall('go\((\{.*?\})\)', r.text)[0])
            cookies[jsl_data['tn']] = get_jsl_clearance_s(jsl_data)
            r = request_cnvd(url, params, proxies, cookies)
    elif r.status_code == 403:
        next_time = random.randint(60, 120)
        print(f'[{get_current_time()}][!] 检测到疑似攻击行为，等待{next_time}秒后重试')
        sleep(next_time)
        return cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxies, cookies=cookies)
    elif r.status_code == 404:
        next_time = random.randint(60, 120)
        print(f'[{get_current_time()}][!] 当前IP已被封禁，等到{next_time}秒后重试')
        sleep(next_time)
        return cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxies, cookies=cookies)
    else:
        print(f'[{get_current_time()}][+] 其他状态码：', r.status_code)
    return r, cookies


def get_current_vul_count(page):
    '''获取当前漏洞总数'''
    soup = BeautifulSoup(page, 'html.parser')
    # 拿到表足的所有span
    pages_div = soup.find('div', class_='pages clearfix')
    if pages_div:
        spans = pages_div.find_all('span')
        pattern = r'共\s*(\d+)\s*条'
        # 提取数字
        for span in spans:
            count = re.search(pattern, span.text)
            if count:
                return int(count.group(1))
    else:
        return None


def get_cnvd(page) -> list[str]:
    '''获取table下的所有cnvd'''
    result_list = []
    soup = BeautifulSoup(page, 'html.parser')
    table = soup.find('table', class_='tlist')
    if table:
        trs = table.find('tbody').find_all('tr')
        for tr in trs:
            # 获取a标签的href
            a = tr.find('a')
            if a:
                result_list.append(a['href'].replace('/flaw/show/', ''))
            else:
                raise Exception('未找到a标签或a标签href值为空')
    return result_list


def write_to_file(data: list):
    with open('cnvd.txt', 'a', encoding='utf-8') as f:
        for d in data:
            f.write(f'{d}\n')
        f.flush()


import time


def replace_list(data_list: list) -> list:
    result_list = []
    for data in data_list:
        data = data.strip()
        if data == "" or data is None:
            pass
        else:
            result_list.append(data)
    return result_list


def get_data(data_html, url):
    day = time.strftime("%Y-%m-%d %H:%M:%S")
    spider_time = int(time.time() * 1000)
    item = {
        "parse_time": day,
        "path": url,
        "spider_time": spider_time
    }
    name = None
    cnvd = None
    publish = None
    severity = None
    cvss_vector = None
    product = None
    description = None
    flaw_type = None
    reference = None
    solution = None
    patch = None
    verify = None
    submit_time = None
    open_time = None
    update_time = None
    cve = None
    name_list = data_html.xpath('//div[@class="blkContainerSblk"]//h1/text()')

    # 有cve和没有cve的html标签是不一样的
    if name_list:
        name = name_list[0]
    item["name"] = name

    #
    cnvd_list = data_html.xpath('//tbody//td[contains(text(),"CNVD-ID")]/following-sibling::td//text()')
    cnvd_list = replace_list(cnvd_list)
    if cnvd_list:
        cnvd = cnvd_list[0]
    item["cnvd"] = cnvd

    publish_list = data_html.xpath('//tbody//td[contains(text(),"公开日期")]/following-sibling::td//text()')
    publish_list = replace_list(publish_list)
    if publish_list:
        publish = publish_list[0]
    item["publish"] = publish
    # 危害级别
    severity_and_cvss_list = data_html.xpath('//tbody//td[contains(text(),"危害级别")]/following-sibling::td//text()')
    severity_and_cvss_list = replace_list(severity_and_cvss_list)
    if severity_and_cvss_list:
        severity = severity_and_cvss_list[0][0]
        try:
            cvss_vector = severity_and_cvss_list[1]
        except:
            pass

    item["severity"] = severity
    item["cvss_vector"] = cvss_vector

    product_list = data_html.xpath('//tbody//td[contains(text(),"影响产品")]/following-sibling::td//text()')
    product_list = replace_list(product_list)
    if product_list:
        product = product_list
    item["product"] = json.dumps(product)

    # 另一套脚本
    cve_list = data_html.xpath('//td[contains(text(),"CVE ID")]/following-sibling::td//text()')

    cve_list = replace_list(cve_list)
    if cve_list:
        cve = cve_list[0]
        cve = cve.strip()
    item["cve"] = cve

    description_list = data_html.xpath('//td[contains(text(),"漏洞描述")]/following-sibling::td//text()')
    description_list = replace_list(description_list)
    if description_list:
        description = "".join(description_list)
        description = description.strip()
    item["description"] = description

    # 漏洞类型
    flaw_type_list = data_html.xpath('//tbody//td[contains(text(),"漏洞类型")]/following-sibling::td//text()')
    flaw_type_list = replace_list(flaw_type_list)
    if flaw_type_list:
        flaw_type = flaw_type_list[0]
        flaw_type = flaw_type.strip()
    item["flaw_type"] = flaw_type

    #  注意一下可能有多个的,以json格式存储
    reference_list = data_html.xpath('//tbody//td[contains(text(),"参考链接")]/following-sibling::td//text()')
    reference_list = replace_list(reference_list)

    if reference_list:
        reference = "\n".join(reference_list)
        reference = reference.strip()
    item["reference"] = reference

    # 修复建议链接
    solution_list = data_html.xpath('//tbody//td[contains(text(),"漏洞解决方案")]/following-sibling::td//text()')
    solution_list = replace_list(solution_list)
    if solution_list:
        solution = "\n".join(solution_list)
        if solution.strip().startswith("http"):
            solution = solution_list[0]
            solution = solution.strip()
            solution = "厂商已发布了漏洞修复程序，请及时关注更新：" + solution
    item["solution"] = solution

    # 补丁名称
    patch_list = data_html.xpath('//tbody//td[contains(text(),"厂商补丁")]/following-sibling::td//text()')
    patch_list = replace_list(patch_list)
    if patch_list:
        patch = patch_list[0]
        patch = patch.strip()
    item["patch"] = patch

    # 验证信息
    verify_list = data_html.xpath('//tbody//td[contains(text(),"验证信息")]/following-sibling::td//text()')
    verify_list = replace_list(verify_list)
    if verify_list:
        verify = verify_list[0]
        verify = verify.strip()

    item["verify"] = verify

    # 报送时间
    submit_time_list = data_html.xpath('//tbody//td[contains(text(),"报送时间")]/following-sibling::td//text()')
    submit_time_list = replace_list(submit_time_list)
    if submit_time_list:
        submit_time = submit_time_list[0]
    item["submit_time"] = submit_time

    # 公开时间
    open_time_list = data_html.xpath('//td[contains(text(),"收录时间")]/following-sibling::td//text()')
    open_time_list = replace_list(open_time_list)
    if open_time_list:
        open_time = open_time_list[0]
    item["open_time"] = open_time

    update_time_list = data_html.xpath('//tbody/tr[13]/td[2]//text()')
    update_time_list = replace_list(update_time_list)
    if update_time_list:
        update_time = update_time_list[0]
    item["update_time"] = update_time
    # data_summary这个得生成
    summary_item = {}
    for k, v in item.items():
        if v is None:
            summary_item[f"{k}"] = ""
        else:
            summary_item[f"{k}"] = v
    data_str = summary_item["path"] + summary_item["cnvd"] + summary_item["cve"] + summary_item["name"] + \
               summary_item["severity"] + summary_item[
                   "product"] + summary_item["flaw_type"] + summary_item["submit_time"] + summary_item["publish"] + \
               summary_item["reference"] + summary_item[
                   "solution"] + summary_item["patch"] + summary_item["description"]
    data_summary = hashlib.md5(data_str.encode("utf-8")).hexdigest()
    item["data_summary"] = data_summary

    return item


def main():
    proxy = {
    }
    page = 0
    size = 100
    cookies = {}
    params = {'flag': True, 'numPerPage': size, 'offset': page * size, 'max': size}
    r1, cookies = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
    while r1.text.find(';location.href=location.pathname+location.search') != -1:
        # 页面不对，重新请求
        next_time = random.randint(3, 8)
        print(f'[{get_current_time()}][+]初始化中，等待{next_time}秒后重定向页面')
        sleep(next_time)
        r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
    # print('循环外查询到页面内容，html为：' , r1.text[:50])
    # print('循环外当前cookie是：',cookies,'\n')
    # 获取漏洞总数
    vul_count = get_current_vul_count(r1.content)
    if not vul_count:
        next_time = random.randint(3, 8)
        print(f'[{get_current_time()}][!]获取漏洞总数失败，等待{next_time}秒后重试')
        return main()
    print(f'[{get_current_time()}][+] 获取到漏洞总数：{vul_count}')
    # 每页100 先用总数除以100 然后+1得到循环次数 每次请求页面设置offset为100的倍数
    print(f'[{get_current_time()}][+] cookie设置完成，开始获取漏洞信息')
    size = 50
    i = 0
    next_time = random.randint(5, 10)
    print(f'[{get_current_time()}][+] 等待{next_time}秒后进行下一次cnvd获取')
    sleep(next_time)
    print(f'[{get_current_time()}][+] 开始获取第{i + 1}页，每页{size}个漏洞')
    params = {'flag': True, 'numPerPage': size, 'offset': i * size, 'max': size}
    r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
    # print('循环内查询到页面内容，html为：' , r1.text[:50])
    while r1.text.find(';location.href=location.pathname+location.search') != -1:
        # 页面不对，重新请求
        retry_time = random.randint(3, 8)
        print(f'[{get_current_time()}][!] 等待{retry_time}秒后重定向页面')
        sleep(retry_time)
        r1, _ = cnvd_jsl("https://www.cnvd.org.cn/flaw/list", params=params, proxies=proxy, cookies=cookies)
        # print('循环内<再次>查询到页面内容，html为：' , r1.text[:50])
    if '<table class="tlist">' in r1.text:
        cnvd_ids = get_cnvd(r1.content)
        print(f'[{get_current_time()}][+] 获取到漏洞{len(cnvd_ids)}个，原始数据为：\n{cnvd_ids}')
        for cvnd_id in cnvd_ids:
            try:
                next_time = random.randint(2, 5)
                print(f'[{next_time}][+] 等待{next_time}秒后进行下一次cnvd获取:{cvnd_id}')
                time.sleep(next_time)
                r, cookies = cnvd_jsl(f'https://www.cnvd.org.cn/flaw/show/{cvnd_id}', params={}, proxies={},
                                      cookies=cookies)
                os.makedirs('CNVD', exist_ok=True)
                resp = r.text
                resp_html = etree.HTML(resp)
                item = get_data(resp_html, f'https://www.cnvd.org.cn/flaw/show/{cvnd_id}')
                with open(f"CNVD/{cvnd_id}.json", "w", encoding='utf8') as f:
                    json.dump(item, f, ensure_ascii=False, indent=4)
            except Exception as e:
                print(
                    f'{cvnd_id=} error, error message: {e}'
                )


if __name__ == '__main__':
    main()

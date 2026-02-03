
from bs4 import BeautifulSoup
import re

def parse_cnvd_list(html_content):
    """解析CNVD列表页，提取CNVD编号和日期"""
    soup = BeautifulSoup(html_content, 'lxml')
    items = []
    
    # Debug: print number of tr found
    trs = soup.find_all('tr')
    print(f"Found {len(trs)} tr elements")

    for i, tr in enumerate(trs):
        text = tr.get_text(" ", strip=True)
        # 查找 CNVD ID
        cnvd_match = re.search(r'CNVD-\d{4}-\d+', text)
        # 查找日期 (YYYY-MM-DD)
        date_match = re.search(r'\d{4}-\d{2}-\d{2}', text)
        
        if cnvd_match and date_match:
            print(f"Row {i}: Found {cnvd_match.group(0)} | {date_match.group(0)}")
            items.append({
                'cnvd_id': cnvd_match.group(0),
                'date': date_match.group(0)
            })
        else:
            # Print failure for first few rows to debug
            if i < 10 and "CNVD" in text:
                 print(f"Row {i} Failed match. Text: {text[:100]}...")

    # 去重
    unique_items = []
    seen = set()
    for item in items:
        if item['cnvd_id'] not in seen:
            unique_items.append(item)
            seen.add(item['cnvd_id'])
            
    return unique_items

with open('list_page_debug.html', 'r', encoding='utf-8') as f:
    content = f.read()
    items = parse_cnvd_list(content)
    print(f"Parsed {len(items)} unique items")
    for item in items:
        print(item)

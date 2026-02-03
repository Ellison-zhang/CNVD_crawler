
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
        # Find link with CNVD ID
        a_tag = tr.find('a', href=re.compile(r'/flaw/show/CNVD-\d+-\d+'))
        
        if a_tag:
            href = a_tag['href']
            cnvd_id = href.split('/')[-1]
            
            # Find date in the same row
            text = tr.get_text(" ", strip=True)
            date_match = re.search(r'\d{4}-\d{2}-\d{2}', text)
            date = date_match.group(0) if date_match else "Unknown"
            
            print(f"Row {i}: Found {cnvd_id} | {date}")
            items.append({
                'cnvd_id': cnvd_id,
                'date': date
            })
        else:
             # Just for debug
             pass

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

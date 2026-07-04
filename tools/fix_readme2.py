#!/usr/bin/env python3
import sys
with open('README.md', 'r', encoding='utf-8') as f:
    c = f.read()

needle = 'waf_mode="safe" request_delay="3"\n\n```\nsrc/xuanmu_bb/'
replacement = 'waf_mode="safe" request_delay="3"\n\n---\n\n## 🏗️ 项目结构\n\n```\nsrc/xuanmu_bb/'

if needle in c:
    c = c.replace(needle, replacement, 1)
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(c)
    print('OK')
else:
    print('Pattern not found')
    # Try with different quoting
    idx = c.find('request_delay="3"')
    print(f'Context around match: ...{c[idx:idx+80]}...')

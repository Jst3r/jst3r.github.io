#!/usr/bin/env python3
"""
Scans writeups directory and generates writeups.json
Run this whenever you add new writeups: python3 build.py
"""

import os
import json
import re

WRITEUPS_DIR = "writeups"
OUTPUT_FILE = "writeups.json"

def get_title_from_md(filepath):
    """Extract title from first # heading or filename"""
    filename_title = os.path.splitext(os.path.basename(filepath))[0].replace('_', ' ').title()
    
    # Patterns that indicate this is NOT a proper title
    bad_patterns = ['http', 'Output:', 'Root Flag', 'User Flag', 'Copyright', 'Password:', 'Permission', '...']
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            in_frontmatter = False
            for line in f:
                line = line.strip()
                # Handle frontmatter
                if line == '---':
                    in_frontmatter = not in_frontmatter
                    continue
                if in_frontmatter:
                    continue
                # Look for first heading
                if line.startswith('# '):
                    title = line[2:].strip()
                    # Validate title
                    if len(title) > 2 and not any(bp in title for bp in bad_patterns):
                        return title
    except:
        pass
    
    return filename_title

def scan_writeups():
    writeups = []
    
    # Scan HTB machines (now with difficulty categories)
    htb_dir = os.path.join(WRITEUPS_DIR, "htb machines")
    if os.path.exists(htb_dir):
        for item in os.listdir(htb_dir):
            item_path = os.path.join(htb_dir, item)
            
            if os.path.isdir(item_path):
                # It's a difficulty folder (easy, medium, hard, insane)
                for filename in os.listdir(item_path):
                    if filename.endswith('.md') and not filename.startswith('_'):
                        filepath = os.path.join(item_path, filename)
                        writeups.append({
                            "title": get_title_from_md(filepath),
                            "category": "htb",
                            "difficulty": item,
                            "file": filepath
                        })
            elif item.endswith('.md') and not item.startswith('_'):
                # .md file directly in htb machines (no difficulty)
                writeups.append({
                    "title": get_title_from_md(item_path),
                    "category": "htb",
                    "difficulty": None,
                    "file": item_path
                })
    
    # Scan CTF writeups
    ctf_dir = os.path.join(WRITEUPS_DIR, "ctf")
    if os.path.exists(ctf_dir):
        for ctf_name in os.listdir(ctf_dir):
            ctf_path = os.path.join(ctf_dir, ctf_name)
            if not os.path.isdir(ctf_path):
                continue
            
            # Scan categories (pwn, rev, web, forensics, etc.)
            for item in os.listdir(ctf_path):
                item_path = os.path.join(ctf_path, item)
                
                if os.path.isdir(item_path):
                    # It's a category folder - scan .md files inside
                    for filename in os.listdir(item_path):
                        if filename.endswith('.md'):
                            filepath = os.path.join(item_path, filename)
                            writeups.append({
                                "title": get_title_from_md(filepath),
                                "ctf": ctf_name,
                                "category": item,
                                "file": filepath
                            })
                elif item.endswith('.md'):
                    # It's a .md file directly in CTF folder - no category
                    writeups.append({
                        "title": get_title_from_md(item_path),
                        "ctf": ctf_name,
                        "category": None,
                        "file": item_path
                    })
    
    return writeups

def main():
    writeups = scan_writeups()
    
    # Sort: HTB first, then CTFs alphabetically
    writeups.sort(key=lambda w: (
        0 if w.get('category') == 'htb' else 1,
        w.get('ctf', ''),
        w.get('category', ''),
        w.get('title', '')
    ))
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(writeups, f, indent=2)
    
    print(f"✓ Generated {OUTPUT_FILE} with {len(writeups)} writeups")
    
    # Summary
    htb_count = len([w for w in writeups if w.get('category') == 'htb'])
    ctf_count = len([w for w in writeups if w.get('ctf')])
    ctf_names = set(w.get('ctf') for w in writeups if w.get('ctf'))
    
    print(f"  - HTB Machines: {htb_count}")
    print(f"  - CTF Writeups: {ctf_count} across {len(ctf_names)} CTF(s)")
    for ctf in sorted(ctf_names):
        count = len([w for w in writeups if w.get('ctf') == ctf])
        print(f"    • {ctf}: {count}")

if __name__ == "__main__":
    main()

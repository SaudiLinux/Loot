#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
شغل الكل للهدف - أداة بسيطة لوضع الهدف وتشغيل جميع الأدوات
Run All For Target - Simple tool to set target and run all tools
"""

import sys
import subprocess
import datetime

def main():
    if len(sys.argv) != 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║              🎯 أداة استغلال الهدف السريعة 🎯               ║
╚══════════════════════════════════════════════════════════════╝

الاستخدام: python شغل_الكل_للهدف.py [الهدف]

الأمثلة:
  python شغل_الكل_للهدف.py 192.168.1.1
  python شغل_الكل_للهدف.py example.com
  python شغل_الكل_للهدف.py localhost
        """)
        sys.exit(1)
    
    target = sys.argv[1]
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🎯 الهدف: {target:<35} 🎯
║  ⏰ الوقت: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<35}  ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"🚀 بدء استغلال الهدف: {target}")
    print("=" * 60)
    
    # Run the target exploitation
    cmd = f"python target_exploit.py --target {target}"
    result = subprocess.run(cmd, shell=True)
    
    if result.returncode == 0:
        print(f"\n✅ تم استغلال الهدف {target} بنجاح!")
        print(f"📁 تم إنشاء التقارير والنتائج")
        print("\n🎉 تم الانتهاء من جميع الأدوات!")
    else:
        print(f"\n⚠️  تم التنفيذ مع بعض التحذيرات")

if __name__ == "__main__":
    main()
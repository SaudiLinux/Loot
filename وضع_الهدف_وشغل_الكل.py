#!/usr/bin/env python3
"""
وضع الهدف وتشغيل جميع الأدوات في أمر واحد
Set target and run all tools in one command
"""

import sys
import subprocess
import datetime

def main():
    if len(sys.argv) < 2:
        print("❌ الاستخدام: python وضع_الهدف_وشغل_الكل.py [الهدف]")
        print("مثال: python وضع_الهدف_وشغل_الكل.py 192.168.1.1")
        print("مثال: python وضع_الهدف_وشغل_الكل.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║              أداة استغلال الهدف الرئيسية                     ║
    ║                                                              ║
    ║  🎯 الهدف: {target:<35}                     ║
    ║  ⏰ الوقت: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<35}  ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Run the main target exploitation script
    cmd = f"python target_exploit.py --target {target}"
    print(f"🚀 تشغيل: {cmd}")
    print("=" * 60)
    
    try:
        result = subprocess.run(cmd, shell=True)
        if result.returncode == 0:
            print(f"\n✅ تم استغلال الهدف {target} بنجاح!")
            print(f"📁 تم إنشاء التقارير والنتائج")
        else:
            print(f"\n⚠️  تم التنفيذ مع بعض التحذيرات")
    except Exception as e:
        print(f"❌ خطأ: {e}")

if __name__ == "__main__":
    main()
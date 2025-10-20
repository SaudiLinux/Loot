#!/usr/bin/env python3
"""
One-command script to run all exploitation tools
سكريبت بل أمر واحد لتشغيل جميع أدوات استغلال الثغرات
"""

import subprocess
import sys
import os

def main():
    """Execute all exploitation tools in sequence"""
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║      تشغيل جميع أدوات استغلال الثغرات - أمر واحد          ║
    ║     Run All Exploitation Tools - Single Command             ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Define the command sequence
    commands = [
        # Practical exploitation
        "python practical_exploitation.py --demo all",
        
        # Proof of concept  
        "python poc_exploitation.py --target http://example-vulnerable-app.com --test all",
        
        # Arabic demo
        "python arabic_exploitation_demo.py --demo all",
        
        # Zero day tool
        "python zero_day_tool.py --demo-mode",
        
        # Exploitation tools
        "python exploitation_tools.py --demo"
    ]
    
    print("🚀 بدء تشغيل جميع الأدوات...")
    print("=" * 60)
    
    # Execute each command
    for i, cmd in enumerate(commands, 1):
        print(f"\n📋 [{i}/{len(commands)}] تنفيذ: {cmd}")
        print("-" * 40)
        
        try:
            # Run the command and show output
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ نجح - رمز الخروج: {result.returncode}")
                # Show brief success output
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    if lines:
                        print(f"مخرجات مختصرة: {lines[-1][:100]}...")  # Last line, first 100 chars
            else:
                print(f"⚠️  تحذير - رمز الخروج: {result.returncode}")
                if result.stderr:
                    print(f"خطأ: {result.stderr[:200]}...")
                    
        except Exception as e:
            print(f"❌ خطأ: {str(e)}")
        
        print("\n" + "=" * 60)
    
    print("\n🎉 تم تشغيل جميع الأدوات بنجاح!")
    print("📁 تحقق من الملفات الناتجة في المجلد الحالي")
    print("📄 ابحث عن ملفات التقارير: *.md, *.json")

if __name__ == "__main__":
    main()
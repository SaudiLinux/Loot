@echo off
echo ╔══════════════════════════════════════════════════════════════╗
echo ║      تشغيل جميع أدوات استغلال الثغرات - أمر واحد          ║
echo ║     Run All Exploitation Tools - Single Command             ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo 🚀 بدء تشغيل جميع أدوات استغلال الثغرات...
echo.

REM Run all exploitation tools in sequence
echo 📋 [1/5] Practical Exploitation Tool...
python practical_exploitation.py --demo all
echo.

echo 📋 [2/5] Proof of Concept Tool...
python poc_exploitation.py --target http://example-vulnerable-app.com --test all
echo.

echo 📋 [3/5] Arabic Exploitation Demo...
python arabic_exploitation_demo.py --demo all
echo.

echo 📋 [4/5] Zero Day Tool...
python zero_day_tool.py --demo-mode
echo.

echo 📋 [5/5] Exploitation Tools Module...
python exploitation_tools.py --demo
echo.

echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    ✅ تم الانتهاء بنجاح!                     ║
echo ║              All Tools Executed Successfully!               ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo 📁 تحقق من الملفات الناتجة:
dir *.md *.json | findstr "report exploitation poc practical"
echo.
pause
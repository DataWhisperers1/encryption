# https://t.me/Master_X_Cha
# encryption 

# أداة التشفير وفك التشفير

## نظرة عامة

هذه الأداة المتقدمة مبنية بلغة بايثون وتستخدم لتشفير وفك تشفير الملفات باستخدام خوارزمية **AES** (معيار التشفير المتقدم). تتيح للمستخدمين تشفير ملفاتهم بكلمة مرور بشكل آمن، مع إمكانية ضغط الملفات قبل التشفير لتقليل حجمها. بالإضافة إلى ذلك، توفر الأداة توقيع الملفات باستخدام **RSA** للتحقق من سلامتها. كما تدعم الأداة تشفير وفك تشفير المجلدات بالكامل.

## الميزات

1. **تشفير وفك تشفير الملفات** باستخدام خوارزمية AES.
2. **ضغط الملفات** قبل التشفير لتقليل حجم البيانات.
3. **توليد مفاتيح RSA** لحفظها واستخدامها لتوقيع الملفات.
4. **توقيع الملفات** باستخدام RSA لضمان سلامة البيانات.
5. **نظام سجل** لحفظ العمليات التي تم تنفيذها.
6. **واجهة مستخدم رسومية بسيطة** لتسهيل استخدام الأداة.

## كيفية الاستخدام

1. قم بتشغيل الأداة من خلال واجهة المستخدم الرسومية.
2. اختر الملف أو المجلد الذي ترغب في تشفيره أو فك تشفيره.
3. أدخل كلمة المرور التي سيتم استخدامها لإنشاء مفتاح التشفير.
4. يمكنك تفعيل خيار **ضغط الملفات** لتقليل حجم الملف قبل التشفير.
5. اضغط على زر **تشفير** أو **فك التشفير** وفقًا للعملية التي ترغب في تنفيذها.
6. إذا كنت ترغب في توقيع الملفات أو التحقق من التوقيع، قم بتوليد مفاتيح RSA باستخدام الأداة.

## المتطلبات

لتشغيل هذه الأداة، يجب أن تكون لديك المكتبات التالية مثبتة:

- Python 3.x
- مكتبة [PyCryptodome](https://pypi.org/project/pycryptodome/)
- مكتبة Tkinter (موجودة ضمن حزمة بايثون)

لتثبيت مكتبة PyCryptodome، استخدم الأمر التالي:

```bash
pip install pycryptodome
```

تثبيت وتشغيل الأداة

1. قم باستنساخ المستودع:


```
git clone https://github.com/DataWhisperers1/encryption/
```

2. انتقل إلى مجلد المشروع:


```
cd encryption
```
3. قم بتشغيل الأداة:


```
python encryption.py
```

مساهمات

نرحب بأي مساهمات لتطوير الأداة وتحسينها. إذا كنت ترغب في المساهمة، يرجى فتح طلب سحب (Pull Request) مع وصف واضح للتعديلات التي ترغب في إضافتها.

التحذيرات القانونية

تأكد من استخدام الأداة بشكل قانوني وأخلاقي.

هذه الأداة تهدف إلى حماية البيانات الشخصية وليس استخدامها في أي أعمال غير قانونية.



# حزمة Laravel SSO

حزمة عامة مستقلة بترخيص MIT، تتطلب PHP 8.4 وتدعم Laravel 12 و13، ولا تعتمد على Livewire.

أضف مستودع Composer من النوع path يشير إلى مجلد الحزمة ثم اطلب
`university-sso/laravel-university-sso:dev-main`.
اضبط SSO_ISSUER وSSO_CLIENT_ID وSSO_CLIENT_SECRET وSSO_REDIRECT_URI وSSO_BROKER_URL.
تتطلب الاتصالات HTTPS وعنوان إعادة توجيه مسجلاً بدقة.

تبدأ المصادقة بواسطة authorizationUrl، وتعالج العودة بواسطة callback،
وتحمي المسارات بوسيط sso ضمن مجموعة web.
يستخدم التدفق PKCE S256 وstate أحادي الاستخدام وnonce والتحقق من التوقيع.
لا تنشئ الحزمة مستخدماً محلياً تلقائياً؛ اربط الهوية بواسطة issuer وsubject.
يفحص الوسيط حالة الإبطال عند كل طلب ويرفض الوصول عند تعطل الخدمة.
توجد أمثلة المسارات وعقد التكامل في README.md وdocs/INTEGRATION.md.

استخدم مخزن جلسات خادمياً وملفات ارتباط Secure وHttpOnly وSameSite=Lax
من دون domain مشترك، ومخزن cache مشترك لجميع العقد.
لم تُنفذ تجربة دخول حقيقية على مزود هوية ضمن هذا التسليم؛ راجع ملف الحالة.

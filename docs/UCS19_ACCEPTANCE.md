# UCS-19 — ביקורת קבלה לפי דרישות

מצב: מימוש מנגנוני האמינות הושלם ונמצא באימות סופי. הצפנת metadata במנוחה וסקירת Owner נשארות פתוחות. מקור הדרישות הוא אפיון UCS-19 ו־DURABLE_EXECUTION.md. בקשת ה־Owner להשלים את UCS אישרה מימוש; אין כאן אישור Production או טענה שסקירת הקבלה כבר התקיימה.

## מטריצת דרישות וראיות

| דרישה ותרחיש | ראיות | גבולות |
| --- | --- | --- |
| 001: אותה פעולה אחרי restart ו־requestId חדש | test_receipts.py, test_durable_execution.py; זהות organization/operation, binding קנוני ומפתח ספק יציב | התהליך העסקי חייב לשמר operationId; תוכן זהה אינו בהכרח אותה פעולה |
| 001: שינוי actor/יעד/סכום או גרסת binding | test_binding_version.py ובדיקות conflict; bindingSchemaVersion=1 נשמר, רשומה היסטורית ללא השדה מפורשת כ־v1 | גרסה לא מוכרת נחסמת ללא IO |
| 002: כוונה לפני IO, צריכת אישור אטומית ותחרות | CAS, unique constraints, approval transaction; test_receipts.py, test_durable_execution.py | commit acknowledgement חסר אינו הרשאה לשליחה |
| 002/008: קריסות בגבולות commit | test_execution_crash_matrix.py: לפני/אחרי intent, אחרי dispatch, אחרי witness ולפני IO, אחרי result commit ואחרי audit delivery commit | ילד נפרד יוצא בקוד 42; restart ומונה השפעות ספק עצמאי |
| 003: הצלחת ספק לפני קריסה | test_process_crash_after_provider_commit_then_keyed_lookup_recovers | התאוששות ב־lookup מאומת; אין הנחה שספק אחר מקיים אותו חוזה |
| 003: pending אסינכרוני | test_dispatch_outcomes.py; dispatchOutcomes מקובע, התאמת key/account/binding/contract וחידוש אחרי crash | pending אינו גורר replay; HTTP accepted לבדו אינו success |
| 004: replay מוגן, חלון שפג ותקציב בירור | test_execution_replay.py, test_execution_recovery.py, test_recovery_timing.py | אותו מפתח וחשבון, notAfter נאכף בספק הסינתטי, backoff עמיד משותף ו־clockMarginMs |
| 005: אישור מבוטל/פג ותחומי הרשאה | test_execution_auth.py, בדיקות revocation/expiry והחזרת result | actor וארגון נבדקים לפני IO או פענוח; SDK מניח מארח מאמת |
| 005: worker ישן ותוצאות סותרות | test_stale_execution_process.py, test_outcome_conflicts.py | terminal אינו נדרס; סתירה סמכותית גוררת quarantine והתראה אטומיים; אין endpoint לאיפוס |
| 006: כשל audit ואובדן acknowledgement | test_receipt_audit.py; result ו־outbox בטרנזקציה אחת, eventId יציב ומסירה אידמפוטנטית | מצב המסירה בטבלת outbox; מסירה אינה מפעילה ספק |
| 007: expiry של payload ו־restore | test_receipt_retention.py, test_dispatch_witness.py | ciphertext נמחק בלי לשחרר זהות; witness חייב להישמר בנפרד ולא להיות משוחזר לאחור עם primary |
| 007: תקציבים, התראות ומדדים | test_execution_observability.py, בדיקות recovery/replay; notices/metrics עם executions:observe | inbox מקומי עמיד; אין טענת מסירה למערכת ניטור חיצונית |
| 007: רשומה פגומה אינה עוצרת retention | test_invalid_receipt_cannot_starve_later_retention_pages, עם גרסה עתידית ו־JSON פגום | הרשומה החשודה וה־ciphertext נשמרים; cursor עובר לרשומות הבאות |
| 008: אריזה ותאימות runtime | CI בונה wheel וטוען ממנו app/OpenAPI; בדיקות UCS הקיימות נשארות ברגרסיה | Docker ו־PostgreSQL נבדקים ב־CI; אינם מותקנים בסביבת הבדיקה המקומית |

## ראיות הריצה העדכניות

- הרגרסיה המקומית אחרי חיבור runtime מוצפן ותיקוני תחרות: 390 עברו, 211 דולגו בשל היעדר PostgreSQL/Docker; אזהרת deprecation אחת בתלות Starlette.
- [CI ב־134dd86](https://github.com/yuliabk/universal-connection-service/actions/runs/35174474215): כל 575 הבדיקות עברו ללא דילוגים, כולל PostgreSQL 16 ו־Docker; גם בניית wheel וטעינת האפליקציה ממנו עברו. ראיה זו כוללת את ה־runtime ומטריצת הקריסה המוצפנים. גם rotation באצוות עבר בשני backends; לכל בדיקת PostgreSQL מסד ייעודי כדי שהחלפת profile לא תשפיע על בדיקות אחרות.
- נוספו בדיקות אתחול מוצפן, provisioning ללא איפוס זהויות, ושחזור דטרמיניסטי של השלמת פעולה בין קריאת primary לבדיקת witness. הצעת מדיניות נבחרת לפי workflowRevision כדי להימנע מהחזרת הצעה ישנה כאשר חותמות הזמן זהות.
- fixtures משתמשים בנתונים סינתטיים ובספק עם ledger עצמאי. הם אינם מוכיחים חוזה של ספק Production, RPO/RTO או הפרדת failure domains בפריסה.

## סעיפים שנותרו פתוחים

1. **הצפנת metadata במנוחה.** תוצאות ו־metadata נשמרים מוצפנים ב־EncryptedStateStore וב־witness עצמאי, וה־runtime דורש profiles ומפתחות תקינים. מטריצת הקריסה המוצפנת עברה בשני backends. גם re-encryption באצוות עבר בשני backends. כלי העברת נתונים קיימים מומש ועבר בדיקות SQLite, כולל חסימת profiles חלקיים והשוואה מלאה של הנתונים. נותר אימות PostgreSQL ב־CI והשלמת ביקורת הקבלה. TLS אינו מכסה דיסק או גיבויים ישנים. אין לסמן סעיף זה כהושלם על סמך דגל תצורה או הצפנת payload בלבד.
2. **G4.3 — סקירת Owner וקבלת תוצר.** PR טיוטה ומעבר CI אינם מעידים שהסקירה התקיימה. יש להציג את המימוש, בדיקותיו והפער שנותר לפני קבלה סופית.

פקודות הפעלה, טיפול במצבים וגבולות restore מתועדים ב־[UCS19_RUNBOOK.md](UCS19_RUNBOOK.md). פריסה או כתיבה לספק אמיתי דורשות היקף ואישור נפרדים.

השלמת הצפנה בשכבת האפליקציה מתקדמת ב־[UCS19_METADATA_ENCRYPTION.md](UCS19_METADATA_ENCRYPTION.md). נוספו מאגר מסמכים טרנזקציוני מוצפן ומיגרציה 7, ומומש EncryptedStateStore עם ממשקי הבקרה וה־receipts. ה־runtime מפעיל אותו אחרי אימות תצורה ו־profiles, וה־witness חובר למאגר מוצפן עצמאי. מעבר נתונים קיימים ובדיקות הקבלה הסופיות עדיין פתוחים. פער מעבר הנתונים נשאר פתוח עד העברה ואימות של הנתונים הקיימים, בלי איפוס זהויות.

ראיות migration מקומיות: רגרסיה מלאה של 390 passed/211 skipped, ואחריה 15 בדיקות migration ממוקדות שעברו ב־SQLite (15 וריאציות PostgreSQL ממתינות ל־CI), כולל CLI, קריסת תהליך, directory tampering ו־tenant עודף.

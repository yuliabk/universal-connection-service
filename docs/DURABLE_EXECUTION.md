# UCS-19 — Durable Execution Receipts + Idempotency

## מטרת השינוי

פעולה יכולה להצליח בספק לפני ש־ConnectionService שומר audit. UCS-19 מוסיף זהות פעולה ו־receipt עמידה לפני dispatch, כך שהתאוששות אינה מפעילה פעולה חדשה בטעות. זהו שינוי במאגר UCS על בסיס UCS-18; הוא אינו שינוי ב־ACL של Agent Factory.

## דרישות

- UCS-19-001: כל פעולה בעלת השפעה SHALL לקבל operationId יציב בתוך organizationId. ניסיון תעבורה מקבל requestId נפרד. אותו operationId עם יעד, פרמטרים או actor שונים SHALL להיחסם ללא IO עסקי. חשבון ספק נבחר בשכבת בקרה מהימנה.
- UCS-19-002: כוונה SHALL להישמר לפני IO; מעבר prepared -> dispatching SHALL להיות אטומי, עם version ו־attemptId. אובדן commit acknowledgement SHALL לא לאפשר שליחה. lease שפג אינו הוכחה שבקשה ישנה לא תבוצע.
- UCS-19-003: מצבי receipt SHALL להבחין בין prepared, dispatching, pending, unknown, succeeded ו־failed_no_effect. completion ו־audit outbox SHALL להישמר באותה טרנזקציה. crash אחרי dispatch או תשובת ספק שאינה סופית SHALL לא להפוך ל־failed_no_effect.
- UCS-19-004: replay אחרי תוצאה עמומה SHALL לדרוש חוזה ספק מאומת, אותו מפתח/חשבון וחלון deduplication תקף, או הוכחה סופית שהניסיון הקודם לא ביצע ולא יוכל לבצע השפעה. ספק ללא חוזה SHALL להישאר unknown עד בירור. MCP hints אינם חוזה כזה.
- UCS-19-005: קריאת receipt SHALL להיות מוגבלת ל־organization/actor מורשים. אישור SHALL להיקשר לפעולה ול־binding digest, וצריכתו SHALL להיות אטומית עם receipt או באמצעות reservation עמיד. ביטול או פקיעת אישור SHALL לחסום replay עסקי.
- UCS-19-006: audit outbox SHALL להימסר עם eventId יציב ו־deduplication. כשל audit SHALL לא להפעיל dispatch חוזר. אין payload, raw approval IDs או credentials באירוע.
- UCS-19-007: operationId SHALL לא להתפנות בעקבות expiry של payload. מחיקה/restore SHALL לא לפתוח מרחב מפתחות ישן לביצוע חוזר. recovery SHALL להיות בעל deadline ותקציב מפורשים. אחסון רגיש מוצפן ובידוד tenant נשארים מחייבים.
- UCS-19-008: קבלה SHALL לכלול restart בתהליך חדש, קריסה לאחר provider commit, תחרות workers, approval expiry/revocation, tenant isolation, key conflict ו־audit failure, מול SQLite ו־PostgreSQL. מספר ניסיונות אינו מספר השפעות.

## תכנון

ReceiptStore הוא port נוסף. SQLiteStateStore ו־PostgresStateStore יממשו את אותו חוזה; PostgreSQL מקבל migration ממוספר, ו־SQLite הרחבה additive. אין שירות תשתית חדש. מצב memory אינו עמיד לפעולות אלה.

binding הוא hash של JSON קנוני הכולל version, organization, user/agent, שירות, חשבון ספק, capability, operation ופרמטרים. הוא אינו ciphertext ואינו מיועד ללוג משותף. operationId אינו hash של input: שתי פעולות מכוונות עם אותם פרמטרים יכולות להיות שונות. transport וגרסת credential אינם זהות עסקית.

ConnectionService יבדוק receipt לפני צריכת אישור שכבר שימש. auto-connect ישמר אותה operationId לאורך restart. ConnectionResult יוסיף receiptId/executionState ללא שינוי במשמעות success: הצלחה מותנית ב־commit. unknown/pending יישאו קוד מפורש ו־retryable=false עבור clients קיימים.

מפתח ספק נשמר לפני השליחה, אינו משתנה ב־replay ואינו credential. fencing מקומי מגן על עדכון receipt אך אינו מסוגל לבטל בקשה ישנה אצל הספק. לכן העברת ownership אינה הרשאה לביצוע מחדש. refund/compensation הם פעולות חדשות עם אישור משלהן.

## קבוצות עבודה וסטטוס

ה־Owner ביקש להשלים את פרויקט UCS בהמשך להצגת טיוטת UCS-19. המימוש מתקדם בענף נפרד, קבוצה אחת בכל פעם עם בדיקה לפני המשך.

- [ ] G1: חוזים, receipt store, CAS ו־outbox טרנזקציוני בשני backends (001–003, 006–008).
- [ ] G2: ConnectionService, אישורים קשורים ובדיקות הרשאה לפני IO (001–005).
- [ ] G3: recovery, auto-connect, audit delivery וגבולות retention/retry (004–007).
- [ ] G4: fault injection בין תהליכים, רגרסיה, ראיות ומגבלות מסירה (008).

העלויות הן כתיבות database וקריאות reconciliation מוגבלות. מוכנות Production אינה נובעת ממעבר בדיקות יחידה; היא דורשת גם contract של ספק, פריסה, הצפנה ו־restore מוכחים. בשלב הבנייה משתמשים בנתונים וספקים סינתטיים בלבד.

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

- [x] G1: חוזים, receipt store, CAS ו־outbox טרנזקציוני בשני backends (001–003, 006–008); הראיות להלן מכסות את שכבת האחסון בלבד.
- [x] G2: ConnectionService, אישורים קשורים ובדיקות הרשאה לפני IO (001–005); היקף וראיות להלן. reconciliation ומוכנות Production עדיין פתוחים.
- [ ] G3: recovery, auto-connect, audit delivery וגבולות retention/retry (004–007).
- [ ] G4: fault injection בין תהליכים, רגרסיה, ראיות ומגבלות מסירה (008).

העלויות הן כתיבות database וקריאות reconciliation מוגבלות. מוכנות Production אינה נובעת ממעבר בדיקות יחידה; היא דורשת גם contract של ספק, פריסה, הצפנה ו־restore מוכחים. בשלב הבנייה משתמשים בנתונים וספקים סינתטיים בלבד.

## ראיות G1 — 2026-09-16

קוד האחסון נבדק ב־commit `a115c8e1122cb339ea39acfdd54351f5bee35f57`. [הרצת CI](https://github.com/yuliabk/universal-connection-service/actions/runs/35116819315) עברה עם PostgreSQL 16 ו־Docker: 141 בדיקות עברו. מקומית עברו 120 בדיקות ו־21 דולגו בהעדר PostgreSQL/Docker; נדרשו PATH של הסביבה המבודדת ו־PYTHONUTF8=1 עבור Schemathesis ב־Windows. התקלה המקומית לא דרשה שינוי בקוד השירות.

בדיקות `tests/test_receipts.py` מכסות מפתח יציב בפתיחה מחדש, binding conflicts, תחרות CAS בין שני מופעי backend, חסימת dispatch חוזר מ־unknown, completion/outbox אטומיים, tenant isolation, acknowledgement חוזר, rollback בכשל outbox ואובדן acknowledgement של commit. בדיקת SQLite בתהליך נפרד משתמשת ב־os._exit לאחר dispatch commit ומוודאת שלא ניתן לבצע dispatch חדש. בדיקות PostgreSQL רצות מול שרת אמיתי ב־CI. בדיקת workflow ישנה עודכנה כדי לא לקבע את גרסת הסכימה ל־3 לאחר הוספת migration 4.

בנקודת G1 עדיין לא היה חיבור ל־ConnectionService. בדיקת התהליך ב־G1 מוכיחה עמידות dispatch בלבד; היא אינה מוכיחה התאוששות לאחר השפעת ספק. יתר היכולות מתוארות לפי קבוצת המימוש שלהן להלן. אין טענת השלמת UCS-19.

## סדר G2 הבא

החלטת G2: consume של אישור יבוצע באותה טרנזקציה עם המעבר prepared -> dispatching ויצירת attempt, אחרי שהכוונה נשמרה. rollback משאיר אישור לא־צרוך; אובדן acknowledgement אחרי commit משאיר receipt חסומה ב־dispatching. השלמת result מוצפן ו־outbox תהיה אטומית. grants קיימים ללא operation/digest binding לא יורשו לכתיבה, אך יישארו תקפים למסלולי read/promotion הקיימים לפי המדיניות שלהם. הגדרות target מהימנות יקשרו organization/service/capability/connector version לחשבון ספק ול־credential handles מאושרים; החלפת handle לא תחליף זהות פעולה. success ייחשב סופי רק אם חוזה target מאושר מצהיר על כך. פלט partial/failed ללא הוכחה סופית ישאיר unknown. G3 יוסיף reconciliation/replay מבוקר במקום retry רגיל.

1. הרחבת ConnectionRequest ב־operationId ו־ConnectionResult ב־receiptId/executionState.
2. operation/digest binding של approvals ומעבר מתועד מ־grants ישנים; צריכה אטומית עם receipt ב־SQLite/PostgreSQL. אישור של פעולה אחרת לא יוכל לשמש לפעולה עמומה.
3. coordinator מהימן שיבדוק policy ו־actor לפני גישה לתוצאה, ויחייב durable store לכל פעולה בעלת השפעה. cached success לא יצרוך approval שוב; unknown לא יבצע connector.execute רגיל.
4. result storage מוצפן, completion אטומי, ומבחני כשל לפני/אחרי IO. memory mode ו־backend חסר לא יוכלו להפעיל write דרך מסלול legacy.
5. בדיקות והרצת רגרסיה לפני G3; לשמור את PR #19 כטיוטה עד סגירת כל הקבוצות.

## ממשק G2 ומעבר מהגרסה הקודמת

ConnectionService מפנה פעולות שאינן read, readOnly=false, סיכון destructive/financial/permissionIncrease, או capability הרשומה בקטלוג execution targets, ל־DurableExecutor. אין bypass לכתיבה דרך ALLOW של policy או אישור ישן בזיכרון. פעולות read שלא רשומות בקטלוג עדיין נשענות על חוזה הסיווג של הפלטפורמה הקוראת; לפני Production יש להוכיח שכל capability בעלת השפעה מסווגת במטא־נתונים מהימנים גם אם הקורא טוען read. בדיקת G2 מוכיחה חסימת שינוי כזה עבור capability רשומה. כיסוי סיווג מלא למתאמים ופריסה נשאר חלק מביקורת G4.

לכתיבה נדרש operationId; requestId יכול להשתנות בין ניסיונות. issuer מחייב אישור עם organization/user/agent/service/capability/operation, operationId ו־bindingDigest. `auto-connect` מנפיק binding דרך ה־executor המהימן. אישור consumed אינו מספיק לביצוע נוסף; receipt קיימת מכריעה אם אפשר להחזיר תוצאה. אישור revoked/expired אינו יכול להתחיל dispatch. אפשר להחליף אישור עבור prepared בלבד אחרי בירור binding; אין החלפת אישור שהופכת unknown לפעולה חדשה.

הגדרות host החדשות (אין ערכים אמיתיים או פריסה בשינוי):
- `UCS_EXECUTION_TARGETS_JSON`: מערך ExecutionTarget עם organizationId, serviceId, capability, providerAccountId, connectorId, connectorVersion, operations, userIds, agentIds, credentialHandleHashes, allowNoCredentials, successIsFinal ו־resultRetentionSeconds. אין wildcard tenant. hash של handle חייב להיות תואם לחשבון הספק שהמפעיל הגדיר; rotation מוסיפה hash של handle חדש לאותו חשבון. allowNoCredentials תקף רק למחבר auth=none.
- `UCS_RECEIPT_KEYRING_JSON`: אובייקט עם activeKey ו־keys (מיפוי key ID לחומר מפתח base64 של 32 bytes). החומר נמסר למארח דרך מנגנון סודות; אינו נשמר בקוד, ב־receipts או ב־audit. תצורה חלקית, key באורך שגוי או store לא עמיד גורמים לכשל startup. בלי הגדרות אלה read ממשיך לפי המדיניות, אך write חסום.

התוצאה נשמרת ב־execution_result כשהיא מוצפנת ב־AES-256-GCM, עם key נגזר לכל organization ו־AAD שקושר receipt/operation/binding. ניתן להשאיר מפתח קודם ב־keyring לקריאת receipts ישנות. אובדן מפתח או expiry מחזירים RESULT_UNAVAILABLE/RESULT_EXPIRED ואינם משחררים operationId לשימוש חוזר. מחיקה פיזית ו־restore quarantine עדיין שייכים ל־G3. אין plaintext body ב־receipt או outbox.

Migration 5 מוסיף operation/digest/revocation ל־approval_grant וטבלת תוצאות מוצפנות. SQLite מבצע הרחבה additive תחת BEGIN IMMEDIATE עם synchronous=FULL; PostgreSQL משתמש במנגנון migrations הקיים וב־synchronous_commit=on לטרנזקציות receipt. זה מבטיח גבול commit מקומי, לא שרידות אובדן דיסק או restore חסר.

successIsFinal הוא חוזה מפעיל מאושר, לא רמז מהמודל או MCP annotation. ללא חוזה זה dispatch חסום. תוצאה שאינה success או exception אחרי dispatch נשארת unknown; אין retries אוטומטיים ב־G2. Timeout/cancellation אינם הוכחת אי־ביצוע. outcome עמום ב־auto-connect נכנס ל־awaiting_reconciliation עם nextAction=reconcile_execution, ואינו מציע restart. מימוש בירור בפועל יתווסף ב־G3.

auditId סופי מצביע לאירוע outbox; לפני completion, receiptId משמש גם כאסמכתת הכוונה העמידה בשדה auditId. כשל לפני הכנת receipt אינו ראיית ביצוע. G3 ישלים מסירת outbox ל־audit store ונתיב status/reconciliation מורשה.

## ראיות G2 — 2026-09-16

Commit `e69d5db991681e49570151d068790bca053cef69` עבר [CI עם PostgreSQL 16 ו־Docker](https://github.com/yuliabk/universal-connection-service/actions/runs/35121423682): 186 בדיקות עברו ללא דילוגים. בבדיקה המקומית המלאה לפני תוספת שלוש בדיקות התחרות/expiry עברו 141 בדיקות ו־39 דולגו בשל העדר PostgreSQL/Docker; לאחר התוספת, 23 בדיקות durable execution מקומיות עברו ו־21 בדיקות PostgreSQL באותו קובץ דולגו מקומית ונבדקו ב־CI.

הראיות החדשות כוללות: החזרת אותה תוצאה מוצפנת אחרי פתיחת store/service חדשים; אישור קשור ל־digest ול־operation; חסימת grants ישנים, scope mismatch, expiry ו־revocation; rollback של consume כשכתיבת attempt נכשלת; בדיקת actor/policy לפני החזרת תוצאה; סיבוב מפתח ופג תוקף payload בלי שחרור operationId; חשבון credential שונה; שני מופעי שירות שמייצרים השפעה אחת; ואובדן acknowledgement אחרי commit הצלחה, שאחריו אותו retry מחזיר את התוצאה השמורה.

בדיקת crash מפעילה תהליך Python נפרד: המחבר הסינתטי מבצע commit ב־database ספק נפרד, ואז os._exit(42) לפני completion ב־UCS. פתיחת UCS מחדש מחזירה OUTCOME_UNKNOWN, אינה מפעילה מחבר נוסף, ומונה ההשפעות נשאר 1. זו הוכחת חסימת כפילות; הכרעת unknown באמצעות lookup/replay מוגן עדיין שייכת ל־G3.

## G3 — העבודה הבאה

1. Provider recovery contract מהימן עם provenance/revision, אופן העברת providerKey לספק מהניסיון הראשון, חלון deduplication וגבולות attempts/deadline. receipts של G2 שלא נשלחו עם מפתח ספק מאומת לא יקבלו replay רק משום שנוספה תצורה חדשה.
2. reconciliation מורשה עם בדיקת account/actor/policy מחדש, הבחנה בין pending/unknown/תוצאה סופית, ו־lookup שאינו מניח ש־not found פירושו שאין השפעה. lease/fencing מקומי אינו אישור ל־retry.
3. מסירת outbox idempotent ל־AuditStore עם אותו eventId, תוך השארת הצלחה עמידה גם כשמסירת audit נכשלת.
4. חידוש auto-connect דרך receipt קיימת אחרי crash לפני שמירת workflow, ללא בקשת אישור חדשה לצורך קריאת תוצאה קיימת. status/reconciliation יישארו tenant/actor scoped.
5. מחיקת payload תוך שמירת tombstone, quarantine ל־restore שאיבד receipts, תקציב reconciliation, וראיות בין תהליכים גם למסלול התאוששות מלא.
6. ביקורת G4 תסגור גם סיווג capabilities מהימן בכל המתאמים, timeout/cancellation, worker ישן שחוזר לפעול אחרי החלפת בעלות, ומטריצת דרישות מלאה. אין לסמן הפרויקט או UCS-19 כהושלמו לפני כן.

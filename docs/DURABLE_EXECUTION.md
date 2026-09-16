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

ReceiptStore הוא port נוסף. SQLiteStateStore ו־PostgresStateStore מממשים את אותו חוזה; PostgreSQL מקבל migration ממוספר, ו־SQLite הרחבה additive. הגנת restore מוסיפה מסד witness עצמאי שחייב להישמר בנפרד מגיבויי primary. המחיר הוא כתיבת commit נוספת לפני כל dispatch, אחסון רישום הניסיונות וגיבוי עצמאי. מצב memory אינו עמיד לפעולות אלה.

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

ConnectionService מפנה פעולות שאינן read, readOnly=false, סיכון destructive/financial/permissionIncrease, או capability הרשומה בקטלוג execution targets, ל־DurableExecutor. אין bypass לכתיבה דרך ALLOW של policy או אישור ישן בזיכרון. G4 מוסיף קטלוג סיווג מהימן: גם read מחייב סיווג host מפורש לגרסת המחבר ולארגון, כמפורט להלן. הצהרת הקורא לבדה אינה מאפשרת מסלול ללא receipt.

לכתיבה נדרש operationId; requestId יכול להשתנות בין ניסיונות. issuer מחייב אישור עם organization/user/agent/service/capability/operation, operationId ו־bindingDigest. `auto-connect` מנפיק binding דרך ה־executor המהימן. אישור consumed אינו מספיק לביצוע נוסף; receipt קיימת מכריעה אם אפשר להחזיר תוצאה. אישור revoked/expired אינו יכול להתחיל dispatch. אפשר להחליף אישור עבור prepared בלבד אחרי בירור binding; אין החלפת אישור שהופכת unknown לפעולה חדשה.

הגדרות host החדשות (אין ערכים אמיתיים או פריסה בשינוי):
- `UCS_EXECUTION_TARGETS_JSON`: מערך ExecutionTarget עם organizationId, serviceId, capability, providerAccountId, connectorId, connectorVersion, operations, userIds, agentIds, credentialHandleHashes, allowNoCredentials, successIsFinal ו־resultRetentionSeconds. אין wildcard tenant. hash של handle חייב להיות תואם לחשבון הספק שהמפעיל הגדיר; rotation מוסיפה hash של handle חדש לאותו חשבון. allowNoCredentials תקף רק למחבר auth=none.
- `UCS_RECEIPT_KEYRING_JSON`: אובייקט עם activeKey ו־keys (מיפוי key ID לחומר מפתח base64 של 32 bytes). החומר נמסר למארח דרך מנגנון סודות; אינו נשמר בקוד, ב־receipts או ב־audit. תצורה חלקית, key באורך שגוי או store לא עמיד גורמים לכשל startup. בלי הגדרות אלה רק read שסווג ואושר בקטלוג effects יכול להמשיך לפי המדיניות; write חסום.

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

### G3 — מסירת audit

נוסף worker של המארח שמוסר אירועי outbox ל־audit_event באותו backend. הוא פועל גם לאחר restart וללא בקשת retry של המשתמש. בכל טרנזקציה נמסרים עד 100 אירועים של organization אחת, עם eventId מקורי ו־ack באותה טרנזקציה. התנגשות ID עם תוכן אחר חוסמת ack. סבב מוגבל ל־100 ארגונים עם cursor, כדי שארגון עם תקלה לא יחסום את הארגונים שאחריו. בין סבבים יש השהיה של 5 שניות; shutdown ממתין לסיום הטרנזקציה לפני סגירת האחסון. שגיאות delivery נרשמות ללא פרטי payload או מזהי ארגון.

ה־audit הקיים מקבל את שדות הפעולה וה־approval hash בלבד; פרטי receipt, operationId, החלטת reconciliation וגרסת connector נשארים ב־outbox המקושר באותו auditId. הצלחת execution אינה ממתינה למסירה. כשל במסירה משאיר את ה־receipt הסופית ואת ה־outbox לשחזור ואינו קורא למחבר. זהו sink מקומי; מסירה למערכת audit חיצונית אינה ממומשת.

בדיקות חדשות מכסות תחרות בין שני חיבורים, restart, הפרדת ארגונים, rollback בכשל ack, אובדן commit acknowledgement, התנגשות audit ID, cursor והתאוששות worker לאחר כשל discovery. מקומית: 6 עברו ו־5 בדיקות PostgreSQL דולגו; הרגרסיה לפני תוספת בדיקות cursor/worker: 148 עברו ו־46 דולגו. G3 נותר פתוח עד השלמת recovery, auto-connect, retention ו־restore.

### G3 — חידוש workflow דרך receipt

לפני בקשת אישור ביצוע, auto-connect בודק דרך ConnectionService אם יש תוצאת dispatch קודמת. הדגל הפנימי `allow_dispatch=False` מחייב בדיקות context, policy, tenant, actor וחשבון ספק רגילות; הוא אינו מכין receipt, צורך אישור או מפעיל connector. receipt חסרה או prepared מחזירה RECEIPT_NOT_DISPATCHED וממשיכה למסלול האישורים הרגיל. תוצאה סופית משחזרת completed, ותוצאה עמומה מחזירה awaiting_reconciliation. advance של workflow במצב זה יכול לרענן תוצאה שכבר נשמרה; הוא עדיין אינו מבצע בירור מול הספק.

בדיקת fault injection נכשלת בשמירת workflow לאחר ביצוע ספק ושמירת receipt, פותחת מחדש את SQLite ומחדשת ללא approval ID. גם הצלחה וגם unknown נשמרות עם אותו receipt ומונה connector נשאר 1. בדיקת service נוספת מוכיחה שגם אישור תקף אינו מאפשר dispatch בנתיב status בלבד. מקומית: 33 בדיקות auto-connect/durable execution עברו ו־22 בדיקות PostgreSQL דולגו.

### G3 — מחיקת תוצאות שפג תוקפן

worker של retention סורק עד 10 תוצאות סופיות בכל סבב, עם cursor לפי receiptId והשהיה של 5 שניות. הוא מאמת את ה־AAD ואת expiresAt מתוך מעטפת AES-GCM, ולכן תומך גם בתוצאות G2 הקיימות ללא migration. מפתח חסר או מעטפה פגומה משאירים את התוצאה ומדווחים הודעה כללית; הם אינם אישור למחיקה. נדרשת זמינות מפתחות rotation הישנים עד השלמת retention.

מחיקת ciphertext המדויק וסימון resultPurgedAt ב־receipt נעשים באותה טרנזקציה עם CAS. receipt סופית, operationId, binding ו־outbox נשמרים. ניסיון חוזר מחזיר RESULT_EXPIRED עם executionState=succeeded, ללא הפעלת המחבר. אין מחיקת receipt או שחרור מפתח. expiry חוסם קריאה מיד; ניקוי האחסון מתבצע בהדרגה וזמנו תלוי במספר התוצאות ובזמינות worker/keyring. זהו DELETE ממסד הנתונים הפעיל, לא הבטחת מחיקה מעותקי גיבוי, WAL או שטחי דיסק פנויים; לפריסה נדרשת מדיניות retention נפרדת עבורם.

בדיקות משותפות ל־SQLite/PostgreSQL מכסות מחיקה אחרי expiry, פתיחה מחדש ללא ביצוע חוזר, שמירת audit, מפתח חסר, תוצאה שלא פג תוקפה, tenant scope, ciphertext mismatch, rollback של מחיקה ב־CAS conflict ושני workers שמוחקים פעם אחת. מקומית עברו 27 בדיקות retention/durable execution ו־25 בדיקות PostgreSQL דולגו. G3 עדיין פתוח: recovery מאומת מול ספק ו־restore quarantine.

### G3 — בירור ספק לפי מפתח מהניסיון הראשון

ExecutionTarget יכול להגדיר `recovery` עם contractId, revision, evidenceSha256, approvalReference, lookupWindowSeconds, maxLookups ו־lookupTimeoutMs. זהו חוזה שהמפעיל אישר וקיבע לתוצאת אימות ספק; אין להסיק אותו מ־MCP annotations או להפיקו מהמודל. המתאם המהימן חייב להחזיר בדיוק את digest החוזה ולהטמיע `execute_keyed` ו־`lookup_execution` בהתאם לראיות. לא נוספה תצורה מאושרת לספק Production כלשהו.

digest החוזה נשמר בכוונה לפני dispatch. הקריאה הראשונה למתאם מקבלת ProviderExecutionKey עם providerKey, חשבון ספק, bindingDigest ו־contractDigest. גרסת connector והחוזה נבדקים שוב לפני lookup. receipts ישנות ללא digest אינן מקבלות יכולת בירור רק באמצעות שינוי תצורה. ההרחבה נשמרת ב־receipt JSON עם defaults תואמי G2 ואינה מחייבת שינוי טבלאות.

`POST /v1/control-plane/executions/reconcile` מקבל request ו־context, מחייב bearer בעל scope `executions:reconcile` לארגון, ואז מפעיל שוב בדיקות policy/context/actor/account/binding של ConnectionService. ה־scope מסמיך מפעיל לבצע בירור בשם actor מורשה ב־target; הוא אינו מסמיך dispatch חדש. אישור עסקי חדש אינו נדרש לקריאת תוצאה. אין קריאה למחבר עסקי ב־endpoint זה, גם כאשר receipt חסרה או prepared.

לפני כל lookup נצרך מונה עמיד תחת CAS, כך שגם קריסה או timeout צורכים תקציב. החלון נספר מיצירת הכוונה (גבול שמרני), וה־timeout מוגבל גם לחלון וגם ל־deadline של הבקשה. pending נשאר pending; not_found ו־unknown נשארים unknown. success מחייב תוצאה סופית. failed_no_effect מחייב בנוסף חוזה שהניסיון הישן לא יוכל לבצע בעתיד (`lateExecutionPrevented`); HTTP error לבדו אינו ראיה לכך. כל תשובה חייבת להתאים לכל ארבעת שדות המפתח, ונבדקת שוב גם אם המתאם החזיר model שניתן לשינוי.

תוצאה סופית נשמרת עם ciphertext ו־audit outbox באותה טרנזקציה. lookup מאוחר אינו יכול לדרוס receipt שהושלמה על ידי עובד אחר. בדיקת subprocess חדשה מבצעת commit במסד ספק סינתטי נפרד ואז os._exit(42); הפעלה מחדש מבצעת lookup לפי המפתח המקורי, שומרת succeeded ומשאירה אפקט ספק יחיד. בדיקות נוספות מכסות budget לאורך restart, not_found/pending/unknown, mismatch בחשבון, actor לא מורשה, scope/tenant של ה־endpoint, פקיעת חלון וחסימת recovery רטרואקטיבי ל־G2.

נותרו במסגרת G3/G4: replay עסקי תחת חוזה deduplication ובדיקות אישור, restore quarantine, כיסוי תחרות/late workers ו־timeouts עמידים לביטול, והוכחת סיווג effects מהימן לכל המתאמים. מסלול lookup הסינתטי אינו הוכחת חוזה לספק Production.

### G3 — replay מוגן אצל הספק

חוזה recovery יכול לכלול `replay` עם deduplicationWindowSeconds, maxAttempts (כולל הניסיון הראשון), providerEnforcesNotAfter=true ו־concurrentDeduplication=true. הפעלת replay מחייבת ראיות ספק מאושרות לשתי ההבטחות: אותה פעולה לא תבוצע פעמיים גם בבקשות מקבילות, ובקשה ישנה שמגיעה אחרי notAfter תידחה גם אחרי שהספק פינה את רשומת deduplication. ספק שנותן רק חלון שמירת מפתחות בלי אכיפת deadline מרוחקת אינו מתאים לחוזה זה. חוזי lookup ישנים ללא replay שומרים על אותו digest.

השליחה הראשונה שומרת providerNotAfter באותה טרנזקציה עם dispatch. המועד הוא המוקדם מבין פקיעת האישור המקורי וסוף חלון deduplication, והוא נמסר למתאם עם המפתח. ניסיונות נוספים משתמשים בדיוק באותו מפתח, חשבון, binding, חוזה ו־notAfter; אין הארכת חלון, החלפת אישור או איפוס attempts. בדיקות מקומיות ו־timeout מוגבל מצמצמים שליחות מאוחרות, אך ההבטחה מול עובד שנעצר וחוזר תלויה גם באכיפה של הספק.

`POST /v1/control-plane/executions/replay` דורש scope נפרד `executions:replay` לארגון ו־approvalId המקורי. אחרי בדיקות policy/actor/account מתבצעת טרנזקציה שבודקת receipt עמומה, CAS, digest, חלון ותקציב; היא נועלת את רשומת האישור מול revocation ומוודאת שהאישור המקורי consumed אך עדיין תקף ואינו revoked. האישור אינו נצרך מחדש. הטרנזקציה שומרת attempt חדש לפני IO. אובדן acknowledgement אינו גורם לקריאה לספק. receipt חסרה או prepared אינה נשלחת דרך endpoint זה, ותוצאה סופית מוחזרת מהאחסון.

בדיקות SQLite/PostgreSQL משתמשות בספק סינתטי עם database נפרד ורשומת dedup אטומית: אחרי commit ותשובה שאבדה, replay מחזיר את האפקט המקורי, והמונה נשאר 1. נבדקים workers מקבילים, פתיחת אחסון מחדש, מפתח ו־deadline יציבים, אישור חסר/אחר/revoked/expired, budget שנצרך גם באובדן commit acknowledgement, scope נפרד ומניעת יצירת פעולה חדשה דרך replay. בדיקת בקשה מאוחרת מפנה במפורש את מטמון dedup של הספק ומוכיחה ש־notAfter עדיין מונע אפקט נוסף. אין בשינוי אימות של ספק Production אמיתי; הפעלת חוזה עבורו דורשת ראיות המותאמות למתאם ולגרסה.

G3 עדיין פתוח עבור restore quarantine. G4 עדיין כולל cancellation, בדיקות תהליכים ועובדים ישנים נוספות, סיווג effects מהימן בכל המתאמים וביקורת מטריצת הדרישות.

### G3 — הגנה משחזור באמצעות dispatch witness עצמאי

DurableExecutor מחייב כעת DispatchWitness במסד נתונים נפרד. לאחר commit של attempt ב־UCS ולפני IO לספק נכתבת רשומת witness בלתי משתנה עם tenant/operation, receipt, מפתח ספק, binding, חוזה, אישור hashed, מספר ניסיון ו־deadline. אין payload או credentials ברישום. רק acknowledgement של הכתיבה מאפשר להתקדם לספק. כשל או אובדן acknowledgement משאירים את הניסיון עמום ללא קריאה נוספת לספק.

לפני גישה ל־receipt ולפני כל dispatch נבדקת התאמה לרישום העצמאי. receipt שנעלמה, חזרה ל־prepared, איבדה ניסיונות או השתנתה ביחס ל־witness מקבלת EXECUTION_RESTORE_QUARANTINED. אישור חדש אינו משחרר את operationId. רישום dispatch כפול או קפיצה במספרי attempts נחסמים. זהו fail-closed גם כאשר primary commit נשמר אך witness commit נכשל; זמינות הפעולה יכולה להידרש לבירור תפעולי. אין endpoint שמוחק witness או מסיר quarantine.

הגדרות host הנדרשות בנוסף ל־targets/keyring:
- `UCS_EXECUTION_WITNESS_ID`: מזהה קבוע של הרישום העצמאי, נשמר גם בתצורת המארח מחוץ לגיבויי UCS.
- עבור SQLite: `UCS_EXECUTION_WITNESS_PATH` לקובץ קיים נפרד; אותו קובץ או hard link למסד הראשי נדחים.
- עבור PostgreSQL: `UCS_EXECUTION_WITNESS_POSTGRES_URL` למסד קיים נפרד. אותו server/database נדחה, גם דרך שני connection pools. מארח PostgreSQL אינו מקבל witness SQLite מקומי, כדי לא לפצל את הרישום בין replicas.

הפעלה אינה יוצרת witness חסר ואינה משנה את זהותו. provisioning נעשה במפורש עבור keyspace חדש בלבד, באמצעות `python -m universal_connection_service.dispatch_witness --sqlite-path <new-path> --witness-id <deployment-id> --confirm-new-keyspace`, או `--postgres-env <environment-variable-name>` במקום נתיב SQLite. ב־PostgreSQL מסד witness ייעודי חייב להיות קיים; פקודת provisioning יוצרת בו את הסכימה. DSN מועבר דרך משתנה סביבה ולא כארגומנט שמופיע ברשימת תהליכים. provisioning חוזר אינו מאפס מסד קיים. אין להשתמש בפקודה כפתרון ל־quarantine או כאמצעי לשדרוג keyspace היסטורי ללא רישום dispatch מוסמך.

גבול התפעול מחייב: witness אינו נכלל בשחזור גיבוי primary, ואסור להחזירו לאחור יחד עם UCS. הפרדת שמות database אינה הוכחה להפרדת failure domains; הפריסה חייבת לשמור ולגבות את witness בנפרד ולוודא שהוא עדכני לפני הפעלת writes אחרי restore. אם גם witness אבד או תקינותו אינה ידועה, writes נשארים כבויים עד שחזור סמכותי ובירור; יצירת witness ריק עם אותו מזהה אסורה. ההגנה אינה יכולה לשחזר מידע שנמחק משני מקורות האמת יחד. התחלת deployment חדש אינה הרשאה למחזר operationIds היסטוריים.

בדיקות restore סינתטיות משחזרות primary ללא receipt או עם snapshot של prepared לאחר אפקט ספק, ואז מנסות שוב עם אישור חדש: מתקבל quarantine ואפס קריאות ספק נוספות. נבדקים גם witness outage, אובדן commit acknowledgement, מזהה witness שגוי, מסד משותף ו־startup ללא קובץ witness. בדיקת PostgreSQL נוספת יוצרת מסד witness סינתטי נפרד, בודקת commit ופתיחה מחדש ומסירה אותו בסיום. G4 ומוכנות פריסה עדיין אינם מוכחים בשלב זה.

### G4 — timeout וביטול בלי המתנה למחבר שמסרב להתבטל

מסלולי dispatch, replay ו־lookup משתמשים כעת ב־ProviderCalls: ההמתנה נעצרת ב־deadline באמצעות asyncio.wait, ונשלחת בקשת cancellation למחבר בלי להמתין לאישורו. ביטול בקשת הלקוח פועל באותו אופן. משימת המחבר אינה מחזיקה סמכות לעדכון receipt; תוצאה או שגיאה שמגיעות לאחר שההמתנה הסתיימה נצרכות ונזרקות, ללא audit סופי וללא שינוי state. receipt עמומה נותרת זמינה לבירור/replay לפי החוזה הרגיל.

לכל executor מותרות עד 64 קריאות ספק פעילות, כולל משימות שלא כיבדו cancellation. כשהמגבלה מלאה לא נוצרת coroutine נוספת ולא מתחיל IO נוסף. משימות שסיימו מפנות מקום; חריגות מאוחרות נצרכות בלי לרשום הודעות ספק שעלולות להכיל סודות. אין טענה שביטול מקומי מבטל אפקט שכבר נשלח לספק.

בדיקות בשני backends כוללות מחבר שבולע CancelledError וממשיך להמתין: הבקשה חוזרת בזמן, retry רגיל אינו מפעיל מחבר נוסף, והצלחה מאוחרת אינה נשמרת. בדיקת lookup נוספת משלימה receipt באמצעות בירור שני ואז משחררת תשובת כישלון מאוחרת מהבירור הראשון; התוצאה הסופית ואירוע ה־audit נשארים ללא שינוי. נבדקים גם מיצוי קיבולת, שחרורה לאחר סיום משימה וצריכת שגיאה מאוחרת.

גבול המנגנון הוא event loop פעיל. קוד Python שחוסם את ה־thread בלי yielding אינו ניתן לעצירה בטוחה באמצעות asyncio; מתאמים לא מהימנים חייבים להמשיך לרוץ בגבול התהליך/הסנדבוקס הקיים עם השגחת runtime. כיבוי תהליך אינו הוכחה לאי־ביצוע מרוחק. סיווג effects מהימן וביקורת הדרישות המלאה עדיין פתוחים.

### G4 — אימות actor בגבול HTTP וב־auto-connect

בביקורת נמצא ש־`POST /v1/connections/execute` הסתפק בהתאמה בין request.actor לבין context שנשלחו שניהם על ידי הקורא. המסלול דורש כעת bearer מאומת מתוך `UCS_CONTROL_PLANE_CREDENTIALS_JSON`, scope `connections:execute`, הרשאה לארגון ו־`executionActors` עם צירופים מפורשים של organizationId/userId/agentId. אין מכפלה של רשימות משתמשים וסוכנים ואין הסקת זהות משדות הבקשה. metadata token ללא executionActors אינו מורשה לבצע פעולות או לקרוא תוצאות receipt שמורות.

למשל, רשומת credential יכולה לכלול `"scopes":["connections:execute"]` ו־`"executionActors":[{"organizationId":"synthetic-org","userId":"synthetic-user","agentId":"synthetic-agent"}]`, לצד tokenSha256, tokenId, subject ו־organizations הקיימים. נשמר רק hash של הטוקן בתצורת האימות. endpoint ללא authenticator מחזיר 503; טוקן חסר/שגוי מחזיר 401; scope/ארגון/actor לא מורשים מחזירים 403 לפני כניסה לשירות. אישור עסקי לביצוע חדש עדיין נדרש בנפרד.

auto-connect מחייב אותה הרשאת actor לפני dispatch או קריאת receipt קיימת. `connectors:review` ממשיך להספיק לצפייה בתכנון ובסטטוס, אך אינו מסמיך executeWhenReady. הרשאות מפעיל `executions:reconcile` ו־`executions:replay` נשארות הרשאות האצלה נפרדות ומפורשות ברמת הארגון, עם בדיקות target/actor/account ואישור replay המקורי. פורט ConnectionService הפנימי ממשיך להניח שמארח ה־SDK אימת את זהות הקורא; גבולות HTTP המסופקים אוכפים זאת בעצמם.

בדיקות API עם receipt אמיתית מוכיחות חסימת טוקן חסר, טוקן לארגון אחר, scope שגוי, actor חסר והתחזות לכל אחד משדות הזהות; רק הצירוף המאושר מקבל את התוצאה ללא dispatch נוסף. נבדקה גם חסימת עקיפה באמצעות workflow preview/advance עם הרשאת review בלבד. סיווג capability מהימן נותר סעיף נפרד להשלמה.

### G4 — סיווג השפעות מהימן לפני ביצוע

`UCS_CAPABILITY_EFFECTS_JSON` הוא מערך רשומות host עם organizationId, serviceId, connectorId, connectorVersion, capability, effect (`read_only` או `side_effecting`), evidenceSha256 ו־approvalReference. המפתח תואם לכל חמשת ממדי הזהות במדויק; אין wildcard ארגון. סיווג read דורש בדיקת המפעיל ליכולת ולגרסת המחבר, כולל השפעות השירות במעלה השרשרת. SHA256 והפניית האישור מתעדים את הראיה שהמארח אישר; UCS אינו מוכיח בעצמו שתוכן הראיה נכון. יש להגן על תצורה זו כמו על execution targets והרשאות runtime.

ברירת המחדל היא קטלוג ריק. פעולה שמוצגת כ־read ללא סיווג מהימן נחסמת לפני connector IO עם EFFECT_CLASSIFICATION_REQUIRED. אין הסקת read בטוח מ־HTTP GET, משם tool, מ־MCP hints, מ־manifest שנמצא בגילוי או מהצהרת readOnly בבקשה. אותה בדיקה חלה על כל אסטרטגיות המתאמים. סיווג side_effecting מזין readOnly=false למדיניות ומחייב DurableExecutor גם אם policy מותאם מחזיר ALLOW. סיווג read_only אינו מנמיך write/delete, רמז סיכון או capability מוגנת ב־ExecutionTarget.

הקטלוג מוגדר בידי המארח; אין endpoint להוספת סיווג על ידי caller. רשומות מועתקות ונבדקות, כפילות נדחית ותצורה פגומה מכשילה startup ללא הדפסת תוכנה. לאחר await של אימות אישור נבדקים שוב המחבר, גרסתו והסיווג לפני read IO. workflow ללא סיווג ממתין ב־awaiting_effect_classification עם nextAction=review_capability_effect; אחרי טעינת הסיווג המאושר אפשר לבצע advance עם הבקשה המקורית. עדכון גרסה דורש סיווג חדש, גם כשגרסה קודמת סווגה כקריאה.

בדיקות test_effects.py מכסות הצהרת read מזויפת בכל אסטרטגיה, חוסר התאמה בכל רכיב של מפתח הסיווג, מניעת הנמכת write, שינוי אובייקט תצורה לאחר אישור, תצורה פגומה, חסימת מתאם MCP וסנדבוקס, החלפת גרסת מחבר בזמן אימות אישור וחידוש workflow לאחר סקירת המארח. fixtures קיימים מאשרים במפורש את הקריאות הסינתטיות שלהם. הרגרסיה המקומית עברה עם 211 הצלחות ו־79 דילוגים עקב היעדר PostgreSQL/Docker. ביקורת G4 הכוללת וראיות CI לגרסה זו עדיין נדרשות; אין כאן אישור ספק אמיתי או פריסה ל־Production.

בדיקת הקריסה לאחר provider commit הורחבה להרצה מול שני backends: תהליך ילד מבצע את הפעולה הסינתטית ומסתיים ב־os._exit(42); מופע חדש מבצע lookup עם אותו provider key ומוודא השפעה יחידה. עבור PostgreSQL החיבור נלקח ממשתנה סביבת הבדיקה, ללא DSN בארגומנטים. witness SQLite נפרד משמש fixture סינתטי משותף לתהליכים; בדיקת witness PostgreSQL נפרד קיימת בנפרד. זו אינה הוכחה לפריסת witness מבוזרת או לעובד ישן שממשיך לפעול במקביל; האחרון עדיין בביקורת G4.

סיווג effects אומת ב־commit `4b9c914` עם 290 בדיקות CI מוצלחות, PostgreSQL 16 ו־Docker: https://github.com/yuliabk/universal-connection-service/actions/runs/35130255269 . הרחבת בדיקת התהליך ל־PostgreSQL נוספה לאחר הרצה זו ודורשת CI משלה.

### G3/G4 — קבלה אסינכרונית מפורשת מהספק

RecoveryContract יכול כעת להצהיר `dispatchOutcomes=true`. ההצהרה משתתפת ב־digest המקובע, ולכן אינה משנה בדיעבד receipt שנוצרה בחוזה קודם. חוזים קיימים ללא הדגל שומרים את ה־digest הקודם. במצב זה execute_keyed חייב להחזיר ProviderOutcome עם providerKey/account/binding/contract/notAfter תואמים; גם מופע מודל נבדק מחדש כדי למנוע עקיפה באמצעות שינוי שדות לאחר יצירה. ConnectorResult רגיל אינו מספיק, אפילו אם status=success.

תשובת pending נשמרת לפני החזרתה ללקוח, ללא תוצאת success וללא outbox סופי. retry רגיל מחזיר EXECUTION_PENDING; גם בקשת replay מפורשת אינה שולחת עבודה accepted שוב. הרשאת reconciliation מאפשרת לברר ולשמור תוצאה סופית. unknown/not_found אינם הוכחת אי־ביצוע. failed_no_effect מחייב כישלון סופי ו־lateExecutionPrevented=true. תשובה לא תואמת או כשל בשמירתה נשארים עמומים ואינם מאפשרים retry רגיל.

target עם successIsFinal=false יכול לבצע רק כאשר חוזה dispatchOutcomes מאושר ומקובע מספק את הסמנטיקה המפורשת. successIsFinal=true ממשיך לתאר את חוזה ConnectorResult הקודם. בדיקות חדשות מכסות finality, mismatch ושינוי מודל, pending לאחר פתיחה מחדש, חסימת replay, השלמה באמצעות lookup, וקריסת תהליך אחרי commit של pending ולפני תשובת הלקוח. ספק הבדיקה שומר ledger עצמאי; בתהליך recovery מתקבלת השפעה אחת ואירוע outbox סופי אחד. בדיקות PostgreSQL נדרשות ב־CI; אין בכך אישור לחוזה ספק אמיתי.

### G3 — מרווח התאוששות עמיד ומרווח שעון

RecoveryContract מגדיר recoveryBackoffMs ו־clockMarginMs חיוביים, ברירת מחדל 1000ms לכל אחד. ערכים אחרים משתתפים ב־digest החוזה; ברירות המחדל משמרות digest היסטורי ומוסיפות הגבלה שמרנית. בדיקות סינתטיות קיימות מגדירות 1ms במפורש כדי לשמר ריצה מהירה; בדיקות התזמון החדשות משתמשות ב־1000ms ובשעון מוזרק.

הבירור/ה־replay הראשון לאחר dispatch יכול להתחיל מיד. כל ניסיון התאוששות שומר recoveryNotBefore באותה טרנזקציה עם צריכת תקציב הניסיון, לפני IO. המועד משותף ל־lookup ול־replay, כך שמעבר ביניהם, worker נוסף או restart אינם עוקפים את המרווח. קריאה מוקדמת מחזירה RECOVERY_BACKOFF_REQUIRED ללא IO וללא שינוי המונים. כשל commit acknowledgement אינו משחרר את ההמתנה. אין לולאת sleep בתוך הבקשה; המפעיל יכול לחזור לאחר המרווח. זהו מרווח קבוע מפורש, לצד תקרות מספר ניסיונות ו־deadline שכבר קיימות.

replay נחסם כאשר now + clockMarginMs מגיע ל־providerNotAfter; גם זמן ההמתנה לקריאת הספק מוגבל לאותו מרווח בטוח. מפתח הספק ו־notAfter המקוריים אינם משתנים. הספק עדיין חייב לאכוף notAfter בעצמו, כולל בקשה ישנה שמתעכבת אחרי הבדיקה המקומית. מרווח זה מניח סטיית שעון בתוך הגבול שהמפעיל אישר; הוא אינו הוכחה לסנכרון שעונים בפריסה. שעון שחזר לאחור מאריך backoff שמור במקום לשחררו מוקדם. אין שינוי בזהות הפעולה או הרשאת replay כתוצאה מפקיעת ההמתנה.

בדיקות test_recovery_timing.py מכסות פתיחה מחדש, חסימה משותפת לשני מסלולי התאוששות, אי־צריכת תקציב בניסיון מוקדם, גבול מדויק של זמן מותר, אובדן acknowledgement ומרווח לפני expiry. בדיקות שני backends נדרשות ב־CI.

### G3 — התראות עמידות ומדדי ביצוע למפעיל מורשה

נוספה טבלת execution_notice, עם migration 6 ב־PostgreSQL והרחבה additive ב־SQLite. לפני הפעלת runtime מול PostgreSQL קיים יש להריץ את מנגנון migrate הקיים עם הרשאת בעל הסכימה; בדיקת readiness מזהה גרסת סכימה ישנה. אין ל־runtime צורך בהרשאת יצירת טבלאות לצורך דיווח שוטף.

ה־executor שומר התראה ממוזערת בקודים מוגדרים מראש עבור unknown/pending, conflict, חסימת replay/recovery ומיצוי תקציב. לכל organization/receipt/code נשמר notice_id יציב, first_seen, last_seen ומספר observations. retry של אותה התראה אינו יוצר התראה לוגית חדשה. המספר הוא מספר תצפיות, לא מספר השפעות או ניסיונות ספק; אובדן acknowledgement של כתיבת התראה יכול להוסיף תצפית חוזרת. אין גופי בקשות/תשובות, approval IDs, credential handles או הודעות שגיאה גולמיות ברשומה. היסטוריית ההתראות נשארת גם אחרי פתרון receipt; מצב receipt נוכחי מוצג במדדים בנפרד.

ממשקי read חדשים תחת `/v1/control-plane/executions`:
- `GET /notices?organizationId=...&limit=100&after=...`: רשומות ארגוניות עם cursor של notice_id; הגודל מוגבל ל־100. בסריקה מחזורית יש להתחיל שוב ללא cursor כדי לקלוט רשומות חדשות ועדכונים; UUID אינו רצף זמן או stream cursor.
- `GET /metrics?organizationId=...`: receiptStates, unknownReceipts (כולל dispatching שנותר עמום), outboxBacklog, oldestUnresolvedAgeSeconds ו־noticeObservations לפי קוד. אלה מדדי snapshot ותצפיות היסטוריות, ללא מזהי ארגונים/פעולות בתוויות התוצאה; אין endpoint ציבורי לכל הארגונים.

שני הממשקים דורשים bearer עם scope נפרד `executions:observe` והרשאה לארגון. connections:execute ו־connectors:review אינם מקנים הרשאת צפייה בהתראות. הרשאה זו אינה מאפשרת replay או שינוי receipt. כשל אחסון בקריאה מחזיר שגיאה גנרית ללא פרטי מסד. כשל שמירת התראה מחזיר EXECUTION_NOTICE_STORE_UNAVAILABLE עם executionState העמום, ואינו מאפשר dispatch נוסף. במהלך outage של האחסון אין הבטחת שמירת התראה; לאחר חזרת האחסון המדדים עדיין מגלים receipts עמומות, וניסיון מורשה נוסף יכול לשמור את ההתראה.

הבדיקות מכסות מיצוי תקציב וקריאה אחרי פתיחה מחדש, זהות יציבה, מונים מקבילים, בידוד ארגונים, pagination, הרשאת scope נפרדת, אי־חשיפת payload, כשל כתיבת התראה ושינוי backlog לאחר מסירת audit ללא IO עסקי. המנגנון הוא inbox מקומי למפעיל; לא נוספה שליחת הודעות חיצוניות או הבטחת מסירת התראה למערכת ניטור שלא הוגדרה. הצפנת metadata במנוחה נשארת סעיף נפרד במטריצת הקבלה.

### G4 — quarantine בעקבות תוצאות סופיות סותרות

כאשר coordinator מקבל בתוך חלון ההמתנה תשובה סופית מאומתת, אך worker אחר כבר שמר מצב סופי הפוך (succeeded לעומת failed_no_effect), נשמר outcomeConflicted ב־receipt יחד עם התראת EXECUTION_OUTCOME_CONFLICT באותה טרנזקציה. מצב הביצוע המקורי, ciphertext ואירוע outbox המקורי נשארים כפי שנשמרו לצורכי ביקורת. קריאות עתידיות מחזירות חסימה ללא payload, גם אחרי restart, ולא מבצעות פעולה עסקית נוספת. אין endpoint שמנקה את הדגל או אישור ידני שהופך את הסתירה להיתר replay.

שתי ראיות לאותו מצב סופי אינן סתירה בפני עצמן. אי־התאמת key/account/binding/contract או תשובה שלא עברה אימות אינן ראיה סמכותית שמאפשרת לשנות receipt. תוצאה שהגיעה אחרי ביטול/timeout ונזרקה ב־ProviderCalls אינה עוברת להמשך coordinator; מגבלת האמון הזו נשארת כפי שתועדה בסעיף cancellation. כשל בשמירת בדיקת הסתירה אינו מוחזר כהצלחה קיימת לבקשה שזיהתה אותו; האחסון חייב לחזור לפעולה כדי לקבע quarantine עמידה.

בדיקות test_outcome_conflicts.py מריצות שני lookups חופפים בשני הכיוונים, בודקות תשובות מסכימות לצד סותרות, מאמתות שמירת ciphertext/outbox, חסימת גישה אחרי פתיחה מחדש, ו־rollback אטומי כששמירת ההתראה נכשלת. locally: 244 בדיקות עברו ו־108 דולגו בהעדר PostgreSQL/Docker; נדרש CI עדכני.

### G4 — מטריצת קריסות, גרסת binding וחבילת הפצה

נוספה test_execution_crash_matrix.py: תהליך ילד מסתיים ב־exit(42) לפני intent, אחרי intent, אחרי dispatch commit, אחרי witness commit ולפני IO, אחרי result commit ולפני תשובה, ואחרי audit delivery commit. מופע חדש בודק האם מותר להמשיך או נדרש unknown/quarantine, וסופר השפעות ב־ledger ספק עצמאי. אם dispatch נשמר אבל witness טרם נשמר, העצירה היא quarantine ולא ניסיון חדש. בדיקות אלה משלימות את קריסת provider commit ואת קריסת pending שתועדו קודם.

ExecutionIntent/Receipt שומרים bindingSchemaVersion=1 במפורש. היעדר השדה ב־receipt ישנה מפורש כ־v1 בלבד; אין שכתוב של digest היסטורי. חישוב binding מקבל את הגרסה שנשמרה; גרסה שאינה נתמכת נחסמת בלי IO. תמיכה עתידית בגרסה נוספת תחייב מימוש מפורש המשמר את אלגוריתם v1 ומבחני מעבר.

README, SPEC, תיעוד מיגרציות ו־UCS19_RUNBOOK.md עודכנו לפי המימוש. cryptography נוספה לתלויות הבסיס מפני שה־runtime מייבא אותה גם ללא extras. נבנה wheel מקומי, נטען ממנו app ונבדקה סכימת OpenAPI עם 23 paths; CI כולל כעת build ו־import מה־wheel. הרגרסיה המקומית עברה עם 255 בדיקות ו־115 דילוגים בהיעדר PostgreSQL/Docker. המטריצה מחייבת CI עדכני בשני backends; הצפנת metadata וקבלת Owner עדיין לא הוכחו.

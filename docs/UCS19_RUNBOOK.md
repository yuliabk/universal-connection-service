# UCS-19 — הפעלה והתאוששות

מסמך זה מתאר את הממשקים הקיימים. הוא אינו אישור לפריסה או להרצת ספק אמיתי. פערי הקבלה נשמרים ב־UCS19_ACCEPTANCE.md.

## לפני הפעלת כתיבה

1. לבחור אחסון עמיד: UCS_STATE_DB_PATH עבור SQLite מקומי או UCS_DATABASE_URL עבור PostgreSQL. מצב זיכרון אינו מתאים ל־receipts עמידים.
2. ב־PostgreSQL להריץ `ucs-db migrate` עם הרשאת DDL, ואז `ucs-db status`. גרסת הסכימה הנוכחית היא 7. מיגרציה 7 מכינה את הטבלאות; ה־runtime דורש גם profiles ומפתחות הצפנה כמפורט ב־UCS19_METADATA_ENCRYPTION.md. runtime רגיל אינו מריץ מיגרציות; גרסה ישנה נחסמת.
3. למרחב חדש בלבד, לטעון UCS_METADATA_PROFILE_ID / UCS_METADATA_KEYRING_JSON ול־witness את UCS_WITNESS_METADATA_PROFILE_ID / UCS_WITNESS_METADATA_KEYRING_JSON ו־UCS_EXECUTION_WITNESS_ID. להריץ `python -m universal_connection_service.storage_runtime --role primary --sqlite-path <new-primary-path> --confirm-new-keyspace` ושוב עם `--role witness --sqlite-path <new-witness-path>`. PostgreSQL: להחליף `--sqlite-path` ב־`--postgres-env <env-name>` למסד ריק ונפרד שכבר קיים. אלה אינן פקודות migration או פתרון ל־restore/quarantine; אין למחוק נתונים קיימים.
4. לטעון UCS_EXECUTION_WITNESS_ID ונתיב/DSN של witness קיים; לטעון UCS_RECEIPT_KEYRING_JSON ממנגנון סודות ו־UCS_EXECUTION_TARGETS_JSON עם חשבון, actor, capability וגרסת מחבר מאושרים. ראו את החוזים המדויקים ב־DURABLE_EXECUTION.md. אין לשמור מפתחות בקוד או בארגומנט shell גלוי.
5. להגדיר UCS_CONTROL_PLANE_CREDENTIALS_JSON עם tokenSha256 ו־executionActors מפורשים. להגדיר UCS_CAPABILITY_EFFECTS_JSON לקריאות שעברו בדיקת host. אישור promotion או readOnly בבקשה אינם תחליף לסיווג effects.
6. ספק שתומך ב־recovery דורש חוזה מקובע, ראיית בדיקה ואישור מפעיל. יש להתאים חלון dedup, notAfter, clockMarginMs, recoveryBackoffMs ותקציב lookup לספק בפועל. בדיקות ספק סינתטי אינן אישור לחוזה ספק אחר.

## טיפול במצב פעולה

| מצב/קוד | פעולת המפעיל |
| --- | --- |
| prepared | לא הוכח dispatch; הבקשה המקורית יכולה להמשיך עם אישור קשור תקף |
| dispatching / OUTCOME_UNKNOWN | לשמר operationId; לברר דרך reconcile מורשה. אין לייצר מזהה חדש כדי לעקוף אי־ודאות |
| pending | lookup בלבד עד תוצאה סופית; replay אינו שולח שוב עבודה accepted |
| RECOVERY_BACKOFF_REQUIRED | להמתין לפי החוזה לפני ניסיון נוסף; אין צורך באישור או operationId חדשים |
| RECOVERY_BUDGET_EXHAUSTED / REPLAY_BUDGET_EXHAUSTED | לעצור ניסיונות עסקיים ולבדוק את ההתראה; הגדלת תצורה אינה משנה את חוזה ה־receipt המקובע |
| succeeded / failed_no_effect | להחזיר תוצאה שמורה למורשה; פעולה עסקית חדשה דורשת זהות ואישור נפרדים |
| RESULT_EXPIRED | payload פג; זהות הפעולה נשמרה ואין לשלוח אותה מחדש |
| EXECUTION_RESTORE_QUARANTINED | לעצור כתיבה במרחב המושפע ולשחזר רישום סמכותי; אין לאפס witness או למחוק receipt |
| EXECUTION_OUTCOME_CONFLICT | לעיין בהתראה ובראיות הספק. התוצאה המקורית נשמרת לביקורת אבל אינה נמסרת כתוצאה מוסכמת; אין endpoint לניקוי החסימה |

ממשקי POST תחת `/v1/control-plane/executions` הם `/reconcile` ו־`/replay`, עם body הכולל request ו־context. הראשון דורש executions:reconcile; השני executions:replay וביצוע עסקי עדיין דורש את האישור המקורי התקף. bearer, credential handle ואישור עסקי הם מנגנונים נפרדים.

## ניטור, retention ו־restore

`GET /v1/control-plane/executions/notices?organizationId=...` ו־`/metrics?organizationId=...` דורשים executions:observe לארגון. התראות הן היסטוריות; observations אינו מונה השפעות ספק. יש לעקוב אחרי unknownReceipts, outboxBacklog ו־oldestUnresolvedAgeSeconds. אין שליחת הודעות חיצוניות אוטומטית.

workers פנימיים מוסרים outbox ומוחקים ciphertext שפג. כשל במסירת audit אינו מפעיל ספק שוב. מחיקת payload אינה מוחקת tombstone. גיבויים, WAL ושטח דיסק פנוי דורשים מדיניות retention והצפנה ברמת הפריסה; מחיקת row אינה הוכחת מחיקה פיזית מכל עותק.

יש לשמור את witness ולגבותו בנפרד מ־primary. אין לשחזר את שניהם לאותה נקודת עבר ואז לפתוח כתיבה. אובדן שני מקורות המידע אינו ניתן להכרעה מתוך UCS בלבד; נדרש רישום ספק/גיבוי סמכותי לפני חידוש כתיבה.

תוצאות מוצפנות ב־AES-GCM עם הפרדת tenant ו־keyring המאפשר rotation. metadata נשמר מוצפן ב־runtime עם profiles ומפתחות שהוכנו מראש. העברת נתונים ישנים עדיין לא הושלמה; עותקי legacy, WAL וגיבויים ישנים נשארים רגישים. גם הגבלת הרשאות ומדיניות ניהול מפתחות דורשות תצורת פריסה מתאימה. TLS בחיבור PostgreSQL אינו הוכחה להצפנה במנוחה.

## מעבר מ־legacy לאחסון מוצפן

הפעלת UCS_STATE_DB_PATH או UCS_DATABASE_URL על מסד legacy אינה מפעילה migration אוטומטי. יש לעצור ולנקז writers ופעולות ספק, לשמור גיבויים, ולהריץ את metadata_migration מול זוג מקורות וזוג יעדים חדשים בהתאם ל־[הוראות המעבר](UCS19_METADATA_ENCRYPTION.md). יש לשמר את witness identity ואת מפתחות payload הישנים. מיקומי DSN ומפתחות נטענים מסודות המארח בלבד.

כשל מותיר יעד לא מאומת חסום; אין לאפס profile כדי לעקוף אותו. אחרי הצלחה יש להעביר את כל ה־writers ליעדים ולא להחזיר את המקורות לכתיבה. מסדי מקור, WAL וגיבויים עדיין רגישים, והטיפול בהם נפרד מההעברה.

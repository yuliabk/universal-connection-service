# UCS-19 — השלמת הצפנת metadata

מצב: תשתית ההצפנה חוברה לממשקי StateStore. גם ה־witness חובר לאחסון מוצפן עצמאי. ה־runtime מחייב תצורת הצפנה ומסדים שהוכנו מראש. מעבר נתונים קיימים טרם הושלם. אין לטעון שהפעלת UCS הקיימת מצפינה metadata רק משום שמיגרציה 7 הותקנה.

## החלטת עבודה

בהיעדר יעד פריסה מוגדר, העבודה מתקדמת בהצפנה בשכבת האפליקציה עבור SQLite ו־PostgreSQL. כך ניתן לבדוק את ההגנה על התוכן גם מול קריאה ישירה במסד, בלי להסתמך על הצהרה על דיסק מוצפן. בחירת פריסה אחרת בידי Owner יכולה לשנות את מימוש שכבת האחסון; דרישת ההגנה עצמה נשארת.

יש להצפין את התוכן והמזהים העסקיים ב־receipts, attempts, outbox, audit, approvals, workflows, evidence, connector metadata ו־witness. אינדקסים של tenant וזהות רשומה יהיו HMAC עם מפתח עצמאי, ולא hash לא ממופתח. מבנה המסד, שמות סוגי הרשומות, מספר הרשומות, שוויון אינדקסים ומונה revision יישארו גלויים. timestamps, actor, account, operationId ותוכן עסקי יהיו בתוך envelope. ההצפנה אינה מחליפה הרשאות או את עדות ה־witness מפני rollback.

## תשתית שמומשה

`metadata_crypto.py` משתמש ב־AES-256-GCM, nonce אקראי, מפתחות נגזרים לפי tenant ו־AAD הקשור לסוג הרשומה וזהותה. keyId וגרסת מעטפת מאומתים; plaintext, גרסה לא מוכרת, מפתח חסר או שינוי מעטפת נחסמים. מפתח אינדקס עצמאי חייב להישאר קבוע לאורך חיי מרחב הפעולות: החלפתו בלי migration עלולה להפוך פעולה קיימת ל־not found ולפתוח dispatch כפול.

`metadata_storage.py` מספק מסמכים מוצפנים, directory מוצפן של tenants, אינדקסים אטומים, insert-if-absent, CAS, pagination וטרנזקציה משותפת לכמה מסמכים. כל פתיחת טרנזקציה מאמתת profile קיים, טביעת מפתח האינדקס ו־probe מוצפן. provisioning מפורש ואינו fallback ב־startup; profile חסר או שונה נחסם. מיגרציה 7 מוסיפה את שלוש הטבלאות, ללא שינוי נתונים קיימים.

ב־rotation מפתח הנתונים הפעיל משתנה, אבל האינדקסים נשארים יציבים. מפתחות קודמים נדרשים עד השלמת re-encryption גם של directory ושל probe. rotate_metadata_batch מספק מעבר ואימות באצוות; אין להסיר מפתח ישן לפני מעבר מלא ואימות כמפורט בהמשך.

## שילוב שנותר לביצוע

1. ממשקי StateStore מחוברים למאגר המסמכים המוצפן ול־runtime תוך שימור טרנזקציה יחידה לצריכת approval ו־dispatch ול־result/outbox. אין פירוש SQL גנרי כדי לנחש אילו ערכים להצפין.
2. witness נפרד מחובר לפורמט המוצפן, כולל provisioning וטעינה ב־runtime, בלי לשנות receiptId, providerKey, attemptCount או binding.
3. runtime דורש profiles ומפתחות מאומתים. תצורה חלקית, מפתח חסר או נתוני legacy נחסמים לפני dispatch; אין fallback למסד חדש או לאחסון גלוי.
4. להוסיף מעבר offline לנתונים קיימים: לעצור writers, להעתיק ליעד מוצפן חדש, לאמת ספירות וזהויות והיכולת לפענח את כל סוגי הרשומות, ולהפעיל רק כאשר primary ו־witness תואמים. אין לייצר מזהים חדשים או לבצע פעולות ספק בעת ההעברה. המסד הישן, WAL וגיבויים נותרים עותקים רגישים עד טיפול נפרד בפריסה.
5. להוסיף re-encryption מוגבל באצוות עם CAS ומעקב אחר key IDs, בלי מחיקת tombstones ובלי הרחבת חלון replay.
6. להריץ את מטריצת הקריסה, worker stale, audit outage, restart, concurrency ובידוד עם האחסון המוצפן בשני backends. לבדוק קריאה ישירה של כל טבלאות היעד, כולל witness, ולוודא שמזהים ותוכן סינתטיים אינם מופיעים בהם בטקסט.

## גבולות הראיה הנוכחית

בדיקות `test_metadata_crypto.py` בודקות tenant/AAD, tampering, framing של אינדקסים, תצורה פגומה ו־rotation. `test_metadata_storage.py` בודקות restart, CAS בין מופעים, rollback של שני מסמכים, pagination, מפתחות שגויים וקריאה ישירה במסד. ה־bodies בבדיקת rollback מייצגים approval ו־receipt; אין זו עדיין בדיקת coordinator אמיתי עם האחסון המוצפן.

העלות הצפויה היא הצפנה/פענוח לכל גישה, directory מוצפן וכתיבות נוספות עבור lookup aliases. סריקות תפעוליות יעברו באצוות לפי tenant; אין להעמיס את כל המסד לזיכרון כדי לשמר את ממשק SQL הישן. מפתח האינדקס הוא סוד ארוך־חיים; אובדנו מחייב שחזור מפתח או migration מאומת ואינו הרשאה לפתוח keyspace חדש.

## חיבור ממשקי הבקרה

`EncryptedControlStore` מחבר כעת את ConnectorStateStore, EvidenceStore, AuditStore, ApprovalStore ו־WorkflowStore למסמכים מוצפנים, בלי ירושה או delegation לכתיבה בטבלאות הגלויות. ה־runtime מפעיל אותו כחלק מ־EncryptedStateStore, יחד עם ReceiptStore ו־witness מוצפן עצמאי.

האישורים נשמרים תחת tenant ומפתחים opaque. ממשק get_approval הקיים מקבל hash בלי organization; עבורו נשמר locator מוצפן במרחב host פנימי, שמצביע על tenant ונגיש רק לקוד האחסון. אין endpoint למציאת ארגון לפי locator. אותם locators שומרים על ייחודיות גלובלית קיימת של audit/evidence/workflow IDs. locator, המסמך וה־request alias של workflow נוצרים באותה טרנזקציה.

צריכת אישור, revocation, claim ועדכון workflow קוראים ונועלים את המסמך בתוך טרנזקציה ומעדכנים ב־CAS. lease נשמר בתוך ciphertext גם כשהוא מוחרג מסריאליזציית ה־API. revision של המסמך הוא מנגנון אחסון נפרד מ־revision העסקי של workflow; claim/release אינם משנים את האחרון. עדכון workflow רשאי לשנות רק את השדות שהמימוש הקודם עדכן ואינו משנה request identity או fingerprint.

רשימות לפי request/kind מסננות לאחר פענוח באצוות בתוך tenant. הדבר משמר את החוזה הקיים אך מגדיל את עלות הקריאה לעומת אינדקס SQL ייעודי; אין טענת שיפור ביצועים. ה־ports הקיימים מחזירים list ולכן התוצאה עצמה עדיין יכולה להיות גדולה. לפני הרחבת שימוש production נדרשת מדידת עומס ותקצוב מתאים.

## חיבור ReceiptStore ומעברי הביצוע

`EncryptedStateStore` מחבר את יתר ממשקי StateStore למאגר המוצפן ומשתמש מחדש במעברי המצב הקיימים של SQLReceiptStore. פעולות האחסון הופרדו ל־hooks מפורשים: טעינת אישור, צריכה ונעילה, שמירת receipt וניסיון ביצוע, וסיום עם תוצאה ו־outbox. אין תרגום SQL גנרי ואין forwarding לטבלאות ה־metadata הגלויות; מסלול SQL שלא הוחלף נכשל במפורש.

צריכת האישור ושמירת dispatch/attempt מתבצעות בטרנזקציה מוצפנת אחת. completion שומר receipt, payload ואירוע outbox יחד. אינדקס pending מוצפן מאפשר acknowledgement בלי מחיקת אירוע הביקורת; יצירת audit והסרת pending אטומיות, וה־eventId המקורי נשמר. retention מוחק רק payload והפניית הסריקה שלו, ומעדכן resultPurgedAt בלי להסיר receipt או מפתח ספק.

גם notices, תקציבי recovery, backoff, quarantine ותצפית תפעולית משתמשים במסמכים מוצפנים. רשימות שומרות על סדר המזהים וה־cursor של הממשק הישן באמצעות פענוח באצוות ובחירת התוצאות המוגבלות בזיכרון; זמן הסריקה אינו מוגבל לגודל הדף המוחזר. כך נשמרת התאימות בלי לחשוף timestamps או מזהים באינדקסים גלויים, במחיר קריאות ופענוחים נוספים.

הבדיקות מפעילות את ConnectionService וה־DurableExecutor האמיתיים מעל StateStore המוצפן, כולל retry, lookup, replay, pending, expiry/revocation, CAS, אובדן acknowledgement, rollback של approval/attempt ושל completion/outbox, מסירת audit ו־retention. ה־witness בבדיקות אלה משתמש כעת במימוש המוצפן ובמסד נפרד, כמפורט בהמשך; migration וכל מטריצת הקריסה בתהליכים נפרדים על שני האחסונים המוצפנים עדיין נדרשים.

## witness מוצפן ועצמאי

`EncryptedDispatchWitness` שומר זהות ועדויות dispatch במאגר מוצפן נפרד ומשתמש באותם כללי התאמה ו־quarantine של DispatchWitness. המפתח לאינדקס קבוצת הניסיונות הוא HMAC של tenant/operation/profile; רשומות הניסיונות עצמן append-only ומוצפנות. latest מחושב מתוך הרשומות של אותה פעולה, בלי מצביע mutable שהיעלמותו עלולה להסתיר ניסיון שכבר נשלח.

provisioning מתאפשר רק באזור מוצפן ריק, ללא נתוני primary קיימים או טבלאות witness ישנות. הוא אינו כלי migration או איפוס. identity נבדקת בכל טרנזקציה, ואיסור שיתוף מסד עם primary נשמר גם כשה־primary הוא EncryptedStateStore.

בדיקות חוזי הביצוע המוצפנים משתמשות כעת ב־witness מוצפן: ב־SQLite בקובץ עצמאי, וב־PostgreSQL במסד נפרד שנוצר ונמחק רק בתוך fixtures סינתטיים. נוספו בדיקות restore חסר/ישן, כשל witness ואובדן acknowledgement, קריאת אחסון ישירה ובדיקות זהות והפרדת מסדים. מעבר offline וראיות קריסה בתהליכים נפרדים כשההצפנה פעילה עדיין נדרשים.

## הפעלה דרך runtime ואתחול מרחב חדש

ה־runtime בוחר כעת EncryptedStateStore כאשר מוגדר אחסון מתמשך. יש לבחור בדיוק אחד מבין UCS_STATE_DB_PATH ו־UCS_DATABASE_URL, ולהגדיר UCS_METADATA_PROFILE_ID ו־UCS_METADATA_KEYRING_JSON. הנתיב/מסד וה־profile חייבים להתקיים מראש. SQLite נפתח ב־mode=rw ואינו יוצר קובץ חלופי כשנתיב שגוי. ללא תצורת אחסון כלל נשאר מצב memory, שאינו מאפשר ביצוע עסקי עמיד.

מבנה ה־keyring הוא אובייקט JSON עם שלושה שדות בלבד: activeKey, keys ו־indexKey. keys ממפה מזהי מפתח ל־Base64 של 32 בתים אקראיים; activeKey מפנה למפתח פעיל. indexKey הוא Base64 של מפתח אקראי נפרד בן 32 בתים. שמות שדות כפולים, מפתח חסר או שימוש באותו חומר מפתח להצפנה ולאינדקס נדחים. יש לטעון את הערכים ממנגנון סודות, בלי להעביר אותם בארגומנטים או לשמור אותם במאגר.

ל־witness מוגדרים בנפרד UCS_WITNESS_METADATA_PROFILE_ID ו־UCS_WITNESS_METADATA_KEYRING_JSON, בנוסף ל־UCS_EXECUTION_WITNESS_ID ולנתיב/DSN הקיימים. executor_from_env דורש primary מוצפן ו־witness מוצפן; מפתחות payload ב־UCS_RECEIPT_KEYRING_JSON נשארים נפרדים. PostgreSQL ממשיך לדרוש witness במסד PostgreSQL נפרד.

אתחול למרחב חדש בלבד, לאחר טעינת משתני המפתחות והזהויות:

```text
python -m universal_connection_service.storage_runtime --role primary --sqlite-path <new-primary-path> --confirm-new-keyspace
python -m universal_connection_service.storage_runtime --role witness --sqlite-path <new-witness-path> --confirm-new-keyspace
```

ב־PostgreSQL מחליפים את --sqlite-path ב־--postgres-env עם שם משתנה סביבה שמכיל DSN של מסד ריק שכבר נוצר. פקודת provisioning מריצה את מיגרציות הסכימה; נדרשת עבורה הרשאת DDL. היא אינה מאתחלת profile קיים ואינה משמשת לעקיפת quarantine. כשל provisioning יכול להשאיר קובץ חדש ריק/חלקי לבדיקה, אך startup לא ישתמש בו ללא profile ו־witness תקינים.

runtime דוחה טבלאות legacy שמכילות נתונים, גם אם לצדן קיים profile מוצפן תקין. הוא גם דוחה מסד witness המשמש כ־primary. זה שינוי מכוון מהפעלת UCS_STATE_DB_PATH לבדה: אין fallback לכתיבה גלויה ואין אימוץ אוטומטי של keyspace ישן. נתונים קיימים דורשים מעבר offline שעדיין בבנייה; אין למחוק אותם כדי לעבור את בדיקת האתחול.

## מטריצת קריסה מוצפנת בתהליכים נפרדים

`test_encrypted_execution_process.py` מריץ את תרחישי הקריסה הקיימים גם מול EncryptedStateStore ו־EncryptedDispatchWitness. תהליכי הבדיקה פותחים profiles קיימים ואינם מאתחלים או מאפסים אותם. ה־ledger של הספק נמצא בקובץ נפרד ונבדק אחרי מות התהליך.

התרחישים כוללים עצירה לפני/אחרי intent, אחרי dispatch, אחרי witness, אחרי result ו־audit acknowledgement; קריסה מיד אחרי commit אצל הספק; pending עמיד; ותהליך ישן שנעצר לפני או אחרי השפעת הספק בזמן שתהליך נוסף מבצע replay מוגן. נבדקים מספר ההשפעות, זהות התוצאה, outbox והיעדר דריסת תוצאה סופית. כל עשרת התרחישים עברו ב־SQLite וב־PostgreSQL ב־CI של db5278c (565 בדיקות ללא דילוגים).

## החלפת מפתחות metadata באצוות

`metadata_rotation.rotate_metadata_batch(repository, cursor=None, limit=100, verify_only=False)` מטפל לכל היותר ב־limit רשומות בכל טרנזקציה. הוא עובר על מסמכים, directory של tenants ולבסוף probe של ה־profile. כל envelope מפוענח ומאומת לפני שימוש ב־keyId; החלפה משתמשת ב־CAS על הגרסה וה־ciphertext המקוריים. כשל אימות או CAS מבטל את כל האצווה. גוף המסמך וזהויות הפעולה אינם משתנים; רק גרסת האחסון והמעטפת מתעדכנות.

RotationBatch מחזיר cursor להמשך, scanned, changed ו־key_counts של המעטפות המאומתות אחרי האצווה. יש להעביר את ה־cursor המוחזר לקריאה הבאה עד שהוא None. ניתן לשמור cursor ולחדש עם אותם profile, indexKey ומפתחות נתונים. cursor אינו אישור שורות שהתרחשו לפניו ואינו הוכחה שמותר להסיר מפתח.

תהליך תחזוקה: להפיץ keyring עם המפתח החדש והישן לכל הקוראים, להעביר את כל ה־writers למפתח החדש, להריץ מעבר מלא בנפרד על primary ועל witness, ואז להריץ verify_only=True מההתחלה ולוודא שבכל האצוות מופיע רק המפתח החדש. יש לעצור writers ישנים לפני החלטת הסרה, או לבצע את התחזוקה כולה offline. יש לוודא גם שניתן לפתוח ולקרוא את שני המאגרים עם המפתחות המיועדים להישאר. החלפת indexKey אינה נתמכת.

ה־repositories זמינים בממשק התחזוקה של store.repository ושל executor.witness.repository; אין endpoint ציבורי לסריקה או rotation. מפתחות ResultCipher הפנימיים נפרדים ואינם מוחלפים במהלך זה. גיבויים, WAL ועותקים ישנים עדיין עשויים להזדקק למפתחות קודמים. מעבר מוצלח אינו אישור למחוק מפתחות גיבוי.

בדיקות test_metadata_rotation.py מכסות מעבר של receipt ו־witness תוך שמירת retry יחיד ואירוע audit, עצירה וחידוש, סריקת אימות ללא כתיבה ו־rollback של אצווה בעקבות ciphertext פגום או CAS שנכשל.

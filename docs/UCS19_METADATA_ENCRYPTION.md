# UCS-19 — השלמת הצפנת metadata

מצב: תשתית הצפנה ואחסון טרנזקציוני מומשה; שילוב בממשקי StateStore וב־runtime טרם הושלם. אין לטעון שהפעלת UCS הקיימת מצפינה metadata רק משום שמיגרציה 7 הותקנה.

## החלטת עבודה

בהיעדר יעד פריסה מוגדר, העבודה מתקדמת בהצפנה בשכבת האפליקציה עבור SQLite ו־PostgreSQL. כך ניתן לבדוק את ההגנה על התוכן גם מול קריאה ישירה במסד, בלי להסתמך על הצהרה על דיסק מוצפן. בחירת פריסה אחרת בידי Owner יכולה לשנות את מימוש שכבת האחסון; דרישת ההגנה עצמה נשארת.

יש להצפין את התוכן והמזהים העסקיים ב־receipts, attempts, outbox, audit, approvals, workflows, evidence, connector metadata ו־witness. אינדקסים של tenant וזהות רשומה יהיו HMAC עם מפתח עצמאי, ולא hash לא ממופתח. מבנה המסד, שמות סוגי הרשומות, מספר הרשומות, שוויון אינדקסים ומונה revision יישארו גלויים. timestamps, actor, account, operationId ותוכן עסקי יהיו בתוך envelope. ההצפנה אינה מחליפה הרשאות או את עדות ה־witness מפני rollback.

## תשתית שמומשה

`metadata_crypto.py` משתמש ב־AES-256-GCM, nonce אקראי, מפתחות נגזרים לפי tenant ו־AAD הקשור לסוג הרשומה וזהותה. keyId וגרסת מעטפת מאומתים; plaintext, גרסה לא מוכרת, מפתח חסר או שינוי מעטפת נחסמים. מפתח אינדקס עצמאי חייב להישאר קבוע לאורך חיי מרחב הפעולות: החלפתו בלי migration עלולה להפוך פעולה קיימת ל־not found ולפתוח dispatch כפול.

`metadata_storage.py` מספק מסמכים מוצפנים, directory מוצפן של tenants, אינדקסים אטומים, insert-if-absent, CAS, pagination וטרנזקציה משותפת לכמה מסמכים. כל פתיחת טרנזקציה מאמתת profile קיים, טביעת מפתח האינדקס ו־probe מוצפן. provisioning מפורש ואינו fallback ב־startup; profile חסר או שונה נחסם. מיגרציה 7 מוסיפה את שלוש הטבלאות, ללא שינוי נתונים קיימים.

ב־rotation מפתח הנתונים הפעיל משתנה, אבל האינדקסים נשארים יציבים. מפתחות קודמים נדרשים עד השלמת re-encryption גם של directory ושל probe. אין עדיין כלי rotation של מסד שלם, ולכן אין להסיר מפתח ישן בהסתמך על בדיקות primitive בלבד.

## שילוב שנותר לביצוע

1. לחבר את כל ports של StateStore למאגר המסמכים המוצפן, תוך שימור גבול טרנזקציה יחיד לצריכת approval ול־dispatch, ול־result/outbox. אין לפרש SQL באופן גנרי כדי לנחש אילו ערכים להצפין.
2. לחבר witness נפרד לאותו פורמט בלי לשנות receiptId, providerKey, attemptCount או binding. profile ומפתחות של primary ושל witness חייבים להיבדק לפני IO.
3. להוסיף runtime configuration מפורש עם secrets ממנגנון המארח. תצורה חלקית, מפתח חסר או ניסיון לפתוח store מוצפן במצב רגיל חייבים להיכשל לפני dispatch; אין fallback שקט למסד חדש או לאחסון לא מוצפן.
4. להוסיף מעבר offline לנתונים קיימים: לעצור writers, להעתיק ליעד מוצפן חדש, לאמת ספירות וזהויות והיכולת לפענח את כל סוגי הרשומות, ולהפעיל רק כאשר primary ו־witness תואמים. אין לייצר מזהים חדשים או לבצע פעולות ספק בעת ההעברה. המסד הישן, WAL וגיבויים נותרים עותקים רגישים עד טיפול נפרד בפריסה.
5. להוסיף re-encryption מוגבל באצוות עם CAS ומעקב אחר key IDs, בלי מחיקת tombstones ובלי הרחבת חלון replay.
6. להריץ את מטריצת הקריסה, worker stale, audit outage, restart, concurrency ובידוד עם האחסון המוצפן בשני backends. לבדוק קריאה ישירה של כל טבלאות היעד, כולל witness, ולוודא שמזהים ותוכן סינתטיים אינם מופיעים בהם בטקסט.

## גבולות הראיה הנוכחית

בדיקות `test_metadata_crypto.py` בודקות tenant/AAD, tampering, framing של אינדקסים, תצורה פגומה ו־rotation. `test_metadata_storage.py` בודקות restart, CAS בין מופעים, rollback של שני מסמכים, pagination, מפתחות שגויים וקריאה ישירה במסד. ה־bodies בבדיקת rollback מייצגים approval ו־receipt; אין זו עדיין בדיקת coordinator אמיתי עם האחסון המוצפן.

העלות הצפויה היא הצפנה/פענוח לכל גישה, directory מוצפן וכתיבות נוספות עבור lookup aliases. סריקות תפעוליות יעברו באצוות לפי tenant; אין להעמיס את כל המסד לזיכרון כדי לשמר את ממשק SQL הישן. מפתח האינדקס הוא סוד ארוך־חיים; אובדנו מחייב שחזור מפתח או migration מאומת ואינו הרשאה לפתוח keyspace חדש.

## חיבור ממשקי הבקרה

`EncryptedControlStore` מחבר כעת את ConnectorStateStore, EvidenceStore, AuditStore, ApprovalStore ו־WorkflowStore למסמכים מוצפנים, בלי ירושה או delegation לכתיבה בטבלאות הגלויות. ה־runtime אינו מפעיל אותו עדיין: תחילה יש להשלים ReceiptStore ו־witness תחת אותם גבולות טרנזקציה.

האישורים נשמרים תחת tenant ומפתחים opaque. ממשק get_approval הקיים מקבל hash בלי organization; עבורו נשמר locator מוצפן במרחב host פנימי, שמצביע על tenant ונגיש רק לקוד האחסון. אין endpoint למציאת ארגון לפי locator. אותם locators שומרים על ייחודיות גלובלית קיימת של audit/evidence/workflow IDs. locator, המסמך וה־request alias של workflow נוצרים באותה טרנזקציה.

צריכת אישור, revocation, claim ועדכון workflow קוראים ונועלים את המסמך בתוך טרנזקציה ומעדכנים ב־CAS. lease נשמר בתוך ciphertext גם כשהוא מוחרג מסריאליזציית ה־API. revision של המסמך הוא מנגנון אחסון נפרד מ־revision העסקי של workflow; claim/release אינם משנים את האחרון. עדכון workflow רשאי לשנות רק את השדות שהמימוש הקודם עדכן ואינו משנה request identity או fingerprint.

רשימות לפי request/kind מסננות לאחר פענוח באצוות בתוך tenant. הדבר משמר את החוזה הקיים אך מגדיל את עלות הקריאה לעומת אינדקס SQL ייעודי; אין טענת שיפור ביצועים. ה־ports הקיימים מחזירים list ולכן התוצאה עצמה עדיין יכולה להיות גדולה. לפני הרחבת שימוש production נדרשת מדידת עומס ותקצוב מתאים.

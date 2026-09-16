# Universal Connection Service — מפרט מערכת

## מטרה וגבולות

UCS חושף יכולות עסקיות בחוזה יציב, בלי לחייב caller להכיר את transport של המחבר. מתאמי MCP ו־REST/OpenAPI ממומשים; transports נוספים יכולים לממש ConnectorContract. השירות אינו נתב agent-to-agent ואינו מנפיק הרשאות עסקיות בעצמו.

HTTP execution מאמת bearer, ארגון וצירוף user/agent מורשה לפני גישה לתוצאה או IO. SDK פנימי מניח מארח מאמת. מדיניות, הרשאת API, חשבון ספק ואישור עסקי נבדקים בנפרד. הרשאת review/promotion אינה הרשאת ביצוע.

## זרימה

1. לקבל ConnectionRequest עם actor ויכולת, וליצור ConnectionPlan הניתן לסקירה.
2. לבחור מחבר trusted בארגון ובגרסה המתאימים; מחבר חדש עובר validation ו־promotion מאושר.
3. לבדוק מדיניות וסיווג effects מהימן. caller אינו יכול להפוך פעולה בעלת השפעה לקריאה באמצעות readOnly.
4. לפתור credentials בגבול יציאה באמצעות handle אטום ולוודא חשבון מאושר.
5. לפעולה בעלת השפעה: לקבע operationId ו־binding, לשמור intent, לצרוך אישור ו־dispatch אטומיים ולשמור witness עצמאי לפני IO.
6. לשמור תוצאה סופית מוצפנת ו־audit outbox באותה טרנזקציה. pending/unknown אינם הצלחה ואינם הרשאה לשליחה רגילה חוזרת.
7. recovery משתמש בחוזה ספק מקובע, מפתח מקורי, תקציב ומרווח עמידים. תוצאה סותרת מאומתת גוררת quarantine; restore חסר אינו מאפס זהות פעולה.
8. למסור audit בנפרד, לשמור tombstone אחרי expiry של payload ולאפשר תצפית ארגונית למורשה.

## יכולות ומסמכי חוזה

חוזי runtime נמצאים ב־contracts.py. תכנון policy ואישורים מתועד ב־POLICY_APPROVAL.md; אחסון ב־PERSISTENCE.md ו־POSTGRES_SUPABASE.md; lifecycle ב־CONTROL_PLANE.md; גילוי/build/sandbox במסמכים הייעודיים. UCS-19 מתועד ב־DURABLE_EXECUTION.md, ומיפוי דרישות לראיות ב־UCS19_ACCEPTANCE.md. פקודות הפעלה והתאוששות מרוכזות ב־UCS19_RUNBOOK.md.

## תרחישי קבלה

- שירות ללא מחבר מאושר מחזיר תכנון לבנייה/אימות ונחסם בביצוע.
- קריאה מאושרת מזוהה לפי service/capability בלי חשיפת credentials; סיווג חסר מחייב סקירת host.
- כתיבה, מחיקה, פעולה פיננסית והגדלת הרשאות דורשות אישור אנושי קשור ואחסון עמיד.
- retry של אותה פעולה לאחר crash מחזיר תוצאה קיימת או עוצר לבירור, בלי השפעה כפולה.
- תחרות workers, כשל commit, pending, אישור פג/מבוטל, tenant isolation ו־audit outage מכוסים בבדיקות סינתטיות. מטריצת UCS-19 מפרטת את גבולות הראיה והפערים שטרם נסגרו.

## מחוץ להוכחת המסירה הנוכחית

פריסת Production, חוזה ספק אמיתי, OAuth callback service, מפתחות ונתוני לקוח אמיתיים, RPO/RTO ותשתית ניטור חיצונית אינם מוכחים על ידי הבדיקות הסינתטיות. הצפנת metadata במנוחה נותרה פער מפורש בביקורת UCS-19; הצפנת payload ו־TLS אינם מכסים אותו לבדם. אין להסיק אישור Production ממעבר CI.

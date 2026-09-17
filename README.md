# Universal Connection Service

שירות חיבור ניטרלי לספקים עבור סוכנים ו־plugins. ממשק אחד מתכנן ובודק יכולות עסקיות, מאמת הרשאות ומפעיל מחבר מאושר עם credential handle אטום.

## יכולות קיימות

- מתאמי MCP ו־REST/OpenAPI, גילוי מחברים ו־build/validation/promotion מפוקחים.
- registry, approvals, evidence ו־audit מבודדים לפי ארגון ב־SQLite או PostgreSQL.
- מדיניות, חבילות חתומות, MCPB sandbox, gateway והרשאות לכלי מסוים.
- auto-connect עם workflow עמיד ואישורים אנושיים.
- UCS-19: receipts עמידים, אישור קשור לפעולה, תוצאות מוצפנות, audit outbox, בירור ו־replay מוגן, הגנת restore באמצעות witness עצמאי ותצפית תפעולית מורשית.

UCS-19 עדיין בביקורת קבלה. [מטריצת הקבלה](docs/UCS19_ACCEPTANCE.md) מציגה ראיות ופערים פתוחים. אין טענת מוכנות Production.

## הפעלה מקומית

נדרשים Python 3.11 ומעלה. ב־Linux/macOS:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
uvicorn universal_connection_service.app:app --reload
```

ב־PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m uvicorn universal_connection_service.app:app --reload
```

תיעוד API נמצא ב־`http://127.0.0.1:8000/docs`. ללא תצורה מפורשת אין הרשאה לביצוע עסקי. התקנת dev כוללת תלויות מתאמים ובדיקות; PostgreSQL ו־Docker עצמם נדרשים בנפרד לבדיקות האינטגרציה המתאימות.

אחסון מתמשך מחייב כעת profile ומפתחות metadata, וגם witness מוצפן לכתיבה. ראו [פקודות אתחול ותצורה](docs/UCS19_METADATA_ENCRYPTION.md); הגדרת נתיב או DSN לבדה אינה מספיקה. נתוני legacy מחייבים מעבר מבוקר ואינם מאומצים אוטומטית.

## ממשקים ובטיחות ביצוע

`GET /health`, `GET /v1/connectors` ו־`POST /v1/connections/plan` מספקים בריאות, metadata ותכנון. `POST /v1/connections/execute` מחייב bearer, scope connections:execute וצירוף actor מאושר. תכנון כשלעצמו אינו היתר ביצוע.

כתיבה, מחיקה ופעולה פיננסית דורשות operationId יציב, target מהימן ואישור קשור. פעולה עמומה אינה נשלחת שוב אוטומטית. readOnly של caller אינו מספיק: מסלול קריאה דורש סיווג host מפורש לפי ארגון, יכולת וגרסת מחבר. recovery, replay ותצפית תפעולית משתמשים ב־scopes נפרדים.

## תיעוד ובדיקות

- [מפרט המערכת](docs/SPEC.md), [הפעלה והתאוששות](docs/UCS19_RUNBOOK.md), [תכנון UCS-19](docs/DURABLE_EXECUTION.md).
- [PostgreSQL ומיגרציות](docs/POSTGRES_SUPABASE.md), [Control Plane](docs/CONTROL_PLANE.md), [אישורים ומדיניות](docs/POLICY_APPROVAL.md).
- [OpenAPI](docs/OPENAPI_ADAPTER.md), [MCP](docs/MCP_ADAPTER.md), [Sandbox](docs/MCPB_SANDBOX.md), [auto-connect](docs/AUTO_CONNECT.md).

הרצת רגרסיה: `python -m pytest -q`. לבדיקות PostgreSQL מגדירים UCS_TEST_POSTGRES_URL למסד סינתטי ייעודי; אין להשתמש במסד לקוח. ב־Windows נדרשים PYTHONUTF8=1 ו־PATH הכולל `.venv\Scripts`. CI מריץ PostgreSQL 16 ובדיקות Docker; דילוגים מקומיים אינם הוכחה לכיסוי מסד או sandbox.

# UCS-19 — ביקורת קבלה לפי דרישות

מצב: בביצוע. מעבר CI אינו מוכיח שכל סעיפי המפרט הושלמו. מקור הדרישות הוא מסמכי UCS-19 שנכתבו לפני המימוש (proposal, design, tasks ו־capability spec), והדרישות ב־DURABLE_EXECUTION.md. בקשת ה־Owner להשלים את UCS אישרה התקדמות במימוש; אין כאן אישור Production או סקירת קבלה של Owner שכבר התקיימה.

## מטריצת הדרישות והתרחישים

| דרישה ותרחיש | ראיה בקוד ובבדיקות | הערכת השלמה |
| --- | --- | --- |
| 001: אותה פעולה, requestId חדש ו־restart | execution_binding, prepare_receipt; test_restart_retry_returns_encrypted_result_without_consuming_again, test_reopen_returns_original_receipt_and_same_provider_key | מכוסה ב־SQLite וב־PostgreSQL; תהליך עסקי חיצוני חייב לשמר operationId |
| 001: שינוי יעד או סכום | binding קנוני כולל actor/account/input; test_key_conflict_cannot_overwrite_intent, test_changed_input_conflicts_even_after_success | מכוסה; schemaVersion נמצא בחומר ה־hash, אך אינו שדה עצמאי ב־receipt כפי שהוצע ב־design |
| 002: כשל שמירה או אובדן commit acknowledgement | prepare/begin_dispatch לפני IO, transaction approval ו־witness; בדיקות lost_dispatch_commit_ack, lost_replay_commit_ack ו־dispatch_witness | מכוסה בכשל מוזרק; טרם הוכחו כל נקודות הקריסה בתהליך נפרד בשני backends |
| 002: שני workers | CAS ו־unique key; test_concurrent_instances_have_one_dispatch_winner, test_two_service_instances_share_one_approval_and_effect | מכוסה בשני backends; בדיקות אלה משתמשות במופעים/threads |
| 003: הצלחת ספק ואז crash | test_process_crash_after_provider_commit_then_keyed_lookup_recovers | מכוסה בתהליך ילד עם exit(42), מונה ספק עצמאי ופתיחה מחדש בשני backends; CI 2923b21 |
| 003: accepted אסינכרוני | חוזה dispatchOutcomes מקובע, ProviderOutcome עם בדיקת key/account/binding/contract; test_dispatch_outcomes.py | מומש pending מ־dispatch, ללא replay בזמן pending; בדיקת exit אחרי pending commit וחידוש ב־lookup בשני backends נוספה ומחייבת CI עדכני |
| 004: replay מוגן | RecoveryContract, ReplayPolicy, begin_receipt_replay; test_execution_replay.py | מכוסה בספק סינתטי בעל dedup אטומי ואכיפת notAfter; אין ספק Production מאושר |
| 004: חלון שפג / lookup לא החלטי / none | test_unresolved_lookup_never_reexecutes_and_budget_survives_restart, test_expired_dispatch_is_rejected_locally_and_by_provider_after_cache_eviction | מכוסה; נוספו backoff משותף עמיד ומרווח שעון מפורשים ב־test_recovery_timing.py; מחייב CI עדכני |
| 005: אישור בוטל אחרי כשל | begin_receipt_replay מאמת את האישור המקורי תחת transaction; test_replay_requires_original_still_valid_approval | מכוסה revoked/expired/replacement/missing בשני backends |
| 005: tenant ו־actor | execution_api, executionActors, target account/credential binding; test_execution_auth.py, test_result_access_rechecks_policy_and_actor_before_decryption | מכוסה בגבולות HTTP ו־auto-connect; SDK מניח מארח מאמת |
| 005: עובד ישן חוזר | test_stale_execution_process.py מחזיק ילד חי לפני/אחרי אפקט הספק, מבצע replay בהורה ואז משחרר אותו | נוספה הוכחה ל־receipt סופית שאינה נדרסת, השפעה יחידה ואירוע outbox יחיד; PostgreSQL דורש CI לגרסה זו |
| 006: audit לא זמין / acknowledgement אבד | complete_receipt + outbox באותה transaction; deliver_receipt_audit; test_receipt_audit.py | מכוסה מסירה אידמפוטנטית ו־rollback בשני backends; מצב delivery נשמר בטבלת outbox נפרדת ולא בשדה receipt |
| 007: payload פג / restore ישן | test_receipt_retention.py, test_dispatch_witness.py | מכוסה מחיקת ciphertext בלי שחרור זהות, ו־quarantine כש־primary מפגר אחרי witness; הפעלה דורשת witness שלא שוחזר לאחור יחד עמו |
| 007: תקציב בירור נגמר | lookup_count/maxLookups, maxAttempts/deadlines; בדיקות recovery/replay | עצירת IO מכוסה; נוספו execution_notice עמיד ו־notices/metrics עם הרשאת executions:observe; מחייב CI עדכני |
| 008: חלון הקריסה הקריטי | provider ledger נפרד, child exit, receipt/outbox ושחזור | מכוסה; מטריצת כל נקודות הקריסה והמצבים בין תהליכים עדיין אינה מלאה |

## סעיפים נוספים מה־design ומ־tasks שאינם סגורים

1. מומשו recoveryBackoffMs, recoveryNotBefore עמיד ומשותף ל־lookup/replay ו־clockMarginMs. בדיקות פתיחה מחדש, אובדן commit acknowledgement ופקיעה משתמשות בשעון מוזרק; אומת ב־CI של e61a8d8: 332 בדיקות עברו ללא דילוגים (run 35133361136).
2. נוספו התראות עמידות עם זהות יציבה, מדדי states/backlog/age/notice codes ו־API ארגוני בהרשאת executions:observe. בדיקות restart, בידוד, כשל אחסון ומונים מקבילים נוספו; נדרש CI עדכני.
3. accepted/pending מתשובת dispatch מאומתת מומש בחוזה dispatchOutcomes ובבדיקת crash/resume. אין הסקת success מ־HTTP accepted; הסעיף אומת ב־CI של a8d4630: 322 בדיקות עברו ללא דילוגים, כולל שני backends (run 35132662022).
4. ה־design דורש quarantine לראיה סופית סותרת. כיום תוצאה מאוחרת אינה דורסת terminal receipt; זה אינו בפני עצמו מנגנון תיעוד/בירור של סתירה סמכותית.
5. להשלים fault injection בתהליכים נפרדים לפני/אחרי intent, אחרי dispatch commit ולפני IO, ואחרי result commit לפני תגובת הלקוח/ack של audit. בדיקות transaction וחריגות באותו תהליך הן ראיות משלימות בלבד.
6. לבדוק מעבר גרסאות binding: כיום canonical hash כולל version=1; יש לקבע במפורש כיצד receipt היסטורית מזוהה כאשר גרסת הנרמול משתנה.
7. הצפנת result במנגנון האפליקציה קיימת. receipts/outbox כוללים metadata בטקסט במסד; דרישת הצפנה במנוחה לכל האחסון אינה מוכחת על ידי AES-GCM של payload בלבד. נדרשת הכרעה ומימוש/אכיפה מתאימים; אין לטעון שכבר הוכחה הצפנת כל המסד.
8. לעדכן README ו־SPEC המתארים יכולות שכבר מומשו כדחויות. להשלים הוראות הפעלה, migration, recovery וגבולות הפריסה לפי הממשקים בפועל.
9. G4.3 דורש סקירת Owner וקבלת התוצאה. יש להציג תוצר ובדיקות מלאים לפני בקשת הקבלה; PR טיוטה ו־CI ירוק אינם ראיה שהסקירה התרחשה.

## ראיות שנבדקו

- commit `2923b21`: [CI עם 291 בדיקות שעברו, ללא דילוגים](https://github.com/yuliabk/universal-connection-service/actions/runs/35131204702), כולל PostgreSQL 16 ו־Docker.
- לאחר הוספת בדיקות העובד החי: 213 בדיקות מקומיות עברו, 82 דולגו בהיעדר PostgreSQL/Docker. בדיקת הבידוד בין תהליכים עברה מקומית בשני תזמוני SQLite; PostgreSQL עדיין מחייב CI עדכני.
- fixtures משתמשים בנתונים סינתטיים ובספק נפרד לוגית עם ledger SQLite. הם אינם מוכיחים חוזה של ספק אמיתי, התנהגות רשת Production או הפרדת failure domains של witness בפריסה.

G1/G2 הושלמו בהיקף המתועד. G3/G4 נשארים פתוחים עד סגירת הסעיפים לעיל והצגת ראיות תואמות לכל סעיף.

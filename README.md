# CRC Event Simulator

מערכת סימולציה וניהול דינמית של Alert Sources (סנסורים/התראות) ב-CLI

## תכונות עיקריות
- ניהול מלא של מקורות התראה (Alert Sources): הוספה, מחיקה, עריכה, שדות דינמיים
- ניהול פריטים (Items) לכל מקור
- ניהול ספים (Thresholds) והגדרות (Settings) לכל מקור
- סימולציה של אירועים (כולל יצירת פריטים אוטומטית לסימולציה)
- אוטומציה של יצירת אירועים
- ולידציה מתקדמת, טיפול בשגיאות, לוגינג
- מבנה קונפיגורציה מודרני, תומך בהרחבה
- CLI נוח עם אפשרות חיפוש פריטים

## התקנה
1. ודאו שיש לכם Python 3.8+
2. התקינו את התלויות:

```bash
pip install -r requirements.txt
```

## הפעלה
```bash
python "simulator (1).py"
```

## קבצים עיקריים
- `simulator (1).py` — קוד המקור הראשי
- `config.json` — קובץ קונפיגורציה דינמי
- `default_config.json` — קונפיגורציה דיפולטית (אופציונלי)
- `test_simulator.py` — בדיקות יחידה (pytest)

## בדיקות
להרצת הבדיקות:
```bash
pytest test_simulator.py
```

## תלויות
- Python 3.8+
- [Faker](https://pypi.org/project/Faker/)
- pytest (לבדיקות)

## דוגמה ל-requirements.txt
```
Faker
pytest
requests
```

## תרומה
תרגישו חופשי לפתוח Issues ו-Pull Requests!

---

© 2025 CRC Event Simulator Team

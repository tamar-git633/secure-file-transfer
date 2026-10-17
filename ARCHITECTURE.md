# ארכיטקטורת הפרויקט – מטלה 06, תכנות מערכות דפנסיבי (20937)

מערכת שרת-לקוח להעברת קבצים מוצפנת:
- **שרת** – Python 3.12.1, ‏PyCryptodome, ‏threads.
- **לקוח** – C++20, ‏Visual Studio 2026, ‏Crypto++, ‏winsock.

> המסמך הזה הוא "החוזה" של הפרויקט. כל החלטה שמשנה אותו – מעדכנים כאן קודם.
> שלבי הפיתוח ובדיקות הביניים לכל יחידה: [PLAN.md](PLAN.md).

---

## 1. מבנה תיקיות

```
DefensivyProject/
├── ARCHITECTURE.md
├── PLAN.md
├── server/
│   ├── server.py            # main() – נקודת הכניסה
│   ├── config.py            # קריאת port.info
│   ├── protocol.py          # קבועים, קודים, גדלים, pack/unpack
│   ├── client_session.py    # טיפול בלקוח אחד (רץ ב-thread משלו)
│   ├── crypto_utils.py      # RSA / AES עטיפות ל-PyCryptodome
│   ├── cksum.py             # CRC זהה לפקודת cksum בלינוקס
│   ├── storage.py           # נתוני לקוחות וקבצים בזיכרון + שמירת קבצים לדיסק
│   ├── database.py          # (בונוס – שאלה 3, מתווסף בסוף)
│   ├── port.info
│   └── tests/               # סקריפטי בדיקה (לא מוגשים)
├── client/
│   ├── main.cpp
│   ├── Constants.h          # כל הקבועים – אין מספרי קסם בקוד
│   ├── Endian.h             # כתיבה/קריאה little-endian מפורשת
│   ├── JsonParser.h/.cpp    # parser מינימלי ל-transfer.json
│   ├── Config.h/.cpp        # טעינת transfer.json ובדיקת תקינות
│   ├── ClientInfo.h/.cpp    # קריאה/כתיבה של me.info ו-priv.key
│   ├── Connection.h/.cpp    # socket מעל winsock (RAII)
│   ├── Protocol.h/.cpp      # בניית בקשות ופענוח תשובות
│   ├── RSAWrapper.h/.cpp    # עטיפה ל-Crypto++ (על בסיס דוגמת יחידה 7)
│   ├── AESWrapper.h/.cpp
│   ├── Base64Wrapper.h/.cpp
│   ├── Cksum.h/.cpp
│   ├── FileSender.h/.cpp    # שליחת קובץ אחד ב-streaming
│   ├── FileTransferClient.h/.cpp  # זרימת העבודה המלאה
│   └── Errors.h             # מחלקות חריגה
└── docs/
    └── vulnerabilities.docx # שאלה 2
```

---

## 2. הפרוטוקול (מחייב – אסור לשנות!)

### כללי
- בינארי, מעל TCP.
- **כל השדות המספריים unsigned ו-little-endian.**
- מחרוזות (שם משתמש/קובץ) – שדה קבוע של 255 בתים, **null-terminated**, ריפוד באפסים.

### כותרת בקשה (לקוח → שרת) – 23 בתים
| שדה | גודל | Python struct |
|---|---|---|
| Client ID | 16 | `16s` |
| Version | 1 | `B` |
| Code | 2 | `H` |
| Payload size | 4 | `I` |

פורמט: `"<16sBHI"`

### כותרת תשובה (שרת → לקוח) – 7 בתים
| שדה | גודל |
|---|---|
| Version | 1 |
| Code | 2 |
| Payload size | 4 |

פורמט: `"<BHI"`

### בקשות
| קוד | שם | Payload | גודל |
|---|---|---|---|
| 825 | REGISTER | Name(255) | 255 |
| 826 | SEND_PUBLIC_KEY | Name(255) + PublicKey(160) | 415 |
| 827 | RECONNECT | Name(255) | 255 |
| 828 | SEND_FILE | ContentSize(4) + OrigFileSize(4) + PacketNumber(2) + TotalPackets(2) + FileName(255) + Content(משתנה) | 267 + content |
| 900 | CRC_OK | FileName(255) | 255 |
| 901 | CRC_RETRY | FileName(255) | 255 |
| 902 | CRC_ABORT | FileName(255) | 255 |

### תשובות
| קוד | שם | Payload |
|---|---|---|
| 1600 | REGISTER_OK | ClientID(16) |
| 1601 | REGISTER_FAILED | – |
| 1602 | AES_KEY | ClientID(16) + EncryptedAESKey(128) |
| 1603 | FILE_RECEIVED_CRC | ClientID(16) + ContentSize(4) + FileName(255) + Cksum(4) |
| 1604 | ACK | ClientID(16) |
| 1605 | RECONNECT_OK | ClientID(16) + EncryptedAESKey(128) |
| 1606 | RECONNECT_DENIED | ClientID(16) |
| 1607 | GENERAL_ERROR | – |

### גרסאות וברירות מחדל
| קבוע | ערך |
|---|---|
| גרסת שרת | 3 |
| גרסת לקוח | 3 |
| פורט ברירת מחדל | 1369 |
| Timeout חוסר פעילות בשרת | 300 שניות |
| מספר ניסיונות שליחה חוזרת של קובץ | 3 (סה"כ 4 שליחות) |
| מספר ניסיונות אחרי שגיאת שרת | 3 |

---

## 3. הצפנה – פרטים שחייבים להתאים בשני הצדדים

| נושא | לקוח (Crypto++) | שרת (PyCryptodome) |
|---|---|---|
| RSA | 1024 ביט, `RSAES_OAEP_SHA_Encryptor/Decryptor` | `PKCS1_OAEP.new(key)` (SHA-1 – ברירת מחדל, תואם) |
| מפתח ציבורי | X.509 DER, ‏**160 בתים** (Crypto++ משתמש ב-e=17) | `RSA.import_key(der_bytes)`; בלקוח-דמה: `RSA.generate(1024, e=17)` – עם ברירת המחדל e=65537 יוצא 162 בתים! |
| AES | 256 ביט, CBC, ‏IV = 16 אפסים, ריפוד PKCS7 (ברירת מחדל של `StreamTransformationFilter`) | `AES.new(key, AES.MODE_CBC, iv=bytes(16))` + `unpad(..., 16)` |
| מפתח AES מוצפן | 128 בתים (RSA-1024) | |
| CRC | cksum של POSIX (לא `zlib.crc32`!) | אותו אלגוריתם |
| ערך בדיקה | `cksum("123456789") == 930766865` | |

- **ה-CRC מחושב על הקובץ המקורי** (לפני הצפנה בלקוח / אחרי פענוח בשרת).
- מפתח פרטי נשמר ב-Base64 גם ב-`me.info` (שורה 3) וגם ב-`priv.key`.

---

## 4. תרחישי זרימה

### 4.1 לקוח חדש (אין `me.info`)
```
Client                                  Server
  |-- 825 REGISTER(name) --------------->|  שם קיים? → 1601
  |<------------- 1600 (client_id) ------|  אחרת: uuid4, שמירה
  |  [מייצר RSA, שומר me.info + priv.key]
  |-- 826 PUBLIC_KEY(name, pubkey) ----->|  שומר מפתח, מייצר AES
  |<------ 1602 (id, RSA(AES key)) ------|
```

### 4.2 לקוח קיים (יש `me.info`)
```
  |-- 827 RECONNECT(name) -------------->|  רשום + יש מפתח ציבורי?
  |<------ 1605 (id, RSA(AES key)) ------|  כן → AES חדש
  |<------ 1606 (id) --------------------|  לא → הלקוח עובר ל-4.1
```

### 4.3 העברת קובץ (לכל קובץ ברשימת files)
```
  |-- 828 (packet 1/N) ---------------->|
  |-- 828 (packet N/N) ---------------->|  מרכיב, מפענח, cksum, שומר
  |<------ 1603 (id, size, name, crc) --|
  CRC תואם?  → 900 → 1604 (Verified=True)
  לא תואם    → 901 → השרת מוחק את הקובץ → שליחה חוזרת של 828 מחבילה 1 (עד 3 פעמים)
  כישלון רביעי → 902 → השרת מוחק את הקובץ מהדיסק ואת הרשומה שלו → 1604
```

> **אין קבצים לא מאומתים בדיסק:** אחרי 902 (וגם לפני שליחה חוזרת אחרי 901) השרת מוחק את הקובץ הפיזי. גם קובץ זמני של העברה שנקטעה (ניתוק / timeout / שגיאה) נמחק.

### 4.4 שגיאת שרת (1607 או תשובה לא צפויה)
הלקוח מדפיס `server responded with an error`, שולח שוב את אותה בקשה (עד 3 פעמים), ואם נכשל – יוצא עם הודעת `Fatal: ...` מפורטת.

---

## 5. שרת – תכנון מחלקות

### `server.py`
- `main()` – קורא פורט, יוצר `ClientStore`, פותח socket מאזין, ובלולאה אינסופית: `accept()` → פותח `threading.Thread(target=ClientSession(...).run, daemon=True)`.
- `if __name__ == "__main__": main()`.
- תופס `KeyboardInterrupt` ויוצא בצורה נקייה.

### `config.py`
- `read_port(path) -> int` – אם הקובץ חסר / לא קריא / לא מספר / מחוץ לטווח 1–65535: מדפיס **אזהרה** ומחזיר 1369. **לעולם לא Traceback.**

### `protocol.py`
- כל הקודים כ-`IntEnum` (`RequestCode`, `ResponseCode`), כל הגדלים כקבועים.
- `parse_request_header(bytes) -> RequestHeader` (dataclass).
- `build_response(code, payload) -> bytes`.
- `pack_name(str) -> bytes` / `unpack_name(bytes) -> str` – בדיקת null-terminator, ASCII בלבד.

### `client_session.py` – `ClientSession`
- מחזיק: socket, הפניה ל-`ClientStore`, לקוח נוכחי, מפתח AES של הסשן, מצב קבלת קובץ (חבילות שהתקבלו).
- `run()` – לולאה: קריאת כותרת → בדיקות → dispatch לפי טבלה `{RequestCode: handler}` → שליחת תשובה.
- `socket.settimeout(300)` – ניתוק לקוח לא פעיל.
- `recv_exact(n)` – קורא בדיוק n בתים (לולאה), חריגה אם החיבור נסגר.
- **בדיקת גרסת לקוח:** גרסה ≠ 3 → אזהרה בלוג וממשיכים בטיפול (לא דוחים), לטובת תאימות מול לקוחות אחרים.
- כל חריגה לא צפויה בטיפול בבקשה → תשובה 1607 + רישום ללוג, וה-thread לא מפיל את השרת.
- handlers: `handle_register`, `handle_public_key`, `handle_reconnect`, `handle_file_packet`, `handle_crc_ok`, `handle_crc_retry`, `handle_crc_abort`.

### `crypto_utils.py`
- `generate_aes_key() -> bytes` (32 בתים, `get_random_bytes`).
- `encrypt_with_public_key(der, data) -> bytes`.
- `decrypt_file_streaming(key, src_path, dst_path, on_chunk) -> int` – מפענח בבלוקים (אובייקט `AES` אחד לכל הקובץ, כך ששרשור ה-CBC נשמר), מסיר padding רק מהבלוק האחרון, וקורא ל-`on_chunk` על כל קטע plaintext (לחישוב cksum במקביל). מחזיר את גודל הקובץ המפוענח.

### `cksum.py`
- מחלקה `Cksum` עם `update(chunk)` ו-`digest()` – חישוב מצטבר (האורך הכולל מתווסף רק ב-`digest()`), מבוסס על הקוד מיחידה 7.
- `memcrc(data: bytes) -> int` – עטיפה נוחה לבדיקות.

### `storage.py` – `ClientStore`
- `dataclass Client(id, name, public_key, last_seen, aes_key)`.
- `dataclass FileRecord(client_id, file_name, path_name, verified)`.
- מילונים בזיכרון: `clients_by_id`, `clients_by_name`, `files`.
- **`threading.Lock`** סביב כל גישה (כמה threads ניגשים במקביל).
- `sanitize_file_name(name) -> str` – ראו סעיף 8 (מניעת path traversal); שם לא חוקי → חריגה → 1607.
- `temp_path(client_id, file_name)` / `final_path(client_id, file_name)` – נתיבים תחת `received_files/<client_id>/`.
- `delete_file(client_id, file_name)` – מוחק את הקובץ הפיזי ואת הרשומה (לאחר 901 / 902 / העברה שנקטעה).
- **הכנה לבונוס:** ל-`ClientStore` יש פרמטר אופציונלי `db=None`. כל מתודה שמשנה נתונים קוראת גם ל-`self._db.xxx()` אם קיים. כך, הוספת שאלה 3 = כתיבת `database.py` + שורה אחת ב-`main()` – בלי לגעת בשאר הקוד.

---

## 6. לקוח – תכנון מחלקות

| מחלקה | אחריות |
|---|---|
| `Config` | טוען `transfer.json` מתיקיית ה-exe; בודק: ip תקין, port 1–65535, שם 1–100 תווים ASCII, רשימת files לא ריקה |
| `JsonParser` | parser מינימלי (object/array/string/number) – כי אסור תלויות נוספות |
| `ClientInfo` | `exists()`, `load()`, `save(name, uuid, privateKeyB64)`; המרת UUID ↔ hex (32 תווים) |
| `Connection` | RAII: `WSAStartup` / `closesocket` בדסטרקטור; `connect`, `sendAll`, `recvExact`; timeout |
| `Protocol` | `buildRequest(code, payload)`, `parseResponseHeader`, פונקציות לכל payload |
| `Endian.h` | `writeLE16/32`, `readLE16/32` – בניית בתים ידנית ב-shift, **לא** `memcpy` של struct (עובד גם על ARM וגם על Intel, ללא תלות ב-padding) |
| `RSAWrapper` / `AESWrapper` / `Base64Wrapper` | עטיפות Crypto++ |
| `Cksum` | אותו אלגוריתם כמו בשרת, מצטבר: `update(chunk)` + `digest()` |
| `FileSender` | שליחת קובץ אחד ב-streaming (סעיף 7): קריאה בבלוקים, הצפנה, חלוקה לחבילות, cksum במקביל |
| `FileTransferClient` | הזרימה: התחברות → רישום/התחברות חוזרת → קבלת AES → לולאת קבצים עם retry |
| `Errors.h` | `ProtocolError`, `ServerError`, `FatalError` (יורשות מ-`std::runtime_error`) |

`main.cpp` – יוצר `FileTransferClient`, קורא `run()`, תופס חריגות ומדפיס `Fatal: ...`, מחזיר קוד יציאה ≠ 0.

---

## 7. העברת קבצים גדולים – Streaming מלא

**עיקרון:** אף צד לא מחזיק את כל הקובץ (מקורי או מוצפן) בזיכרון. הזיכרון בשימוש חסום בגודל חבילה אחת, בלי קשר לגודל הקובץ.

### חישוב ContentSize מראש
ב-AES-CBC עם ריפוד PKCS7 תמיד מתווסף ריפוד של 1–16 בתים, ולכן גודל ה-ciphertext ידוע לפני ההצפנה:

```
ContentSize = (⌊OrigSize / 16⌋ + 1) × 16
TotalPackets = ⌈ContentSize / PACKET_CONTENT_SIZE⌉
```

דוגמאות: 0 → 16, ‏15 → 16, ‏16 → 32, ‏100,000 → 100,016.
כך הלקוח שולח את הגודל המדויק כבר בחבילה הראשונה.

### לקוח (`FileSender`)
1. בודק שהקובץ קיים ושגודלו מאפשר `ContentSize ≤ UINT32_MAX` ו-`TotalPackets ≤ 65535`.
2. מחשב ContentSize ו-TotalPackets.
3. בלולאה: קורא בלוק מהקובץ → מעדכן cksum (על המקור) → מכניס ל-`StreamTransformationFilter` של AES (`Put`, ובסוף הקובץ `MessageEnd`) → אוסף את הפלט המוצפן ל-buffer.
4. בכל פעם שב-buffer יש `PACKET_CONTENT_SIZE` בתים (או בסוף הקובץ – מה שנשאר) → שולח בקשת 828 עם PacketNumber עולה (מתחיל מ-1).
5. בודק שסך הבתים שנשלחו = ContentSize (assert הגנתי).
6. משאיר את ה-cksum של המקור להשוואה מול 1603.

`PACKET_CONTENT_SIZE` = **64KB**. כל חבילה = בקשת 828 נפרדת עם אותם ContentSize / OrigFileSize / TotalPackets / FileName.

### שרת
1. **חבילה 1:** מאמת שם קובץ (סעיף 8), בודק ש-`ContentSize == (⌊OrigSize/16⌋+1)×16`, ש-ContentSize ≤ `MAX_FILE_SIZE`, ש-TotalPackets תואם; פותח **קובץ זמני** (`<name>.tmp`) בתיקיית הלקוח.
2. **כל חבילה:** בודק ש-PacketNumber = הצפוי, ששאר שדות הכותרת זהים לחבילה 1, ושסך הבתים לא חורג מ-ContentSize. קורא את התוכן מה-socket בקטעים וכותב **ישירות לקובץ הזמני**.
3. **חבילה אחרונה:** בודק שסך הבתים = ContentSize, ואז `decrypt_file_streaming` מפענח בבלוקים מהקובץ הזמני לקובץ הסופי, ומחשב cksum במקביל. בודק שהגודל המפוענח = OrigFileSize. מוחק את הקובץ הזמני, רושם `FileRecord(verified=False)` ושולח 1603.
4. תשובה נשלחת **רק** אחרי החבילה האחרונה.
5. כל כישלון באמצע (חבילה לא עקבית, פענוח נכשל, ניתוק, timeout) → מחיקת הקובץ הזמני והסופי → 1607 (או סגירת חיבור).

---

## 8. דגשים מההנחיות – וכיצד ממומשים

### כללי
| דגש | יישום |
|---|---|
| תכנות מונחה עצמים | מחלקות לפי אחריות (סעיפים 5–6) |
| אין מספרי קסם | `protocol.py` (IntEnum + קבועים), `Constants.h` (`constexpr`) |
| תיעוד | docstring לכל מחלקה/פונקציה ב-Python; הערת תיאור לכל מחלקה ופונקציה ציבורית ב-C++ |
| שמות משמעותיים | `snake_case` ב-Python, `camelCase`/`PascalCase` ב-C++ |
| little / big endian | `struct` עם `<` בשרת; `Endian.h` בלקוח |
| הודעות גדולות | Streaming מלא: חלוקה לחבילות, כתיבה ישירה לדיסק, פענוח בבלוקים (סעיף 7) |
| עבודה מודולרית ובדיקות מוקדמות | כל מודול נבדק לבד לפני חיבור (ראו PLAN.md) |
| Git | commit אחרי כל שלב שעובר בדיקה |

### אבטחת מידע (קוד דפנסיבי)
| סיכון | הגנה |
|---|---|
| Payload size ענק (DoS / זיכרון) | גבול עליון לכל קוד בקשה; לגודל קובץ כולל – `MAX_FILE_SIZE`; streaming לדיסק במקום RAM |
| Payload size לא תואם לקוד | בדיקה מדויקת לבקשות בגודל קבוע (825/826/827/900–902) |
| קוד בקשה לא מוכר | דחייה עם 1607 |
| גרסת לקוח ≠ 3 | **אזהרה בלוג והמשך טיפול** (תאימות מול לקוחות אחרים) |
| מחרוזת בלי null-terminator / תווים לא ASCII | דחייה |
| path traversal בשם קובץ (`..\..\x`) | `sanitize_file_name` – ראו פירוט למטה |
| קבצים פגומים / לא מאומתים נשארים בדיסק | מחיקה אחרי 901 / 902 / העברה שנקטעה |
| Client ID מזויף | בדיקה שה-ID בכותרת תואם ללקוח שאומת בסשן |
| בקשה מחוץ לסדר (828 לפני מפתח) | מצב סשן – דחייה אם אין מפתח AES |
| חבילות לא עקביות | בדיקה ש-PacketNumber עוקב, TotalPackets/ContentSize קבועים, סכום הגדלים = ContentSize |
| פענוח שנכשל (padding שגוי) | תפיסת `ValueError` → 1607 |
| גישה מקבילה לנתונים | `threading.Lock` |
| לקוח תקוע | `settimeout(300)` |
| זיכרון דינמי ב-C++ | `std::vector`/`std::string`/`std::unique_ptr` בלבד, ללא `new`/`delete` ידני |
| casting ב-C++ | `static_cast` בלבד, בדיקת טווח לפני המרה (למשל `size_t` → `uint32_t`) |
| קריאת buffer מחוץ לגבולות | `recvExact` + בדיקת גודל לפני כל פענוח |
| קבצי קלט פגומים (json / me.info) | בדיקת תקינות מלאה, הודעת שגיאה ברורה |

#### סינון שמות קבצים (`sanitize_file_name`) – כל כלל שנכשל → 1607
1. פענוח השדה (255 בתים) עד ה-null הראשון; אין null → דחייה. תווים לא ASCII → דחייה.
2. חילוץ שם הקובץ בלבד: `ntpath.basename` (מטפל גם ב-`\` וגם ב-`/`). הלקוח שולח שם בלבד, בלי נתיב.
3. דחייה אם השם: ריק; מכיל `..`; מכיל תו מתוך `<>:"/\|?*` או תו בקרה (קוד < 32); מסתיים בנקודה או ברווח; הוא שם שמור של Windows (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, גם עם סיומת).
4. בדיקה סופית: הנתיב המלא אחרי `os.path.realpath` חייב להתחיל בתיקיית `received_files/<client_id>/` (הגנה כפולה).

### שרת
- Python 3.12.1, ספריות סטנדרטיות + PyCryptodome **בלבד**.
- פונקציה `main()` + `if __name__ == "__main__":`.
- `ruff check` נקי לפני הגשה.
- הדפסות/לוג (`logging`) לכל בקשה ותשובה – כדי שיראו בווידאו.
- מגישים **רק קבצי `.py`**.

### לקוח
- C++20, ‏Visual Studio 2026, ‏winsock, ‏Crypto++, ‏STL.
- פועל ב-batch mode – ללא קלט מהמשתמש.
- `transfer.json`, `me.info`, `priv.key` – בתיקיית ה-exe (`GetModuleFileNameW`).
- מגישים **רק קבצי `.h` ו-`.cpp`**.
- בדיקה סופית: פרויקט VS חדש בתיקייה נקייה → קומפילציה → ריצה.

---

## 9. החלטות פתוחות (הנחות שלנו במקום שבו ההנחיות לא חד-משמעיות)

1. **השרת לא עונה על 901** – הוא מוחק את הקובץ, והלקוח שולח מיד את ה-828 מחדש (מחבילה 1).
2. **1606 → רישום מחדש:** אם השם כבר קיים בשרת, הרישום יחזיר 1601 והלקוח ייצא עם Fatal (נאמן להנחיות: "שם קיים → שגיאה").
3. **מפתח AES חדש בכל התחברות** (גם ב-827).
4. **קובץ שהתקבל מחדש באותו שם** – דורס את הקודם.
5. **דוגמת ה-JSON במטלה אינה JSON חוקי** (`\d`) – בקובץ שלנו נכתוב `\\` או `/`.
6. **גרסה לא תואמת לא נדחית** – השרת מזהיר בלוג וממשיך; גם הלקוח מזהיר אם גרסת השרת ≠ 3 וממשיך.
7. **קובץ שלא אומת נמחק** – אחרי 902 השרת מוחק את הקובץ הפיזי ואת הרשומה שלו.
8. **שם קובץ שמכיל `..` נדחה** גם אם הוא חוקי ב-Windows (למשל `a..b.txt`) – עדיף להחמיר.

---

## 10. בונוס – שאלה 3 (SQLite) – מתווסף בסוף, רק אם יש זמן

- קובץ `defensive.db`, מודול `sqlite3` הסטנדרטי.
- טבלה `clients`: ‏`ID BLOB(16) PRIMARY KEY, Name TEXT(255), PublicKey BLOB(160), LastSeen TEXT, AESKey BLOB(32)`.
- טבלה `files`: ‏`ID BLOB(16), FileName TEXT(255), PathName TEXT(255), Verified INTEGER`.
- בהפעלה: אם הקובץ קיים – טוען לקוחות ל-`ClientStore` (הזיכרון נשאר המקור הראשי).
- שאילתות עם פרמטרים (`?`) בלבד – מניעת SQL injection.
- חיבור נפרד לכל thread או חיבור אחד מוגן ב-Lock.

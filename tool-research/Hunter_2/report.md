# Hunter-2 安全掃描報告

**目標：** http://192.168.56.1:5000

**產生時間：** 2026-04-18T05:24:46.483156 UTC

**輸出資料夾：** `loot`

**總發現數：** 2

## 摘要

- **其他**：1 項
- **檔案分析**：1 項

### 風險等級統計

- **重大**：1
- **高**：0
- **中**：1
- **低**：0
- **資訊**：0
- **未知**：0

### 驗證狀態統計

- **已觀察 (observed)**：0
- **可疑 (suspected)**：2
- **已驗證 (verified)**：0
- **已利用 (exploited)**：0

### 檔案分析統計

- **已分析檔案數**：1
- **已輸出修補檔數**：1
- **驗證成功次數**：0
- **驗證失敗次數**：1

---

# 其他

## 1. role-cookie-bypass

**風險等級：** 重大

**驗證狀態：** 可疑

**信心水準：** medium

**網址：** `http://192.168.56.1:5000/admin`

**證據：**

- `welcome admin`
- `picoCTF{test_web_lab}`

**修補建議：** Store authorization state server-side, sign or encrypt session data, and never trust a client-supplied role cookie for access control.

---

# 檔案分析

## 2. passive-artifact-analysis

**風險等級：** 中

**驗證狀態：** 可疑

**信心水準：** medium

**網址：** `http://192.168.56.1:5000/backup.zip`

**證據：**

- `best_guess:ZIP`
- `confidence:Medium`

**檔案分析：**

- 來源檔案：`loot\artifacts\passive\backup_b4326b0247.zip`
- 最可能類型：`ZIP`
- 信心水準：`Medium`
- 可疑分數：`35`
- 建議修補：`是`
- 修補後輸出：`loot\recovered\passive\backup_b4326b0247_repaired.zip`
- 驗證結果：
  - `[FAIL] ZIP validation failed: File is not a zip file`

**修補建議：** Review downloaded artifact, verify true file type, and inspect repaired output if generated.

---


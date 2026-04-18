# Hunter-2 自建 Flask 靶場實驗報告

## 一、實驗基本資料
- **實驗主題**：以自建 Flask Web Lab 驗證 Hunter-2 規則覆蓋率與偵測能力
- **實驗日期**：2026-04-18
- **實驗目標**：
  1. 建立可由 Kali 連線的本機 Flask 測試靶場。
  2. 驗證 Hunter-2 在預設規則下對 Flask 類弱點的偵測能力。
  3. 針對漏報情況補充自訂規則後重新測試。
  4. 比較第一次與第二次掃描結果，評估規則補強效果。

## 二、實驗環境
### 1. 網路架構
- **主機端**：Windows 主機，VirtualBox Host-only IP 為 `192.168.56.1`
- **攻擊端**：Kali Linux VM，Host-only IP 為 `192.168.56.101`
- **VM 網路模式**：Host-only + NAT
- **測試目標**：`http://192.168.56.1:5000`

### 2. 測試服務
主機端以 Flask 建立自訂 Web Lab，包含以下路由：
- `/login`
- `/admin`
- `/debug`
- `/robots.txt`
- `/api/me`
- `/config.bak`
- `/backup.zip`

### 3. 工具
- **掃描工具**：Hunter-2
- **輔助工具**：curl、whatweb、gobuster
- **作業系統**：Windows + Kali Linux VM

## 三、實驗設計
### 1. 靶場弱點設計
本次 Flask Web Lab 主要模擬下列弱點：
1. **Cookie-based Access Control Bypass**
   - `/login` 會設定 `role=guest`。
   - `/admin` 直接信任 client 送出的 `role` cookie。
2. **Debug Information Exposure**
   - `/debug` 回傳 `DEBUG=True`、`SECRET_KEY`、`ENV=development` 等資訊。
3. **Sensitive File Exposure**
   - `/config.bak`
   - `/backup.zip`
4. **Sensitive Path Disclosure**
   - `/robots.txt` 暗示 `/secret-panel` 與 `/old-login`
5. **API Debug Hint**
   - `/api/me?debug=1` 額外回傳內部提示資訊。

### 2. 驗證流程
1. 先以 `curl` 驗證 Kali 可正常存取主機端服務。
2. 使用 Hunter-2 內建 pack（`ctf + spring + web-misconfig`）進行第一次掃描。
3. 觀察漏報項目，補充自訂規則。
4. 重新掃描並比對輸出報告。

## 四、第一次掃描結果（未補規則）
第一次 Hunter-2 報告僅發現 **1 個資訊級問題**，目標仍為 `http://192.168.56.1:5000`，且總發現數為 1。唯一偵測到的項目是 `passive-cookie-clue`，位置在 `/login`，證據為 `set-cookie:role=guest; Path=/`。整體驗證狀態為 `suspected`，並未進一步驗證或利用。這表示初始規則只能做到被動 cookie 線索擷取，尚未覆蓋本靶場中的權限繞過、debug 資訊洩漏與敏感檔案暴露等問題。 

## 五、規則補強內容
為提升對 Flask 靶場的覆蓋率，本次補充以下自訂規則：
1. `role-cookie-bypass.yaml`
   - 先存取 `/login?user=guest`
   - 再偽造 `Cookie: role=admin`
   - 重送至 `/admin` 進行權限繞過檢測
2. `flask-debug.yaml`
   - 檢測 `/debug` 中的 `DEBUG=True`、`SECRET_KEY`、`ENV=development`
3. `config-backup.yaml`
   - 檢測 `/config.bak`、`/backup.zip`
4. `robots-sensitive-path.yaml`
   - 分析 `robots.txt` 中的敏感或 legacy 路徑
5. `api-debug-hint.yaml`
   - 檢測 `/api/me?debug=1` 相關洩漏資訊

## 六、第二次掃描結果（已補規則）
第二次 Hunter-2 報告共發現 **2 個問題**：

### 1. role-cookie-bypass
- **風險等級**：重大
- **驗證狀態**：可疑（suspected）
- **目標路徑**：`/admin`
- **關鍵證據**：
  - `welcome admin`
  - `picoCTF{test_web_lab}`
- **說明**：
  Hunter-2 已能透過自訂鏈式規則完成 cookie 偽造後的存取測試，並在 `/admin` 命中成功訊息，代表工具已具備檢出此類 Broken Access Control 問題的能力。

### 2. passive-artifact-analysis
- **風險等級**：中
- **驗證狀態**：可疑（suspected）
- **目標路徑**：`/backup.zip`
- **關鍵證據**：
  - `best_guess:ZIP`
  - `confidence:Medium`
- **分析結果**：
  Hunter-2 對下載到的 artifact 進行類型推測與修補流程，但最終 ZIP 驗證失敗，顯示該檔案屬於可疑樣本，而非有效壓縮檔。

## 七、結果比較與分析
### 1. 偵測能力變化
- **第一次掃描**：僅能被動發現 cookie 線索。
- **第二次掃描**：
  - 已可 discover/crawl `/debug`、`/robots.txt`、`/api/me`、`/config.bak`、`/backup.zip`
  - 已可執行 `role-cookie-bypass` 鏈式驗證
  - 已能將權限繞過正式列為 finding

### 2. 實驗觀察
本次實驗證明 Hunter-2 在初始狀態下對自建 Flask 靶場的覆蓋率有限，偏向被動 clue 擷取；但在補充自訂規則後，已能對特定弱點進行主動驗證，尤其是 cookie-based access control bypass 類問題。

### 3. 尚未完全覆蓋的項目
雖然已能發現更多路由與弱點，但第二次報告仍未正式列出：
- `/debug` 資訊洩漏
- `/robots.txt` 敏感路徑提示
- `/config.bak` 暴露
- `/api/me?debug=1` 洩漏

這表示目前規則雖已改善，但對 Flask 類資訊洩漏與設定暴露的分類、matcher 與 verifier 仍需補強。

## 八、風險與修補建議
### 1. Cookie-based Access Control Bypass
- 不應信任使用者可修改的 `role` cookie 作為授權依據。
- 授權狀態應由伺服器端 session 控制。
- 若使用 cookie 儲存狀態，至少應加入簽章或加密保護。

### 2. Debug / 設定暴露
- 移除開發環境專用 debug 頁面。
- 避免回傳 `SECRET_KEY`、`ENV`、內部提示等敏感資訊。
- 生產環境應關閉除錯模式。

### 3. 備份與設定檔暴露
- 禁止將 `.bak`、`.zip`、舊版路由與測試檔部署到對外服務。
- 建立部署前檢查流程，清除 backup / temporary / legacy 檔案。

## 九、實驗結論
本次實驗成功建立了「Windows 主機 Flask 靶場 + Kali VM 攻擊端 + Hunter-2 掃描驗證」的本地測試環境。第一次掃描證明 Hunter-2 預設規則對 Flask 類靶場的覆蓋率不足；第二次在補充自訂規則後，已能有效檢出 `role-cookie-bypass` 與 `backup.zip` 可疑 artifact，顯示工具已從被動線索擷取，進一步發展到對自建弱點樣本進行主動驗證。

整體而言，本次實驗不只是「換地方練 picoCTF」，而是完成了一次以自建靶場為基礎的工具驗證流程，對 Hunter-2 後續的規則開發、回歸測試與覆蓋率分析具有實際價值。

## 十、後續改進方向
1. 將 `/debug`、`/robots.txt`、`/config.bak`、`/api/me?debug=1` 補成正式 finding。
2. 強化 verifier，讓成功命中條件時可升級為 `verified`。
3. 建立固定 regression lab，作為 Hunter-2 規則更新後的回歸測試樣本。
4. 將本次實驗流程納入 tool-research 筆記，形成可重複比較的測試紀錄。

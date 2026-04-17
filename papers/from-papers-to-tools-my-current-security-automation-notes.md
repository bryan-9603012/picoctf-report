# 從論文到工具：我目前資安自動化方向的整理

## 前言

我目前的學習與實作主軸，已經不只是單純解 picoCTF 題目，而是開始往「資安分析流程的工具化」發展。  
目前我已經實作了至少兩個工具雛形，並且開始閱讀與自動化分析、PoC 生成、exploit generation 相關的論文。這讓我的方向逐漸清楚：我想做的不是只會操作工具的人，而是能把分析流程、規則、驗證與輸出結果整合起來的人。

這篇筆記的目的，是整理我目前兩個工具與兩篇論文之間的關聯，並釐清我接下來可以發展的方向。

---

## 我目前已經做的兩個工具

### 1. Hunter-2

Hunter-2 可以視為我在 Web / 規則式安全檢測方向上的工具雛形。  
它的核心想法不是只掃描表面資訊，而是希望把規則、請求流程、條件判斷與輸出報告串起來。這種方向的重點不只是「有沒有發現問題」，而是能不能把問題轉成可追蹤、可重現、可驗證的結果。

我從這個工具身上學到的，不只是規則怎麼寫，而是：

- 工具要有明確的輸入與輸出
- 規則不應只是靜態比對，也可以有流程與條件
- 報告本身也是工具價值的一部分
- 若未來要更進一步，工具不能只做 detection，還要思考 validation

Hunter-2 目前更像是 rule-based security checking / workflow prototype。  
它代表的是我對「自動化安全分析」這條線的第一個實作起點。

---

### 2. ArtifactScope

ArtifactScope 比較偏向 file triage / artifact analysis。  
這個方向跟 Web 不同，但同樣在做一件事：把原本需要人工一步一步觀察的流程，轉成較穩定、可重複、可輸出的分析程序。

從 README 的功能描述來看，ArtifactScope 已經涵蓋：

- 檔案 metadata 收集
- MD5 / SHA1 / SHA256 雜湊
- magic byte / signature-based type detection
- 副檔名不一致偵測
- entropy 分析
- strings 擷取
- IOC 類型資訊抽取
- 簡單規則引擎與風險分數
- embedded artifact discovery / carving
- JSON 與 Markdown 報告輸出

它自己也把定位說得很清楚：這是一個面向 CTF、DFIR learning、可疑檔案檢視的 lightweight、security-oriented MVP，而不是直接取代大型鑑識工具。:contentReference[oaicite:0]{index=0} :contentReference[oaicite:1]{index=1}

這個工具讓我更清楚一件事：  
我做工具的方向，不一定要一開始就追求「超強、超完整」，而是可以先做一個分析流程清楚、目標明確、能產出有價值結果的 MVP。

---

## 我最近閱讀的兩篇論文

### 1. PAGENT：Program Analysis Guided LLM Agent for Proof-of-Concept Generation

這篇論文研究的是：  
在給定 source code 與特定 code location 的情況下，能不能自動產生能觸發漏洞的 PoC。

PAGENT 的核心設計是把三個部分串在一起：

1. **Static Analysis**
2. **PoC Generation Agent**
3. **Dynamic Analysis**

論文指出，傳統 symbolic execution 與 fuzzing 雖然有能力找到或驗證問題，但常常需要專家手動引導，而且會遇到 scalability 問題；單靠 LLM agent 又容易 hallucinate，所以他們提出一種 hybrid approach，讓 static analysis 提供 vulnerability-specific guidance，dynamic analysis 提供 coverage 與 profiling feedback，再由 agent 根據這些資訊持續修正 PoC。:contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3}

這篇論文最讓我有感的地方不是「用了 LLM」，而是它沒有把 agent 當成萬能解法。  
相反地，它把 agent 放在一個被分析資訊約束、被執行結果回饋修正的架構裡。這點很重要。

在具體設計上，PAGENT 的 static analysis 會先做兩件事：

- lightweight static analysis：從 entrypoint 出發做 call graph 與 reachable filtering
- rule-based static analysis：用規則抽出 vulnerability report，包括 vulnerable function、taint path、entrypoint、template assertion violation 等資訊 :contentReference[oaicite:4]{index=4}

之後 agent 不是盲目看整個 repo，而是拿著這份 vulnerability report 去做 PoC generation；若失敗，dynamic analysis 會回報 execution time、entrypoint 與 line / region / branch coverage，讓 agent 用事實修正推論。:contentReference[oaicite:5]{index=5}

從結果上看，PAGENT 在 203 個 vulnerability、10 個 open-source projects 的資料集上，DeepSeek3.2 版本達到 64.6% accuracy，且找出了 32 個會在 patched version 仍可觸發的 post-patch vulnerabilities。論文也提到，它可以自然整合到 CI/CD，對每次 commit 的修改位置做檢查與 PoC 驗證。:contentReference[oaicite:6]{index=6} :contentReference[oaicite:7]{index=7} :contentReference[oaicite:8]{index=8}

#### PAGENT 對我的啟發

這篇論文對我最直接的影響是：

- 規則與 agent 不應該對立，而應該互補
- static analysis 可以先幫 agent 縮小空間
- dynamic feedback 能把「猜測」變成「可修正的實驗」
- 工具的目標不該停在 finding，要進一步做到 proof / validation

如果把這些想法放回我目前的工具上，我會想到：

- Hunter-2 未來不一定只是輸出 finding，也可以提供更明確的 exploitability / validation hints
- ArtifactScope 未來不一定只是做 triage，也可以做更像 rule-guided investigation
- 我未來可以試著做一個小型 analysis-guided agent workflow，而不是直接把 AI 當成萬能外掛

---

### 2. MAYHEM：Unleashing MAYHEM on Binary Code

如果說 PAGENT 比較接近我現在的方向，那 MAYHEM 比較像是更底層、更經典的方法論基礎。

MAYHEM 的目標不是一般 bug finding，而是 **automatically finding exploitable bugs in binaries**，而且每個 bug report 都附上 working exploit。論文強調，這樣的輸出才是 security-critical 且 actionable 的。:contentReference[oaicite:9]{index=9}

它處理的兩個核心問題是：

1. **如何在 symbolic execution 中管理 execution paths，而不因 path explosion 與記憶體耗盡而停滯**
2. **如何在 binary-level 上處理 symbolic memory indices**

為了解決前者，MAYHEM 提出了 **hybrid symbolic execution**，在 online 與 offline symbolic execution 之間切換，試圖同時取得 online 的速度與 offline 的記憶體優勢。:contentReference[oaicite:10]{index=10}

第 5 頁的圖 3 和圖 4 很有代表性：  
圖 3 說明 hybrid execution 想在 offline 與 online 之間折衷；圖 4 則顯示 online execution 的 throughput 會隨著記憶體壓力上升而下降。:contentReference[oaicite:11]{index=11}

為了解決 symbolic memory 的問題，MAYHEM 提出 **index-based memory modeling**。論文提到，若只是把 memory indices 全部 concretize，很多 exploit 根本無法生成；它們的實驗顯示，超過 40% 的案例需要 symbolic memory modeling。:contentReference[oaicite:12]{index=12}

MAYHEM 還進一步引入：

- VSA 幫忙縮小 symbolic index 的範圍
- refinement cache / lemma cache 減少 solver queries
- index search trees
- linearization / bucketization  
來降低 symbolic memory 帶來的成本。第 8 頁與第 12 頁的圖表顯示，這些優化可以顯著減少 solver queries 與總時間。:contentReference[oaicite:13]{index=13} :contentReference[oaicite:14]{index=14}

在結果上，MAYHEM 分析了 29 個 Linux / Windows 程式，成功展示 29 個 exploitable vulnerabilities，其中 2 個是當時的 zero-day。第 11 頁的表 1 很直接列出了各個案例、input source、exploit type 與 exploit generation time。:contentReference[oaicite:15]{index=15} :contentReference[oaicite:16]{index=16}

#### MAYHEM 對我的啟發

MAYHEM 對我最大的提醒是：

- 找到 bug 不等於找到可利用漏洞
- 「能不能產生 proof」比單純報告問題更重要
- 真正困難的地方常常不是語法層，而是路徑管理、狀態管理、記憶體模型與成本控制

這讓我更清楚地看到，我目前的工具雖然還沒有走到 binary exploitation 這麼深，但方向上其實是有共通點的：

- 都在想怎麼把分析流程系統化
- 都不只是要找問題，而是要讓結果更 actionable
- 都牽涉到規則、驗證、輸出與成本控制

---

## 這兩篇論文與我目前工具的共同點

雖然 Hunter-2、ArtifactScope、PAGENT、MAYHEM 看起來分屬不同方向，但它們有一些很明顯的共同主題：

### 1. 從 detection 走向 validation / proof

- ArtifactScope 不只是看檔案，而是試圖把可疑跡象整理成可讀報告
- Hunter-2 不只是比對規則，而是希望把發現結果轉成更有脈絡的輸出
- PAGENT 直接把目標定成 PoC generation
- MAYHEM 甚至要求每個 bug report 都附上 working exploit

也就是說，真正有價值的資安工具，往往不是只告訴你「這裡可能有問題」，而是能更進一步回答：

- 問題能不能重現？
- 影響有多大？
- 能不能形成 proof？
- 使用者接下來該做什麼？

### 2. 單靠一種方法通常不夠

- PAGENT 結合 static analysis、dynamic analysis 與 agent
- MAYHEM 在 online / offline symbolic execution 之間折衷
- 我目前的工具也逐漸顯示，只靠單一比對方式通常不夠穩

這代表未來更有價值的方向，不一定是「把某個方法做到極致」，而可能是把多個方法透過合理架構串起來。

### 3. 輸出形式本身就是價值

- PAGENT 的 vulnerability report 是 agent 的起點
- MAYHEM 的 exploit 與 test case 是結果的一部分
- ArtifactScope 的 JSON / Markdown report 已經證明輸出不是附屬品，而是工具設計的一部分

這也提醒我，未來做工具時不能只想 detection logic，也要想：
- 報告怎麼寫
- 結果怎麼分類
- 使用者怎麼理解與後續利用

---

## 我接下來可以做的事情

### 1. 補強 Hunter-2 的「驗證性」
我可以開始思考，Hunter-2 除了 finding 之外，能不能產出：
- 更明確的 reproduction hints
- exploitability hints
- rule chain / request chain 的上下文
- 對應的驗證步驟建議

這樣它才會更接近「analysis-guided security tooling」而不只是 rule scanner。

### 2. 補強 ArtifactScope 的規則與分析層
ArtifactScope 目前已經有 metadata、hash、strings、IOC、entropy、carving 與 report。下一步可以往：
- 更細的 rule engine
- 更明確的 suspicious pattern grouping
- nested artifact / archive handling
- timeline / relationship view  
發展。

### 3. 嘗試一個簡化版的 PAGENT 思路
我不一定一開始就要做完整 agent，但可以先做一個簡化版：

- 規則或分析先產出 structured report
- 再交給後續模組根據 report 做下一步推理或驗證
- 執行結果再回饋進下一輪

這種「analysis → action → feedback」的流程，是我認為很值得嘗試的下一步。

### 4. 建立自己的 tool-research 筆記系統
比起只蒐集論文與程式碼，我更需要建立：
- 每個工具的定位
- 每篇論文的啟發
- 哪些概念已經實作
- 哪些還只是想法
- 下一步可實驗的 prototype 是什麼

這樣才會慢慢形成自己的研究與開發路線，而不是零散做東西。

---

## 結論

回頭看目前的狀態，我雖然還在早期階段，但方向其實已經開始成形：

- **Hunter-2** 代表我在 Web / 規則式安全分析上的實作起點
- **ArtifactScope** 代表我在 file triage / DFIR-oriented analysis 上的工具嘗試
- **PAGENT** 讓我看到 static analysis、dynamic feedback 與 agent 如何被整合成 PoC generation workflow
- **MAYHEM** 則讓我理解 exploit generation、symbolic execution 與 binary-level reasoning 的經典問題與方法

這些東西加起來，說明我現在做的事並不是零散的。  
我其實正在逐步建立一條屬於自己的資安自動化學習路線：從 CTF 題解出發，延伸到工具、報告、方法論，再慢慢接近更完整的分析與驗證系統。

現階段最重要的，不是急著把每個工具都做成最終版本，而是持續把：

- 工具
- 論文
- 筆記
- 報告
- 實驗

整理成一條可以持續前進的主線。

只要這條主線還在，我做的每一個小工具、每一篇筆記、每一次實驗，就都不是白做的。
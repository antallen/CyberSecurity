# CyberSecurity
## 資訊安全專有名詞
1. [組織名稱](doc/organization.md)
2. [規格標準名稱](doc/standard.md)
3. [風險名稱](doc/risk.md)
4. [密碼學名稱](doc/cryptography.md)
5. [機制與流程名稱](doc/process.md)

## 不分類查詢(Ctrl+F)
+ BCP : Business Continuity Plan (商業持續運作計劃)
+ DLP : Data Loss Prevention (資料洩露保護)
+ PII : Personally Identifiable Information (個人身份資訊)
+ IP : Intellectual Property (知識產權)
+ PCI DSS： 支付卡行業 (PCI) 資料安全標準 (DSS)
  + 建立並維護安全網路和系統
  + 保護持卡人資料
  + 維護漏洞管理計畫
  + 嚴格的認證及授權
  + 定期稽核監控及測試網路
  + 維護資訊安全政策
+ NIST CSF : 美國國家標準與技術研究所（NIST）網路安全框架（Cybersecurity Framework，CSF）
+ Rogue Access Point : 企業內的非法自設存取點
+ Evil twin : 公眾網路的非法 SSID （非企業內的）
+ SIEM : 安全性資訊與事件管理 (簡稱 SIEM) 是一種解決方案，可協助組織在威脅傷害企業營運之前，先進行偵測、分析和回應安全性威脅。
+ NOC : 網路運營中心 （network operations center,  NOC）
+ ARP poisoning : 讓真實的IP位置連結成攻擊者的 Mac address
+ MAC flooding : 洗去 switch 上的 mac address table 表內容
+ SAML : 安全聲明標記語言 (SAML) 為開放的聯合標準，可讓身分識別提供者 (IdP) 驗證使用者，並將驗證憑證傳送給另一個稱為服務供應商 (SP) 的應用程式。
+ CASB（唸作 Cas-Bee）是 Cloud Access Security Broker 的縮寫，意即雲端存取資安代理。
+ MITM：(Man-in-the-middle) Attack /Countermeasures 泛指所有以中間人方式介入,並欺騙通訊雙方其中間人為目標之行為
+ SMS 全名為 Short Message Service，通稱為「簡短訊息服務」。
+ 網路釣魚簡訊 (Smishing)：網路釣魚簡訊是經由手機簡訊 (SMS) 來發動攻擊
+ Phishing(網路釣魚)、Smishing(簡訊釣魚)、Vishing(語音釣魚)、Spam(垃圾郵件)、Spam over instant messaging(SPIM)(即時通訊軟體上的垃圾訊息)、Spear phishing(魚叉式釣魚，針對特定目標的釣魚方式)、Whaling(釣鯨，鎖定企業高階主管為釣魚目標)、Invoice scams(帳務付款詐騙)等等。
+ shoulder surfing ：肩窺（指站在他人身後，眼睛越過其肩膀偷窺其輸入個人資料，以竊取密碼等個人資訊的行為）
+ OAuth 2.0 : 並不是一個認證 (Authentication)機制，而只是一個單純的授權 (Authorization)機制，也就是正如其名：Open Authorization。
+ SOC : 資通安全威脅偵測管理服務，一般常稱之為SOC監控服務 (Security Operation Center)
+ UTM : 整合式威脅管理設備（UTM）
+ MSSP（Managed Scurity Services Provider）企業採用資安產品之餘，這些供應商也順水推舟的提供資安管理委外服務。
+ SOAR (Security Orchestration, Automation, and Response) : SOAR 為一組技術，可幫助資安團隊透過『標準化』工作流程及『自動化』，提高資安團隊工作效率，對威脅行為進行鑑定、調查及補救。
+ Watering hole attack：針對的目標多為特定的團體（組織、行業、地區等）。攻擊者首先通過猜測（或觀察）確定這組目標經常訪問的網站，併入侵其中一個或多個，植入惡意軟體，最後，達到感染該組目標中部分成員的目的。「水坑（Watering hole）」攻擊和我們一般認為的網路攻擊相反。並不是去攻擊目標，而是去埋伏在他們知道目標可能會去的地方。
+ 同態加密( homomorphic encryption)：同態加密指的是一種加密方式，使得使用者可以對密文做計算，計算出來的結果，再做解密的時候的明文是預期的計算結果。讓應用程式可處理加密狀態下的資料，而如同處理未加密資料一樣。
+ Rainbow Table：彩虹表是一個龐大的數據存儲庫，它不僅用於攻擊密碼本身，而且還用於攻擊哈希提供的加密安全性的方法。
+ 透過無腦的 try-error 來破解密碼，這樣的攻擊手法被稱為 brute-force
+ 密碼潑灑（password spray）：密碼潑灑有2種特質，一是低調、緩慢，最高竿的攻擊者會使用不同IP位址同時間，以很少次猜測來攻擊多個帳號。二是利用重覆使用的密碼，攻擊者從暗網上蒐集外洩的用戶登入憑證，利用「憑證填充（credential stuffing）」手法來存取受害者重覆使用同一組帳號密碼的不同網站。
+ Hacktivists : 駭客主義 "a person who gains unauthorized access to computer files or networks in order to further social or political ends."
+ CSRF ( Cross Site Request Forgery )，跨站請求偽造。想像你到一家餐廳吃飯，陌生人拿了一張有你桌號的菜單點餐之後給老闆，結果老闆問也不問便收了菜單並將帳記到了你的身上，這就是 CSRF 的基礎概念。
+ MTBF：Mean Time Between Failures 產品在操作使用或測試期間的平均連續無故障時間
+ Recovery Time Objective: RTO 是服務中斷與恢復服務之間的最大可接受延遲。這會決定可接受的服務無法使用之時間長度。
+ Recovery Point Objective: RPO 是自上次資料復原點之後的最大可接受時間長度。這會決定最後一個復原點與服務中斷之間可接受的資料遺失。
+ 平均復原時間（Mean time to recovery，MTTR）
+ ARO：After Receipt of Order
+ MOU：諒解備忘錄 memorandum of understanding
+ Service Level Agreement (SLA) 中文是服務級別協定，這是服務供應商與客戶就服務水準、品質、效能等方面作出的協議，即技術承包者需要向客戶提供何種級別的服務，同時還要列明服務供應者在未能滿足 SLA 要求時的補救措施和賠償條款。
+ BPA：一攬子採購協定(Blanket Purchase Agreement，簡稱BPA)是一種為降低採購成本，與供應商簽訂的中長期採購協定。一次簽訂，多次要貨。
+ IOC (Indicators of Compromise) 入侵威脅指標。
+ 擴充驗證憑證（Extended Validation Certificate，簡稱「EV憑證」）是一種根據一系列特定標準頒發的X.509電子憑證。根據要求，在頒發憑證之前，憑證發行機構(CA)必須要驗證申請者的身分。不同機構根據憑證標準發行的擴充驗證憑證並無太大差異，但是有的時候根據一些具體的要求，特定機構發行的憑證可以被特定的軟體所辨識。
+ User acceptance testing (UAT) 是在軟體測試流程的最後一步
+ 系統發展生命周期（System Development Life Cycle，SDLC），也稱軟體生命周期，是系統工程、資訊系統和軟體工程中的術語，用於描述一個資訊系統從規劃、建立、測試到最終完成部署的全過程。
+ NTLMv1 / NTLMv2 微軟的身份驗證機制
+ 不可否認（Non-repudiation）是指某一資料的作者無法否認資料是由他所作，或是無法否認相關契約的合法性。
+ 動態密碼(OTP)機制，隨機亂數產生的密碼，根據事件每次產生不同的密碼，而且只使用一次
+ Protected health information (PHI), also referred to as personal health information, is the demographic information, medical histories, test and laboratory results, mental health conditions, insurance information and other data that a healthcare professional collects to identify an individual and determine appropriate care.
+ BYOD（Bring Your Own Device）就是將自己的手機或是電腦帶到公司的環境裡做使用。
+ MDM（Mobile Device Management），是一個可以讓公司遠端監控行動裝置的軟體，並可以監測使用者所有收或發的訊息，必要時甚至可以強制從遠端刪除裝置上的所有資料。移動設備管理（MDM）是容器化的另一個亮點。 簡而言之，MDM與BYOD基本相同，只是移動設備是由組織而不是其員工擁有和控制的。
+ Credential harvesting(憑證竊取)
+ Typosquatting(利用相似域名的詐騙)
+ Pharming(網址嫁接)：劫持一般正常網站地址或網址（例如「www.mybank.com」）的行為，將你重新導到一個看起來像原本網站的假網站。這偽造的網站會偷偷收集你所輸入的個人資料，然後用在其他可能的犯罪活動上。
+ 混合戰爭，亦稱「混合戰」，（Hybrid Warfare，是一種在戰爭中傳統與非傳統手段的混合，最早由美國提出，是21世紀出現的一種新的戰爭形態。
+ Wifi AP security: WEP / WAP-PSK  https://mic1491.pixnet.net/blog/post/30237227  
+ chain-of-custody ： 物證連續保管 ： 向法庭提交物證的人，如在毒品案件中向法庭提交麻醉品作為物證的人，必須說明從他開始保管該物證直至他向法庭提交該物證的期間，他一直保管該物證的情況。Date and time of collection
  + Location of collection
  + Name of investigator(s)
  + Name or owner of the media or computer
  + Reason for collection
  + Matter name or case number
  + Type of media
  + Serial number of media if available
  + Make and model of hard drive or other media
  + Storage capacity of device or hard drive
  + Method of capture (tools used)
  + Physical description of computer and whether it was on or off
  + Name of the image file or resulting files that were collected
  + Hash value(s) of source hard drive or files
  + Hash value(s) of resulting image files for verification
  + Any comments or issues encountered
+ Web Application Firewall (WAF) 網頁應用系統防火牆：主要是用於是保護網站應用程式，透過監控網站傳輸的 HTTP 流量，比對病毒與惡意程式資料庫，過濾出可疑流量並拒絕惡意流量進入，保護網站免受駭客攻擊。
+ UEM（Unified Endpoint Management）統一端點管理平台：不分裝置型態，均可列管及部署應用程式，沒有行動、PC平臺的隔閡，都能納入統一的管控體系當中。
+ IPSec security architecture ： https://kkc.github.io/2018/03/21/IPSEC-note/
  + 使用 Layer3 Network layer 這層
  + Application 層的大家可以無感的享受其 CIA 的好處
  + Components
    + Authentication Header (AH) 主要提供的是驗證 Data integrity & data origin source，然後沒有提供任何加密的功能，使用 HMAC 算法，把 payload & header 和 IKE 定義好的 key 一起拿來 hash，但這邊要小心因為 NAT 會改變 header，而被改變的話，另外一邊就沒辦法解析正確，所以基本上 AH 應該是不可能跟 NAT 共存。使用 port 51。
    + Encapsulation Security Payload (ESP)ESP 的功能比起 AH 強大了許多， confidentiality, authentication, integrity 都包含在其中了，所以真正有提供加密的功能，而在驗證 Data integrity 方面，還是要看是使用 Transport mode 或是 Tunnel mode
      + Transport mode: ESP 沒有對 IP header 做 hash，所以只能保證 Data 是沒有被修改的
      + Tunnel mode: 有將 IP header 包進來，所以這點跟 AH 是一致的
      + ESP 和 AH 最大的差別應該是 AH 會對於 Outer IP header 做驗證，所以其實 IPSec 唯有使用 ESP tunnel mode 才能和 NAT 共存。
    + Security Associations (SA)：IPsec 中最重要的其實是 SA，因為它定義了如何協商，還有要使用哪些 Policy 和參數
      + Authentication method
      + Encryption algorithm & hashing algorithm
      + Life time of SA
      + Sequence number (避免 replay 攻擊)
      + 而基本上 SA 是單向的，所以通常要建立兩條 SA (from A to B and B to A)，然後這些 parameter 會經過 Internet Key Exchange (IKE) protocal 來決定，IKE 主要有分兩個 step
        + IKE phase1: 主要做 Authenticate，Authentication 方面常常使用的都是 pre-shared key，基本上就是用同一組密碼，接著透過 Diffie-Hellman 來建立一組 Key，而這組 Key 是要被 Phase2 拿來用的。
        + IKE phase2: 處理 IPsec security 協商，最後 IPSec SA 完成，接下來才會建立 IPSec 的連線。
        + ** IKE 主要走 port 500
+ 雙因子認證機制Multi-Factor Authentication (MFA)：作為登入系統基本使用者密碼驗證之第二步驟的驗證機制，認證方式須包含兩個(或以上)因子，例如：
  + Something you know (例如：密碼)
  + Something you have (例如：token)
  + Something you are (例如：指紋)

+ 端點偵測及應變機制(Endpoint Detection and Response, 簡稱EDR)主要目的為偵測端點系統上異常活動，以期能及早發現駭客活動跡象，降低後續可能引發之資安風險。
+ 網路型入侵偵測系統（Network Intrusion Detection System, NIDS）
+ FDE (Full Disk Encryption) / FBE (File Based Encryption)
+ 通用漏洞評分系統 (Common Vulnerability Scoring System, CVSS)：https://ithelp.ithome.com.tw/articles/10203313
  + CVSS特別興趣群 (CVSS Special Interest Group, CVSS SIG)
+ FIRST是Forum of Incident Response and Security Teams的縮寫，為全球最大的資安事件應變及安全小組論壇：https://ithelp.ithome.com.tw/articles/10197572
+ 具有高度目的性、目標性的攻擊者稱為 Advanced Persistent Threat (APT；進階持續性威脅)。
+ 戰術面透過分析敵人的 Tactics, Techniques, and Procedures (TTP；戰術、技術、程序)，在資安設備上可以用來設定更精準的規則以偵測、阻擋敵人。
+ STIX (Structured Threat Information eXpression) 是由 MITRE 公司 (The MITRE Corporation) 所定義與開發出用來快速能達到表示事件相關性與涵蓋性之語言，以表達出架構性的網路威脅資訊。STIX 語言將包含網路威脅資訊的全部範圍，並盡可能地達到完整表示、彈性化、可延展性、自動化與可解讀性等特性。
+ 防範行動 (Course of Action，簡稱COA，包含事件應變或弱點補救措施)。
+ TAEII：Trusted Automated Exchange of Intelligence Information  https://ithelp.ithome.com.tw/articles/10289702
+ TAXII 有兩個服務：
  + 集合 (Collections)：Server 跟 Client 的交換埠口，這是我求它傳東西給我。
  + 頻道 (Channel)：生產者 (producer) 透過 Server 向 Client (Consumer)推播訊息，這是它直接把東西丟給我。
+ OSINT : Open-Source Intelligence
+ 紅綠燈協議（Traffic Light Protocol，TLP）TLP所採用的4種顏色為紅（TLP:RED ）、黃（TLP:AMBER）、綠（TLP:GREEN）與白（TLP:WHITE），紅色代表資訊的接受者不得與自己以外的其它人分享，例如只限與會人士得知；黃色代表只能與自己組織內的成員、或是必須知道才能避免危害的客戶分享；綠色則是能與同一領域的同儕或社群分享；白色代表可向大眾分享。
+ 完全前向保密（Perfect Forward Secrecy，PFS）是一件非常重要的工作；PFS是金鑰交換演算法的一項功能，是要確保即便伺服器的私鑰被駭，對話金鑰仍可以維持其安全性，透過為每個對話產生新的金鑰，PFS可以保護之前的對話，也能防止未來的金鑰洩漏。
+ FAR (False Acceptance Rate)：生物辨識系統誤將不合法使用者辨認為合法使用者的機率。代表安全程度。
+ FRR (False Rejection Rate)：生物辨識系統將合法使用者誤判為不合法使用者的機率。代表便利程度。
+ Disaster Recovery Plan (DRP)
+ Remote Administration Tool 遠端存取特洛伊木馬程式，可讓不法份子經由網際網路連線
+ FIM（File Integrity Monitoring，檔案完整性監控）：即時監控企業IT架構裡的重要檔案或系統物件，以發現任何未經管理的權限變更，或異常存取檔案的行為。
+ FRR(False Reject Rate),FAR(False Accept Rate) ,CER(Crossover Error Rate)
  + FRR:錯誤拒絕率，把對的驗證為錯誤的屬於Type I error
  + FAR:錯誤接受率，把錯誤的驗證為對的屬於Type II error
  + CER:交叉錯誤率，集合FRR及FAR兩個曲線的交叉點。
+ 輸入資料驗證 input data validation : 一種用於檢查輸入資料是否精確、完整與合理的輸入控制。
+ DNS Sinkholing 的機制，就是 : 當防火牆偵測到 DNS 查詢的是一個已知的惡意網域，防火牆就會回應一個偽造的IP (管理者定義)，使得這個連線失敗，讓電腦無法成功連線到惡意網站。
+ 國家支持型駭客的攻擊行為（state-sponsored actors）
+ Off-site backup（異地備援） is a method of backing up data to a remote server or to media that is transported off site.
遠端存取木馬程式 (RAT)
+ DKIM (DomainKeys Identified Mail) 網域驗證郵件，用來防止郵件內容遭到竄改
+ SPF (Sender Policy Framework) 寄件者政策框架：SPF 用來規範在選定的郵件發送服務器位址，可以用來發送寄件人的網域郵件。
+ DMARC 是用來輔助 SPF 與 DKIM 的不足：用來讓發信端網域通知收件端郵件服務器，當遇到 SPF 與 DKIM 的設定檢查不過時，進行的處理方式。
  + https://www.richesinfo.com.tw/index.php/mxmail/mxmail-faq/267-dkim-dmarc
+ Non-Polymorphic 類型即是指宿主文件在被感染後，不同的文件所擷取出來的病毒碼絕大部分都相同，表示此種感染型病毒在感染每個文件時，病毒碼都不會太大的差異，對於病毒開發者相對較容易，但一體兩面，對於病毒分析者也一樣較簡單的去分析病毒行為。
+ Polymorphic 較 Non-Polymorphic 的技術高端，可說是感染型病毒碼的一種保護方式，在不同檔案中比較擷取過後的病毒碼，可以發現病毒碼完全不一樣！
+ 產生 CSR 的過程: https://docs.gandi.net/zh-hant/ssl/common_operations/csr.html 
  + 填寫 簽署名稱（Common Name，CN），即為您要用憑證保護的網域名稱
  + https://blog.miniasp.com/post/2018/04/24/Using-PowerShell-to-build-Self-Signed-Certificate
  + http://ijecorp.blogspot.com/2016/01/ocsp-crl.html
+ 惡作劇病毒(Hoaxes)並不是真的病毒，您並不會因為開啟電子郵件而受到病毒感染。其本身不具任何破壞力，徒增恐慌和困擾。
+ Spam over instant messaging(SPIM)(即時通訊軟體上的垃圾訊息)
+ Identity fraud(身份詐騙)。
+ Credential harvesting(憑證竊取)
+ Typosquatting(利用相似域名的詐騙)
+ Message Digest Algorithm (MD5) : 可以產生出一個128位元（16個字元(BYTES)）的雜湊值（hash value），用於確保資訊傳輸完整一致。
+ Secure Hash Algorithm (SHA) : 是一個密碼雜湊函式家族，是FIPS所認證的安全雜湊演算法。能計算出一個數位訊息所對應到的，長度固定的字串（又稱訊息摘要）的演算法。且若輸入的訊息不同，它們對應到不同字串的機率很高。160位元~512位元
+ Padding Oracle On Downgraded Legacy Encryption（POODLE，貴賓狗）的攻擊行動，利用上述的降級功能突破了SSL 3.0的密碼安全防護，因而可用來竊取原本應是加密的cookies或Tokens。
+ 迪菲-赫爾曼密鑰交換（英語：Diffie–Hellman key exchange，縮寫為D-H） 是一種安全協定。它可以讓雙方在完全沒有對方任何預先資訊的條件下通過不安全信道建立起一個金鑰。這個金鑰可以在後續的通訊中作為對稱金鑰來加密通訊內容。
+ NFC：是Near Field Communication(近距離無線通訊/近場通訊)的縮寫，是一種短距離的高頻無線通訊技術，可以讓裝置以非接觸的方式進行點對點資料傳輸，也能夠讀取含有產品資訊的NFC標籤。起初是應用在信用卡和悠遊卡之類的塑膠貨幣上，在行動支付的運用中， Apple Pay、Samsung Pay、Android Pay、HCE手機信用卡/金融卡、TSM手機信用卡等，均使用同樣的傳輸方式；行動裝置之間的傳輸，或是手機與家電的傳輸，也可透過NFC完成。

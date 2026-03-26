# Cấu trúc chi tiết các Event trong Sysmon

> Tài liệu này mô tả cấu trúc, định nghĩa và ý nghĩa từng trường dữ liệu của tất cả các event trong **Sysmon** (EventID 1–26, 255), dựa trên tài liệu chính thức của Microsoft Sysinternals, cộng đồng SOC / DFIR, và các tài liệu Sysmon tiếng Việt đã đối chiếu, kiểm chứng.

---

## 1. EventID 1 – Process Create (Tạo tiến trình)

### Ý nghĩa
Ghi nhận sự kiện tạo mới một tiến trình (child) trên hệ thống, bao gồm chi tiết về tiến trình cha, lệnh thực thi, tài khoản người dùng và thông tin file thực thi.

### Danh sách các trường và ý nghĩa

| Trường | Kiểu / Ý nghĩa |
|-------|----------------|
| UtcTime | Thời gian UTC của sự kiện (thời điểm tạo tiến trình). |
| ProcessGuid | GUID duy nhất cho tiến trình được tạo (child process). Dùng để theo dõi tiến trình trong suốt vòng đời. |
| ProcessId | Process ID (PID) trên hệ điều hành của tiến trình được tạo. |
| Image | Đường dẫn đầy đủ đến file thực thi tạo nên tiến trình (ví dụ: `C:\Windows\System32\notepad.exe`). |
| FileVersion | Version của file thực thi (metadata `FileVersion`). |
| Description | Mô tả phần mềm trong file thực thi (metadata `FileDescription`). |
| Product | Tên sản phẩm của file thực thi (metadata `ProductName`). |
| OriginalFileName | Tên ban đầu của file, được ghi trong PE header (thường không bị đổi tên). |
| Company | Tên công ty sở hữu file thực thi (metadata `Company`). |
| CommandLine | Câu lệnh và tham số đầy đủ được dùng để chạy tiến trình (ví dụ: `cmd.exe /c whoami`). |
| CurrentDirectory | Thư mục làm việc hiện tại của tiến trình khi được tạo. |
| User | Tài khoản người dùng đã tạo tiến trình (định dạng `DOMAIN\Username`). |
| LogonGuid | Logon GUID, dùng để liên kết với các sự kiện đăng nhập khác (ví dụ: EventID 4624/4648). |
| LogonId | Logon ID của phiên đăng nhập, dùng để liên kết xuyên các event. |
| TerminalSessionId | ID của session RDP / Terminal (nếu có). |
| IntegrityLevel | Mức độ bảo mật (integrity level) của tiến trình: `Low`, `Medium`, `High`, `System`,… |
| Hashes | Băm file thực thi (MD5/SHA1/SHA256/IPMHASH…), tùy thuộc cấu hình `HashAlgorithms`. |
| ParentProcessGuid | GUID của tiến trình tạo nên tiến trình hiện tại (parent process). |
| ParentProcessId | PID của tiến trình cha. |
| ParentImage | Đường dẫn file thực thi của tiến trình cha. |
| ParentCommandLine | Câu lệnh đầy đủ của tiến trình cha (nếu có). |

### Ứng dụng trong phân tích
- Vẽ cây process tree (mối quan hệ parent–child).
- Phát hiện các parent bất thường (ví dụ: `svchost.exe` sinh `powershell.exe`).
- Phát hiện LOLBins (living-off-the-land binaries) và các lệnh shell/PowerShell bất thường.

---

## 2. EventID 2 – File Creation Time Changed (Thay đổi thời gian tạo file)

### Ý nghĩa
Ghi nhận khi một tiến trình thay đổi **thời gian tạo (Creation Time)** của một file – thường được dùng để **timestomp** (che dấu thời gian thiệt hại).

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC của sự kiện. |
| ProcessGuid | GUID của tiến trình thực hiện thay đổi thời gian. |
| ProcessId | PID của tiến trình đó. |
| Image | Đường dẫn file thực thi của tiến trình. |
| TargetFilename | Đường dẫn đầy đủ của file bị thay đổi thời gian tạo. |
| CreationUtcTime | Giá trị **mới** của thời gian tạo (UTC). |
| PreviousCreationUtcTime | Giá trị **cũ** của thời gian tạo trước khi bị thay đổi. |
| User | Tài khoản người dùng đã thực hiện thay đổi. |

### Ứng dụng trong phân tích
- Phát hiện **timestomping** dùng trong malware/ATA để làm xáo trộn timeline.
- Phát hiện khi kẻ tấn công sửa lại evidence (file log, malware…).

---

## 3. EventID 3 – Network Connection (Kết nối mạng)

### Ý nghĩa
Ghi nhận các kết nối mạng TCP/UDP được khởi tạo hoặc nhận trên hệ thống, bao gồm chi tiết 5-tuple (source/destination IP, port, protocol).

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC của sự kiện. |
| ProcessGuid | GUID của tiến trình thực hiện kết nối. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi của tiến trình. |
| User | Tài khoản người dùng chạy tiến trình. |
| Protocol | Giao thức mạng: `6` = TCP, `17` = UDP. |
| Initiated | `True` nếu tiến trình **khởi tạo** kết nối (outbound). |
| SourceIsIpv6 | `True` nếu địa chỉ nguồn là IPv6. |
| SourceIp | Địa chỉ IP địa phương (source). |
| SourceHostname | Tên host DNS của địa chỉ nguồn (nếu bật `DnsLookup`). |
| SourcePort | Cổng nguồn (local port). |
| SourcePortName | Tên dịch vụ (ví dụ: `http`, `rdp`, `dns`). |
| DestinationIsIpv6 | `True` nếu địa chỉ đích là IPv6. |
| DestinationIp | Địa chỉ IP remote (destination). |
| DestinationHostname | Tên host DNS của địa chỉ đích (nếu có reverse DNS). |
| DestinationPort | Cổng đích (remote port). |
| DestinationPortName | Tên dịch vụ đích (ví dụ: `http`, `https`, `445`). |

### Ứng dụng trong phân tích
- Phát hiện **C2 beaconing**, beacon qua HTTPS/DNS_tunneling.
- Phát hiện kẻ tấn công thực hiện **lateral movement** (SMB, RDP, RPC…).
- Xây dựng đồ thị kết nối mạng cho host.

---

## 4. EventID 4 – Sysmon Service State Changed (Thay đổi trạng thái dịch vụ Sysmon)

### Ý nghĩa
Ghi nhận khi dịch vụ **Sysmon** khởi động, dừng hoặc gặp lỗi.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC của sự kiện. |
| State | Trạng thái dịch vụ: `running`, `stopped`, `error`,… |
| Version | Phiên bản binary Sysmon (ví dụ: `14.15`). |
| SchemaVersion | Phiên bản schema cấu hình Sysmon (ví dụ: `4.30`). |

### Ứng dụng trong phân tích
- Phát hiện **Sysmon bị tắt** hoặc **restart** (potentially tampering).
- Theo dõi các lần thay đổi cấu hình sau khi service restart.

---

## 5. EventID 5 – Process Terminated (Tiến trình kết thúc)

### Ý nghĩa
Ghi nhận khi một tiến trình bị kết thúc (thoát, bị kill, crash).

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC tiến trình kết thúc. |
| ProcessGuid | GUID của tiến trình bị kết thúc. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi của tiến trình. |
| User | Tài khoản người dùng đã tạo tiến trình (nếu còn có thể thu thập). |
| ExitStatus | Mã exit code của tiến trình (thường 0 = bình thường, khác 0 = lỗi). |

### Ứng dụng trong phân tích
- Xác định thời điểm **malware bị tắt** hoặc **process bị kill**.
- Liên kết với các event khác (Process Create, Network, File) để hiểu vòng đời tiến trình.

---

## 6. EventID 6 – Kernel Driver Loaded (Driver kernel được load)

### Ý nghĩa
Ghi nhận khi một **driver kernel** được load vào hệ thống – thường dùng để phát hiện **rootkit** hoặc driver độc hại.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC driver được load. |
| ImageLoaded | Đường dẫn đầy đủ đến file driver (ví dụ: `C:\Windows\System32\drivers\malware.sys`). |
| Hashes | Băm file driver (MD5/SHA1/SHA256…). |
| Signed | `True` nếu driver có chữ ký số hợp lệ. |
| Signature | Tên chủ thể (signer) của chữ ký số. |
| SignatureStatus | Tình trạng chữ ký: `Valid`, `Invalid`, `Unknown`. |

### Ứng dụng trong phân tích
- Phát hiện **rootkit driver**, driver không ký (untrusted).
- Theo dõi các driver lạ được load sau khi C2 hoạt động.

---

## 7. EventID 7 – Image Loaded (Load DLL / Module)

### Ý nghĩa
Ghi nhận khi một **module / DLL** được load vào không gian bộ nhớ của một tiến trình – rất quan trọng trong phát hiện **DLL injection**.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC DLL được load. |
| ProcessGuid | GUID của tiến trình chứa DLL. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi của tiến trình. |
| ImageLoaded | Đường dẫn file DLL được load. |
| FileVersion | Phiên bản của DLL. |
| Description | Mô tả của DLL. |
| Product | Tên sản phẩm của DLL. |
| Company | Tên công ty của DLL. |
| OriginalFileName | Tên ban đầu của file DLL (trong PE header). |
| Hashes | Băm file DLL (MD5/SHA1/SHA256/IPMHASH…). |
| Signed | `True` nếu DLL có chữ ký hợp lệ. |
| Signature | Tên người ký DLL. |
| SignatureStatus | Trạng thái chữ ký DLL. |
| User | Tài khoản người dùng của tiến trình. |

### Ứng dụng trong phân tích
- Phát hiện **DLL sideloading**, **DLL hijacking** (DLL đặt tên giả, ở thư mục khác).
- Phát hiện **reflective DLL injection** hoặc **applocker bypass**.

---

## 8. EventID 8 – CreateRemoteThread (Remote Thread / Inject)

### Ý nghĩa
Ghi nhận khi một tiến trình tạo một thread trong **tiến trình khác** (thường dùng để code injection).

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC sự kiện. |
| SourceProcessGuid | GUID của tiến trình **khởi tạo** remote thread. |
| SourceProcessId | PID của tiến trình nguồn. |
| SourceImage | Đường dẫn file thực thi của tiến trình nguồn. |
| TargetProcessGuid | GUID của tiến trình **bị inject** (target). |
| TargetProcessId | PID của tiến trình bị inject. |
| TargetImage | Đường dẫn file thực thi của tiến trình bị inject. |
| NewThreadId | ID của thread mới được tạo. |
| StartAddress | Địa chỉ bắt đầu chạy của thread (RVA). |
| StartModule | Module nào chứa địa chỉ `StartAddress` (nếu có). |
| StartFunction | Tên hàm (nếu có khớp với export table). |
| SourceUser | Tài khoản người dùng của tiến trình nguồn. |
| TargetUser | Tài khoản người dùng của tiến trình mục tiêu. |

### Ứng dụng trong phân tích
- Phát hiện **process hollowing**, **DLL injection**.
- Phát hiện **privilege escalation** lên các tiến trình có đặc quyền cao (ví dụ: LSASS, svchost).

---

## 9. EventID 9 – RawAccessRead (Đọc trực tiếp thiết bị – Raw Disk Access)

### Ý nghĩa
Ghi nhận khi một tiến trình thực hiện **đọc trực tiếp** từ thiết bị lưu trữ (ví dụ: `\\Device\\HarddiskVolumeX`), thường dùng trong các công cụ Forensics hoặc RAT.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC sự kiện. |
| ProcessGuid | GUID của tiến trình thực hiện đọc. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi. |
| Device | Đường dẫn thiết bị được đọc (ví dụ: `\\Device\\HarddiskVolume1`). |
| User | Tài khoản người dùng. |

### Ứng dụng trong phân tích
- Phát hiện công cụ **disk imaging**, **credential harvester** trực tiếp từ disk.
- Theo dõi các hành vi **offensive tooling** (ví dụ: Mimikatz, forensic tools…).

---

## 10. EventID 10 – Process Access (Process Access)

### Ý nghĩa
Ghi nhận khi một tiến trình mở **handle** tới một tiến trình khác (ví dụ: dùng `NtOpenProcess`). Thường dùng để phát hiện **credential dumping** hoặc **debug access**.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC. |
| SourceProcessGUID | GUID của tiến trình **mở** handle. |
| SourceProcessId | PID của tiến trình nguồn. |
| SourceThreadId | ID thread trong tiến trình nguồn thực hiện mở handle. |
| SourceImage | Đường dẫn file thực thi của tiến trình nguồn. |
| TargetProcessGUID | GUID của tiến trình **bị truy cập**. |
| TargetProcessId | PID của tiến trình bị truy cập. |
| TargetImage | Đường dẫn file thực thi của tiến trình mục tiêu. |
| GrantedAccess | Bitmask quyền được cấp (ví dụ: `0x1F0B` – quyền debug toàn bộ). |
| CallTrace | Stack trace ngắn (DLL và RVA) của hàm gọi `NtOpenProcess`. |
| SourceUser | Tài khoản người dùng của tiến trình nguồn. |
| TargetUser | Tài khoản người dùng của tiến trình mục tiêu. |

### Ứng dụng trong phân tích
- Phát hiện **LSASS access** (ví dụ: `mimikatz`, `sekurlsa::logonPasswords`).
- Phát hiện **process injection** hoặc **debugging** tiến trình hệ thống.

---

## 11. EventID 11 – File Create (File được tạo / ghi đè)

### Ý nghĩa
Ghi nhận khi một file được **tạo mới** hoặc **ghi đè** trên hệ thống.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC sự kiện. |
| ProcessGuid | GUID của tiến trình tạo file. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi của tiến trình. |
| TargetFilename | Đường dẫn đầy đủ của file được tạo. |
| CreationUtcTime | Thời gian tạo file (UTC). |
| User | Tài khoản người dùng tạo file. |

### Ứng dụng trong phân tích
- Phát hiện **payload drop**, **webshell**, **config file bị ghi đè**.
- Xác định thời điểm file bất thường được tạo sau khi C2 chạy.

---

## 12. EventID 12 – RegistryEvent (Object Create and Delete – Tạo/Xóa khóa Registry)

### Ý nghĩa
Ghi nhận khi một **khóa registry** được tạo hoặc xóa.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC sự kiện. |
| EventType | `CreateKey` hoặc `DeleteKey`. |
| ProcessGuid | GUID của tiến trình tạo/xóa khóa. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi của tiến trình. |
| TargetObject | Đường dẫn đầy đủ khóa registry (ví dụ: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\malware`). |
| User | Tài khoản người dùng truy cập registry. |

### Ứng dụng trong phân tích
- Phát hiện **persistence** trong Run, RunOnce, RunServices,…
- Phát hiện **registry-based backdoor** hoặc **config change**.

---

## 13. EventID 13 – RegistryEvent (Value Set – Thiết lập giá trị Registry)

### Ý nghĩa
Ghi nhận khi giá trị bên trong một khóa registry được **thay đổi**.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC sự kiện. |
| EventType | `SetValue`. |
| ProcessGuid | GUID của tiến trình. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi. |
| TargetObject | Đường dẫn đầy đủ khóa registry. |
| Details | Giá trị mới được gán (data của value). |
| User | Tài khoản người dùng. |

### Ứng dụng trong phân tích
- Phát hiện **enable/disable** tính năng bảo mật (ví dụ: WDigest, LSA Protection).
- Theo dõi thay đổi **policy** hoặc **registry-based configuration**.

---

## 14. EventID 14 – RegistryEvent (Key and Value Rename – Đổi tên khóa/giá trị)

### Ý nghĩa
Ghi nhận khi một **khóa hoặc giá trị registry** bị đổi tên.

### Danh sách các trường

| Trường | Ý nghĩa |
|-------|---------|
| UtcTime | Thời gian UTC sự kiện. |
| EventType | `RenameKey` (đổi tên khóa). |
| ProcessGuid | GUID của tiến trình. |
| ProcessId | PID của tiến trình. |
| Image | Đường dẫn file thực thi. |
|

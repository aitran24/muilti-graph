# Phân tích chi tiết các mã MITRE ATT&CK trong danh sách đầu vào

## Phạm vi và cách đọc

Tài liệu này được dựng theo danh sách 140 mã mà bạn cung cấp. Mục tiêu của file là gom toàn bộ kỹ thuật tương ứng, biểu hiện, hành vi, dấu vết săn tìm, và luồng tấn công thường gặp vào một chỗ để tiện đọc, đối chiếu và map hunting/detection.

## Ghi chú chuẩn hoá mã

- `T1547.011` là mã lịch sử và ATT&CK hiện đã thay bằng `T1647 - Plist File Modification`.
- `T1053.004` là mã lịch sử đã bị deprecate. Trong bối cảnh ATT&CK cũ, nó gắn với `Scheduled Task/Job: Launchd`.
- `T1035.009` không còn xuất hiện như một live technique ID trên ATT&CK Enterprise hiện hành. Trong file này nó được giữ nguyên theo input nhưng được gắn cờ là mã legacy/không rõ, gần nhất về mặt phân tích là `T1036.009 - Break Process Trees`.

## Cấu trúc mỗi mục

Mỗi kỹ thuật được trình bày theo cùng một khung:
1. Trạng thái ATT&CK hiện tại.
2. Bản chất kỹ thuật.
3. Điều kiện/tiền đề thường thấy.
4. Biểu hiện và hành vi chi tiết.
5. Luồng tấn công tương ứng.
6. Dấu vết/hunting ưu tiên.
7. Liên hệ hoặc biến thể nên xem cùng.
8. URL ATT&CK để đối chiếu nhanh.

---
## T1003.006 - OS Credential Dumping: DCSync
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công giả lập lưu lượng replication của Domain Controller để kéo NTLM/Kerberos material từ Active Directory mà không cần dump trực tiếp trên DC. Thường lợi dụng quyền Replicating Directory Changes, Mimikatz/DSInternals hoặc API DRS để lấy hash của KRBTGT, admin domain, service account và lịch sử mật khẩu.
- **Điều kiện/tiền đề thường thấy:** Thường đòi hỏi foothold miền nội bộ và quyền đặc biệt trong AD hoặc khả năng đọc vật liệu xác thực liên quan đến domain.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công giả lập lưu lượng replication của Domain Controller để kéo NTLM/Kerberos material từ Active Directory mà không cần dump trực tiếp trên DC. Thường lợi dụng quyền Replicating Directory Changes, Mimikatz/DSInternals hoặc API DRS để lấy hash của KRBTGT, admin domain, service account và lịch sử mật khẩu. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold nội bộ -> leo quyền đến cấp domain -> trích hoặc giả vật liệu Kerberos/hash -> mạo danh tài khoản mạnh -> persistence và lateral movement.
- **Dấu vết/hunting ưu tiên:** Săn sự kiện replication hoặc DRS từ máy không phải DC, yêu cầu Kerberos/LDAP/Netlogon bất thường, ticket có tuổi đời lạ, SPN/SID-History biến động và đặc biệt là quyền Replicating Directory Changes trên principal không nên có.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1003/006/

## T1005 - Data from Local System
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1005/

## T1012 - Query Registry
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor đọc Registry để lấy cấu hình máy, phần mềm đã cài, thiết lập proxy, đường dẫn RDP, dấu hiệu anti-analysis và khoá persistence. Hoạt động này hay đi qua reg.exe, WinAPI hoặc WMI để phục vụ quyết định bước kế tiếp.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor đọc Registry để lấy cấu hình máy, phần mềm đã cài, thiết lập proxy, đường dẫn RDP, dấu hiệu anti-analysis và khoá persistence. Hoạt động này hay đi qua reg.exe, WinAPI hoặc WMI để phục vụ quyết định bước kế tiếp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Tìm chuỗi lệnh liệt kê file, account, port, dịch vụ, VM, registry hoặc cloud asset trong thời gian ngắn. Process hệ thống hoặc ứng dụng văn phòng mà bỗng làm discovery hàng loạt thường rất đáng ngờ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1012/

## T1020 - Automated Exfiltration
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: dữ liệu đã được gom -> nén hoặc mã hoá hoặc chia lô -> gửi ra ngoài qua C2/web/cloud/alternative protocol -> xoá dấu vết hoặc đổi kênh nếu bị chặn.
- **Dấu vết/hunting ưu tiên:** Hunting bằng burst outbound tới web service, cloud storage hoặc C2 sau giai đoạn archive/collection; file nén, file tạm, password-protected archive tạo rồi xóa nhanh; và dòng dữ liệu nhỏ nhưng đều để né ngưỡng cảnh báo.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1020/

## T1021 - Remote Services
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor dùng SMB, RDP, SSH, WinRM, VNC, VPN, Citrix hoặc nền tảng quản trị từ xa để điều khiển máy khác, thực thi lệnh, copy file và lan ngang hoặc chui vào nội bộ từ ngoài Internet. Khi có quyền hợp lệ, kỹ thuật này giảm nhu cầu phải đưa payload mới lên mỗi máy.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Actor dùng SMB, RDP, SSH, WinRM, VNC, VPN, Citrix hoặc nền tảng quản trị từ xa để điều khiển máy khác, thực thi lệnh, copy file và lan ngang hoặc chui vào nội bộ từ ngoài Internet. Khi có quyền hợp lệ, kỹ thuật này giảm nhu cầu phải đưa payload mới lên mỗi máy. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1021/

## T1027.006 - Obfuscated Files or Information: HTML Smuggling
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1027.010, T1027.011, T1027.013. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1027/006/

## T1027.010 - Obfuscated Files or Information: Command Obfuscation
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1027.006, T1027.011, T1027.013. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1027/010/

## T1027.011 - Obfuscated Files or Information: Fileless Storage
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1027.006, T1027.010, T1027.013. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1027/011/

## T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1027.006, T1027.010, T1027.011. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1027/013/

## T1030 - Data Transfer Size Limits
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1030/

## T1035.009 - LEGACY/UNCLEAR: likely intended T1036.009 Masquerading: Break Process Trees
- **Trạng thái ATT&CK:** legacy/unclear; likely typo or stale mapping to T1036.009
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Không có live page ATT&CK hiện hành cho mã này; trong file đã gắn cờ để kiểm tra thủ công, gần nhất với T1036.009 Break Process Trees. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** Không tìm thấy live page ATT&CK hiện hành; cần đối chiếu lại nguồn đầu vào. Gần nhất trên ATT&CK live là T1036.009

## T1036.002 - Masquerading: Right-to-Left Override
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1036.005, T1036.008, T1036.009. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1036/002/

## T1036.005 - Masquerading: Match Legitimate Resource Name or Location
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1036.002, T1036.008, T1036.009. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1036/005/

## T1036.008 - Masquerading: Masquerade File Type
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1036.002, T1036.005, T1036.009. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1036/008/

## T1036.009 - Masquerading: Break Process Trees
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1036.002, T1036.005, T1036.008. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1036/009/

## T1037.002 - Boot or Logon Initialization Scripts: Login Hook
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1037/002/

## T1040 - Network Sniffing
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu là chặn hoặc đọc lưu lượng để lấy thông tin xác thực, session token, tên miền nội bộ, giao thức điều khiển và dữ liệu truyền rõ. Trong mạng nội bộ, ARP poisoning thường được dùng để ép lưu lượng của nạn nhân đi qua máy của actor.
- **Điều kiện/tiền đề thường thấy:** Cần vị trí mạng thuận lợi, khả năng ở cùng broadcast domain, cài công cụ capture hoặc quyền cấu hình mạng trung gian.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu là chặn hoặc đọc lưu lượng để lấy thông tin xác thực, session token, tên miền nội bộ, giao thức điều khiển và dữ liệu truyền rõ. Trong mạng nội bộ, ARP poisoning thường được dùng để ép lưu lượng của nạn nhân đi qua máy của actor. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1040/

## T1041 - Exfiltration Over C2 Channel
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: dữ liệu đã được gom -> nén hoặc mã hoá hoặc chia lô -> gửi ra ngoài qua C2/web/cloud/alternative protocol -> xoá dấu vết hoặc đổi kênh nếu bị chặn.
- **Dấu vết/hunting ưu tiên:** Hunting bằng burst outbound tới web service, cloud storage hoặc C2 sau giai đoạn archive/collection; file nén, file tạm, password-protected archive tạo rồi xóa nhanh; và dòng dữ liệu nhỏ nhưng đều để né ngưỡng cảnh báo.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1041/

## T1046 - Network Service Discovery
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1046/

## T1048 - Exfiltration Over Alternative Protocol
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: dữ liệu đã được gom -> nén hoặc mã hoá hoặc chia lô -> gửi ra ngoài qua C2/web/cloud/alternative protocol -> xoá dấu vết hoặc đổi kênh nếu bị chặn.
- **Dấu vết/hunting ưu tiên:** Hunting bằng burst outbound tới web service, cloud storage hoặc C2 sau giai đoạn archive/collection; file nén, file tạm, password-protected archive tạo rồi xóa nhanh; và dòng dữ liệu nhỏ nhưng đều để né ngưỡng cảnh báo.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1048/

## T1053 - Scheduled Task/Job
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có quyền cục bộ -> ghi cấu hình trigger/job/service -> hệ thống tự chạy payload ở lần boot/logon/sự kiện kế tiếp -> duy trì chỗ đứng dài hạn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1053.004, T1053.007.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1053/

## T1053.004 - DEPRECATED: Scheduled Task/Job: Launchd
- **Trạng thái ATT&CK:** deprecated historical sub-technique
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có quyền cục bộ -> ghi cấu hình trigger/job/service -> hệ thống tự chạy payload ở lần boot/logon/sự kiện kế tiếp -> duy trì chỗ đứng dài hạn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Mã này đã bị deprecate; về mặt hành vi lịch sử nó gắn với Launchd trên macOS. Cùng họ kỹ thuật trong tập mã này: T1053, T1053.007.
- **ATT&CK URL:** Không còn trang live độc lập; tham chiếu ATT&CK release notes về Scheduled Task/Job: Launchd (deprecated)

## T1053.007 - Scheduled Task/Job: Container Orchestration Job
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có quyền cục bộ -> ghi cấu hình trigger/job/service -> hệ thống tự chạy payload ở lần boot/logon/sự kiện kế tiếp -> duy trì chỗ đứng dài hạn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1053, T1053.004.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1053/007/

## T1059.002 - Command and Scripting Interpreter: AppleScript
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1059/002/

## T1070.003 - Indicator Removal: Clear Command History
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1070.004. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1070/003/

## T1070.004 - Indicator Removal: File Deletion
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1070.003. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1070/004/

## T1071.001 - Application Layer Protocol: Web Protocols
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1071.002.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1071/001/

## T1071.002 - Application Layer Protocol: File Transfer Protocols
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1071.001.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1071/002/

## T1072 - Software Deployment Tools
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor mượn hạ tầng hoặc quyền tin cậy sẵn có của bên thứ ba, sản phẩm quản trị hoặc pipeline triển khai để code độc chạy dưới vỏ bọc hợp pháp. Đây là kiểu supply-chain hoặc post-compromise rất khó phân biệt với vận hành bình thường.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor mượn hạ tầng hoặc quyền tin cậy sẵn có của bên thứ ba, sản phẩm quản trị hoặc pipeline triển khai để code độc chạy dưới vỏ bọc hợp pháp. Đây là kiểu supply-chain hoặc post-compromise rất khó phân biệt với vận hành bình thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1072/

## T1078.004 - Valid Accounts: Cloud Accounts
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Tài khoản cloud hợp lệ bị lạm dụng để vào tenant một cách có vẻ hợp pháp. Sau khi đăng nhập thành công, actor thường đổi MFA, thêm secret, cấp role, tạo automation hoặc truy cập dữ liệu SaaS/IaaS ngay dưới ngữ cảnh của người dùng thật.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Tài khoản cloud hợp lệ bị lạm dụng để vào tenant một cách có vẻ hợp pháp. Sau khi đăng nhập thành công, actor thường đổi MFA, thêm secret, cấp role, tạo automation hoặc truy cập dữ liệu SaaS/IaaS ngay dưới ngữ cảnh của người dùng thật. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có credential hoặc session -> đăng nhập hợp lệ -> mở rộng quyền hoặc truy dữ liệu trực tiếp -> thiết lập cơ chế bền hơn như rule, token, key hoặc role.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1078/004/

## T1083 - File and Directory Discovery
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Tìm chuỗi lệnh liệt kê file, account, port, dịch vụ, VM, registry hoặc cloud asset trong thời gian ngắn. Process hệ thống hoặc ứng dụng văn phòng mà bỗng làm discovery hàng loạt thường rất đáng ngờ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1083/

## T1087 - Account Discovery
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Tìm chuỗi lệnh liệt kê file, account, port, dịch vụ, VM, registry hoặc cloud asset trong thời gian ngắn. Process hệ thống hoặc ứng dụng văn phòng mà bỗng làm discovery hàng loạt thường rất đáng ngờ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1087.004. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1087/

## T1087.004 - Account Discovery: Cloud Account
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1087. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1087/004/

## T1095 - Non-Application Layer Protocol
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1095/

## T1098.001 - Account Manipulation: Additional Cloud Credentials
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1098.002, T1098.003, T1098.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1098/001/

## T1098.002 - Account Manipulation: Additional Email Delegate Permissions
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1098.001, T1098.003, T1098.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1098/002/

## T1098.003 - Account Manipulation: Additional Cloud Roles
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1098.001, T1098.002, T1098.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1098/003/

## T1098.005 - Account Manipulation: Device Registration
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là sửa đối tượng identity để tạo đường vào bền hơn: thêm access key hoặc secret, cấp role mạnh hơn, đăng ký thiết bị tin cậy, hoặc gán delegate. Kiểu này nguy vì khiến truy cập sau đó trông giống hoạt động quản trị hợp pháp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1098.001, T1098.002, T1098.003. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1098/005/

## T1102 - Web Service
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1102.002.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1102/

## T1102.002 - Web Service: Bidirectional Communication
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1102.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1102/002/

## T1110 - Brute Force
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1110.002, T1110.003, T1110.004.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1110/

## T1110.002 - Brute Force: Password Cracking
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1110, T1110.003, T1110.004. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1110/002/

## T1110.003 - Brute Force: Password Spraying
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1110, T1110.002, T1110.004. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1110/003/

## T1110.004 - Brute Force: Credential Stuffing
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này xoay quanh việc thử mật khẩu ở quy mô lớn nhưng cách ra đòn khác nhau: cracking thường diễn ra offline trên hash; spraying dùng ít mật khẩu lên nhiều tài khoản để né lockout; stuffing tái sử dụng bộ username/password đã lộ; brute force tổng quát thử lặp trực tiếp lên giao diện đăng nhập. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1110, T1110.002, T1110.003. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1110/004/

## T1113 - Screen Capture
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Malware chụp màn hình toàn phiên, từng cửa sổ hoặc theo sự kiện để lấy nội dung người dùng đang xem, tài liệu mở sẵn, giao diện ngân hàng, email hoặc dashboard quản trị. Một số mẫu chụp định kỳ, một số chụp khi foreground window đổi.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Malware chụp màn hình toàn phiên, từng cửa sổ hoặc theo sự kiện để lấy nội dung người dùng đang xem, tài liệu mở sẵn, giao diện ngân hàng, email hoặc dashboard quản trị. Một số mẫu chụp định kỳ, một số chụp khi foreground window đổi. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1113/

## T1114 - Email Collection
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu là thu thập nội dung mailbox, tiêu đề, attachment, metadata hoặc toàn bộ lịch sử thư. Có thể đi qua IMAP, POP, EWS, Graph, Exchange Online hoặc truy cập trực tiếp nếu đã chiếm quyền mailbox.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu là thu thập nội dung mailbox, tiêu đề, attachment, metadata hoặc toàn bộ lịch sử thư. Có thể đi qua IMAP, POP, EWS, Graph, Exchange Online hoặc truy cập trực tiếp nếu đã chiếm quyền mailbox. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1114.002, T1114.003. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1114/

## T1114.002 - Email Collection: Remote Email Collection
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu là thu thập nội dung mailbox, tiêu đề, attachment, metadata hoặc toàn bộ lịch sử thư. Có thể đi qua IMAP, POP, EWS, Graph, Exchange Online hoặc truy cập trực tiếp nếu đã chiếm quyền mailbox.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu là thu thập nội dung mailbox, tiêu đề, attachment, metadata hoặc toàn bộ lịch sử thư. Có thể đi qua IMAP, POP, EWS, Graph, Exchange Online hoặc truy cập trực tiếp nếu đã chiếm quyền mailbox. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1114, T1114.003. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1114/002/

## T1114.003 - Email Collection: Email Forwarding Rule
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor thay luật hộp thư để tự động chuyển tiếp, ẩn, đánh dấu đã đọc hoặc redirect thư nhạy cảm. Đây là kiểu persistence rất khó chịu trong Exchange/M365 vì nó sống trong mailbox thay vì trên endpoint.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor thay luật hộp thư để tự động chuyển tiếp, ẩn, đánh dấu đã đọc hoặc redirect thư nhạy cảm. Đây là kiểu persistence rất khó chịu trong Exchange/M365 vì nó sống trong mailbox thay vì trên endpoint. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1114, T1114.002. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1114/003/

## T1119 - Automated Collection
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1119/

## T1129 - Shared Modules
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1129/

## T1133 - External Remote Services
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor dùng SMB, RDP, SSH, WinRM, VNC, VPN, Citrix hoặc nền tảng quản trị từ xa để điều khiển máy khác, thực thi lệnh, copy file và lan ngang hoặc chui vào nội bộ từ ngoài Internet. Khi có quyền hợp lệ, kỹ thuật này giảm nhu cầu phải đưa payload mới lên mỗi máy.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Actor dùng SMB, RDP, SSH, WinRM, VNC, VPN, Citrix hoặc nền tảng quản trị từ xa để điều khiển máy khác, thực thi lệnh, copy file và lan ngang hoặc chui vào nội bộ từ ngoài Internet. Khi có quyền hợp lệ, kỹ thuật này giảm nhu cầu phải đưa payload mới lên mỗi máy. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có credential hoặc session -> đăng nhập hợp lệ -> mở rộng quyền hoặc truy dữ liệu trực tiếp -> thiết lập cơ chế bền hơn như rule, token, key hoặc role.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1133/

## T1134 - Access Token Manipulation
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1134.001, T1134.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1134/

## T1134.001 - Access Token Manipulation: Token Impersonation/Theft
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1134, T1134.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1134/001/

## T1134.005 - Access Token Manipulation: SID-History Injection
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường đòi hỏi foothold miền nội bộ và quyền đặc biệt trong AD hoặc khả năng đọc vật liệu xác thực liên quan đến domain.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1134, T1134.001. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1134/005/

## T1136 - Create Account
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1136.003. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1136/

## T1136.003 - Create Account: Cloud Account
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1136. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1136/003/

## T1176.001 - Software Extensions: Browser Extensions
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor nhắm thẳng vào browser để cướp session sống, chèn extension, chích script, đọc cookie và token rồi mượn phiên đã đăng nhập. Loại này rất nguy với SaaS, SSO và quản trị cloud vì có thể vượt qua cả MFA khi cookie còn hiệu lực.
- **Điều kiện/tiền đề thường thấy:** Cần quyền trên endpoint, vào được profile browser hoặc chiếm được phiên người dùng đang đăng nhập.
- **Biểu hiện và hành vi chi tiết:** Actor nhắm thẳng vào browser để cướp session sống, chèn extension, chích script, đọc cookie và token rồi mượn phiên đã đăng nhập. Loại này rất nguy với SaaS, SSO và quản trị cloud vì có thể vượt qua cả MFA khi cookie còn hiệu lực. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có credential hoặc session -> đăng nhập hợp lệ -> mở rộng quyền hoặc truy dữ liệu trực tiếp -> thiết lập cơ chế bền hơn như rule, token, key hoặc role.
- **Dấu vết/hunting ưu tiên:** Theo dõi truy cập file profile browser, DB cookie/login data, extension manifest, local storage, remote debugging và tiến trình lạ tiêm vào browser. Phía SaaS cần đối chiếu phiên đổi IP/UA bất thường nhưng vẫn vượt qua xác thực.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1176/001/

## T1185 - Browser Session Hijacking
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor nhắm thẳng vào browser để cướp session sống, chèn extension, chích script, đọc cookie và token rồi mượn phiên đã đăng nhập. Loại này rất nguy với SaaS, SSO và quản trị cloud vì có thể vượt qua cả MFA khi cookie còn hiệu lực.
- **Điều kiện/tiền đề thường thấy:** Cần quyền trên endpoint, vào được profile browser hoặc chiếm được phiên người dùng đang đăng nhập.
- **Biểu hiện và hành vi chi tiết:** Actor nhắm thẳng vào browser để cướp session sống, chèn extension, chích script, đọc cookie và token rồi mượn phiên đã đăng nhập. Loại này rất nguy với SaaS, SSO và quản trị cloud vì có thể vượt qua cả MFA khi cookie còn hiệu lực. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có credential hoặc session -> đăng nhập hợp lệ -> mở rộng quyền hoặc truy dữ liệu trực tiếp -> thiết lập cơ chế bền hơn như rule, token, key hoặc role.
- **Dấu vết/hunting ưu tiên:** Theo dõi truy cập file profile browser, DB cookie/login data, extension manifest, local storage, remote debugging và tiến trình lạ tiêm vào browser. Phía SaaS cần đối chiếu phiên đổi IP/UA bất thường nhưng vẫn vượt qua xác thực.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1185/

## T1187 - Forced Authentication
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1187/

## T1199 - Trusted Relationship
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor mượn hạ tầng hoặc quyền tin cậy sẵn có của bên thứ ba, sản phẩm quản trị hoặc pipeline triển khai để code độc chạy dưới vỏ bọc hợp pháp. Đây là kiểu supply-chain hoặc post-compromise rất khó phân biệt với vận hành bình thường.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor mượn hạ tầng hoặc quyền tin cậy sẵn có của bên thứ ba, sản phẩm quản trị hoặc pipeline triển khai để code độc chạy dưới vỏ bọc hợp pháp. Đây là kiểu supply-chain hoặc post-compromise rất khó phân biệt với vận hành bình thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1199/

## T1203 - Exploitation for Client Execution
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp.
- **Điều kiện/tiền đề thường thấy:** Cần phiên bản phần mềm hoặc dịch vụ dễ tổn thương hoặc điều kiện để ép người dùng tương tác với đối tượng độc hại.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1203/

## T1204.003 - User Execution: Malicious Image
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1204/003/

## T1207 - Rogue Domain Controller
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1207/

## T1210 - Exploitation of Remote Services
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1210/

## T1212 - Exploitation for Credential Access
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp.
- **Điều kiện/tiền đề thường thấy:** Cần phiên bản phần mềm hoặc dịch vụ dễ tổn thương hoặc điều kiện để ép người dùng tương tác với đối tượng độc hại.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1212/

## T1213 - Data from Information Repositories
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1213.002. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1213/

## T1213.002 - Data from Information Repositories: Sharepoint
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1213. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1213/002/

## T1218.003 - System Binary Proxy Execution: CMSTP
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1218.014.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1218/003/

## T1218.014 - System Binary Proxy Execution: MMC
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1218.003.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1218/014/

## T1222.002 - File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1222/002/

## T1480 - Execution Guardrails
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mã độc tự kiểm tra môi trường trước khi bung hành vi thật: dò VM, sandbox, tiến trình phân tích, vùng ngôn ngữ, mutex, domain, IP, file hoặc điều kiện mục tiêu. Nếu điều kiện không khớp, nó ngủ, thoát hoặc chỉ chạy tính năng vô hại.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mã độc tự kiểm tra môi trường trước khi bung hành vi thật: dò VM, sandbox, tiến trình phân tích, vùng ngôn ngữ, mutex, domain, IP, file hoặc điều kiện mục tiêu. Nếu điều kiện không khớp, nó ngủ, thoát hoặc chỉ chạy tính năng vô hại. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1480/

## T1484 - Domain or Tenant Policy Modification
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1484.001, T1484.002.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1484/

## T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1484, T1484.002.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1484/001/

## T1484.002 - Domain or Tenant Policy Modification: Trust Modification
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1484, T1484.001.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1484/002/

## T1491 - Defacement
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: actor đạt mục tiêu hoặc muốn gây áp lực -> thực thi payload tác động -> làm gián đoạn vận hành và tăng chi phí ứng cứu.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1491/

## T1496 - Resource Hijacking
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: actor đạt mục tiêu hoặc muốn gây áp lực -> thực thi payload tác động -> làm gián đoạn vận hành và tăng chi phí ứng cứu.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1496/

## T1497 - Virtualization/Sandbox Evasion
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mã độc tự kiểm tra môi trường trước khi bung hành vi thật: dò VM, sandbox, tiến trình phân tích, vùng ngôn ngữ, mutex, domain, IP, file hoặc điều kiện mục tiêu. Nếu điều kiện không khớp, nó ngủ, thoát hoặc chỉ chạy tính năng vô hại.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mã độc tự kiểm tra môi trường trước khi bung hành vi thật: dò VM, sandbox, tiến trình phân tích, vùng ngôn ngữ, mutex, domain, IP, file hoặc điều kiện mục tiêu. Nếu điều kiện không khớp, nó ngủ, thoát hoặc chỉ chạy tính năng vô hại. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1497/

## T1498 - Network Denial of Service
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: actor đạt mục tiêu hoặc muốn gây áp lực -> thực thi payload tác động -> làm gián đoạn vận hành và tăng chi phí ứng cứu.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1498/

## T1499 - Endpoint Denial of Service
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: actor đạt mục tiêu hoặc muốn gây áp lực -> thực thi payload tác động -> làm gián đoạn vận hành và tăng chi phí ứng cứu.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1499.004.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1499/

## T1499.004 - Endpoint Denial of Service: Application or System Exploitation
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Hành vi cốt lõi là lợi dụng lỗi phần mềm hoặc dịch vụ để ép thực thi code, đọc secret hoặc mở đường lan ngang. Có thể khai thác tài liệu phía client, dịch vụ remote, cơ chế xác thực hay kho thông tin doanh nghiệp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: actor đạt mục tiêu hoặc muốn gây áp lực -> thực thi payload tác động -> làm gián đoạn vận hành và tăng chi phí ứng cứu.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1499.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1499/004/

## T1505.004 - Server Software Component: IIS Components
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1505.006.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1505/004/

## T1505.006 - Server Software Component: vSphere Installation Bundles
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1505.004.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1505/006/

## T1525 - Implant Internal Image
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật sửa thành phần phần mềm hoặc image gốc để mã độc được phân phối cùng sản phẩm hoặc hệ thống hợp pháp. Đây là hướng supply-chain rất sâu vì payload xuất hiện từ giai đoạn build, install, update hoặc boot image.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật sửa thành phần phần mềm hoặc image gốc để mã độc được phân phối cùng sản phẩm hoặc hệ thống hợp pháp. Đây là hướng supply-chain rất sâu vì payload xuất hiện từ giai đoạn build, install, update hoặc boot image. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1525/

## T1526 - Cloud Service Discovery
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1526/

## T1528 - Steal Application Access Token
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1528/

## T1529 - System Shutdown/Reboot
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu ở đây là tác động nhìn thấy được: phá giao diện, đào coin, ép reboot, làm nghẽn dịch vụ hoặc bóp chết endpoint và network. Đây là bước gây ảnh hưởng, tống tiền, che giấu xâm nhập hoặc làm nhiễu phản ứng sự cố. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: actor đạt mục tiêu hoặc muốn gây áp lực -> thực thi payload tác động -> làm gián đoạn vận hành và tăng chi phí ứng cứu.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1529/

## T1530 - Data from Cloud Storage
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1530/

## T1537 - Transfer Data to Cloud Account
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: dữ liệu đã được gom -> nén hoặc mã hoá hoặc chia lô -> gửi ra ngoài qua C2/web/cloud/alternative protocol -> xoá dấu vết hoặc đổi kênh nếu bị chặn.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1537/

## T1539 - Steal Web Session Cookie
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor nhắm thẳng vào browser để cướp session sống, chèn extension, chích script, đọc cookie và token rồi mượn phiên đã đăng nhập. Loại này rất nguy với SaaS, SSO và quản trị cloud vì có thể vượt qua cả MFA khi cookie còn hiệu lực.
- **Điều kiện/tiền đề thường thấy:** Cần quyền trên endpoint, vào được profile browser hoặc chiếm được phiên người dùng đang đăng nhập.
- **Biểu hiện và hành vi chi tiết:** Actor nhắm thẳng vào browser để cướp session sống, chèn extension, chích script, đọc cookie và token rồi mượn phiên đã đăng nhập. Loại này rất nguy với SaaS, SSO và quản trị cloud vì có thể vượt qua cả MFA khi cookie còn hiệu lực. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có credential hoặc session -> đăng nhập hợp lệ -> mở rộng quyền hoặc truy dữ liệu trực tiếp -> thiết lập cơ chế bền hơn như rule, token, key hoặc role.
- **Dấu vết/hunting ưu tiên:** Theo dõi truy cập file profile browser, DB cookie/login data, extension manifest, local storage, remote debugging và tiến trình lạ tiêm vào browser. Phía SaaS cần đối chiếu phiên đổi IP/UA bất thường nhưng vẫn vượt qua xác thực.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1539/

## T1543 - Create or Modify System Process
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có quyền cục bộ -> ghi cấu hình trigger/job/service -> hệ thống tự chạy payload ở lần boot/logon/sự kiện kế tiếp -> duy trì chỗ đứng dài hạn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1543/

## T1546 - Event Triggered Execution
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có quyền cục bộ -> ghi cấu hình trigger/job/service -> hệ thống tự chạy payload ở lần boot/logon/sự kiện kế tiếp -> duy trì chỗ đứng dài hạn.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1546/

## T1547.011 - REPLACED: Boot or Logon Autostart Execution: Plist Modification
- **Trạng thái ATT&CK:** legacy/replaced by T1647
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Mã này là bản cũ của Plist File Modification và đã được ATT&CK thay bằng T1647.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1647/  (kỹ thuật thay thế hiện hành)

## T1552 - Unsecured Credentials
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1552.001, T1552.004, T1552.005, T1552.006, T1552.007. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1552/

## T1552.001 - Unsecured Credentials: Credentials In Files
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1552, T1552.004, T1552.005, T1552.006, T1552.007. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1552/001/

## T1552.004 - Unsecured Credentials: Private Keys
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1552, T1552.001, T1552.005, T1552.006, T1552.007. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1552/004/

## T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1552, T1552.001, T1552.004, T1552.006, T1552.007. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1552/005/

## T1552.006 - Unsecured Credentials: Group Policy Preferences
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1552, T1552.001, T1552.004, T1552.005, T1552.007. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1552/006/

## T1552.007 - Unsecured Credentials: Container API
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor săn secret được để hớ hênh: file cấu hình, script deploy, .env, backup, SSH key, cloud metadata service, GPP cpassword, kube/docker API hoặc credential rơi trong hệ thống điều phối. Dạng này thường rất hiệu quả vì không cần bẻ khoá gì cả. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1552, T1552.001, T1552.004, T1552.005, T1552.006. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1552/007/

## T1553.001 - Subvert Trust Controls: Gatekeeper Bypass
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1553.005. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1553/001/

## T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1553.001. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1553/005/

## T1554 - Compromise Host Software Binary
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật sửa thành phần phần mềm hoặc image gốc để mã độc được phân phối cùng sản phẩm hoặc hệ thống hợp pháp. Đây là hướng supply-chain rất sâu vì payload xuất hiện từ giai đoạn build, install, update hoặc boot image.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật sửa thành phần phần mềm hoặc image gốc để mã độc được phân phối cùng sản phẩm hoặc hệ thống hợp pháp. Đây là hướng supply-chain rất sâu vì payload xuất hiện từ giai đoạn build, install, update hoặc boot image. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1554/

## T1555.001 - Credentials from Password Stores: Keychain
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1555.003, T1555.004, T1555.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1555/001/

## T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Cần quyền trên endpoint, vào được profile browser hoặc chiếm được phiên người dùng đang đăng nhập.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có credential hoặc session -> đăng nhập hợp lệ -> mở rộng quyền hoặc truy dữ liệu trực tiếp -> thiết lập cơ chế bền hơn như rule, token, key hoặc role.
- **Dấu vết/hunting ưu tiên:** Theo dõi truy cập file profile browser, DB cookie/login data, extension manifest, local storage, remote debugging và tiến trình lạ tiêm vào browser. Phía SaaS cần đối chiếu phiên đổi IP/UA bất thường nhưng vẫn vượt qua xác thực.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1555.001, T1555.004, T1555.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1555/003/

## T1555.004 - Credentials from Password Stores: Windows Credential Manager
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1555.001, T1555.003, T1555.005. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1555/004/

## T1555.005 - Credentials from Password Stores: Password Managers
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Theo dõi việc đọc hàng loạt file cấu hình, secret store, keychain, registry hive, metadata service, mailbox hoặc screenshot API. Cần chú ý staging folder và thao tác gom dữ liệu trước khi nén/gửi ra ngoài.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1555.001, T1555.003, T1555.004. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1555/005/

## T1556.006 - Modify Authentication Process: Multi-Factor Authentication
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1556/006/

## T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Mục tiêu là chặn hoặc đọc lưu lượng để lấy thông tin xác thực, session token, tên miền nội bộ, giao thức điều khiển và dữ liệu truyền rõ. Trong mạng nội bộ, ARP poisoning thường được dùng để ép lưu lượng của nạn nhân đi qua máy của actor.
- **Điều kiện/tiền đề thường thấy:** Cần vị trí mạng thuận lợi, khả năng ở cùng broadcast domain, cài công cụ capture hoặc quyền cấu hình mạng trung gian.
- **Biểu hiện và hành vi chi tiết:** Mục tiêu là chặn hoặc đọc lưu lượng để lấy thông tin xác thực, session token, tên miền nội bộ, giao thức điều khiển và dữ liệu truyền rõ. Trong mạng nội bộ, ARP poisoning thường được dùng để ép lưu lượng của nạn nhân đi qua máy của actor. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1557/002/

## T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm lạm dụng Kerberos để giả vé, trích xuất vật liệu xác thực hoặc bẻ khoá offline. Golden Ticket dựng TGT bằng khoá KRBTGT; Silver Ticket dựng TGS cho service cụ thể; AS-REP Roasting lợi dụng tài khoản tắt pre-auth để lấy blob mang đi crack.
- **Điều kiện/tiền đề thường thấy:** Thường đòi hỏi foothold miền nội bộ và quyền đặc biệt trong AD hoặc khả năng đọc vật liệu xác thực liên quan đến domain.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm lạm dụng Kerberos để giả vé, trích xuất vật liệu xác thực hoặc bẻ khoá offline. Golden Ticket dựng TGT bằng khoá KRBTGT; Silver Ticket dựng TGS cho service cụ thể; AS-REP Roasting lợi dụng tài khoản tắt pre-auth để lấy blob mang đi crack. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold nội bộ -> leo quyền đến cấp domain -> trích hoặc giả vật liệu Kerberos/hash -> mạo danh tài khoản mạnh -> persistence và lateral movement.
- **Dấu vết/hunting ưu tiên:** Săn sự kiện replication hoặc DRS từ máy không phải DC, yêu cầu Kerberos/LDAP/Netlogon bất thường, ticket có tuổi đời lạ, SPN/SID-History biến động và đặc biệt là quyền Replicating Directory Changes trên principal không nên có.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1558.002, T1558.004. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1558/001/

## T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm lạm dụng Kerberos để giả vé, trích xuất vật liệu xác thực hoặc bẻ khoá offline. Golden Ticket dựng TGT bằng khoá KRBTGT; Silver Ticket dựng TGS cho service cụ thể; AS-REP Roasting lợi dụng tài khoản tắt pre-auth để lấy blob mang đi crack.
- **Điều kiện/tiền đề thường thấy:** Thường đòi hỏi foothold miền nội bộ và quyền đặc biệt trong AD hoặc khả năng đọc vật liệu xác thực liên quan đến domain.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm lạm dụng Kerberos để giả vé, trích xuất vật liệu xác thực hoặc bẻ khoá offline. Golden Ticket dựng TGT bằng khoá KRBTGT; Silver Ticket dựng TGS cho service cụ thể; AS-REP Roasting lợi dụng tài khoản tắt pre-auth để lấy blob mang đi crack. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold nội bộ -> leo quyền đến cấp domain -> trích hoặc giả vật liệu Kerberos/hash -> mạo danh tài khoản mạnh -> persistence và lateral movement.
- **Dấu vết/hunting ưu tiên:** Săn sự kiện replication hoặc DRS từ máy không phải DC, yêu cầu Kerberos/LDAP/Netlogon bất thường, ticket có tuổi đời lạ, SPN/SID-History biến động và đặc biệt là quyền Replicating Directory Changes trên principal không nên có.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1558.001, T1558.004. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1558/002/

## T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm lạm dụng Kerberos để giả vé, trích xuất vật liệu xác thực hoặc bẻ khoá offline. Golden Ticket dựng TGT bằng khoá KRBTGT; Silver Ticket dựng TGS cho service cụ thể; AS-REP Roasting lợi dụng tài khoản tắt pre-auth để lấy blob mang đi crack.
- **Điều kiện/tiền đề thường thấy:** Thường đòi hỏi foothold miền nội bộ và quyền đặc biệt trong AD hoặc khả năng đọc vật liệu xác thực liên quan đến domain.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm lạm dụng Kerberos để giả vé, trích xuất vật liệu xác thực hoặc bẻ khoá offline. Golden Ticket dựng TGT bằng khoá KRBTGT; Silver Ticket dựng TGS cho service cụ thể; AS-REP Roasting lợi dụng tài khoản tắt pre-auth để lấy blob mang đi crack. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold nội bộ -> leo quyền đến cấp domain -> trích hoặc giả vật liệu Kerberos/hash -> mạo danh tài khoản mạnh -> persistence và lateral movement.
- **Dấu vết/hunting ưu tiên:** Săn sự kiện replication hoặc DRS từ máy không phải DC, yêu cầu Kerberos/LDAP/Netlogon bất thường, ticket có tuổi đời lạ, SPN/SID-History biến động và đặc biệt là quyền Replicating Directory Changes trên principal không nên có.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1558.001, T1558.002. Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1558/004/

## T1559 - Inter-Process Communication
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1559/

## T1560 - Archive Collected Data
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> tìm nguồn dữ liệu giá trị -> gom, lọc, cấu trúc hoặc nén dữ liệu -> staging cục bộ hoặc đẩy sang bước exfiltration.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1560/

## T1562 - Impair Defenses
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1562.003, T1562.006, T1562.007, T1562.008, T1562.012. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1562/

## T1562.003 - Impair Defenses: Impair Command History Logging
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1562, T1562.006, T1562.007, T1562.008, T1562.012. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1562/003/

## T1562.006 - Impair Defenses: Indicator Blocking
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1562, T1562.003, T1562.007, T1562.008, T1562.012. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1562/006/

## T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1562, T1562.003, T1562.006, T1562.008, T1562.012. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1562/007/

## T1562.008 - Impair Defenses: Disable or Modify Cloud Logs
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1562, T1562.003, T1562.006, T1562.007, T1562.012. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1562/008/

## T1562.012 - Impair Defenses: Disable or Modify Linux Audit System
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1562, T1562.003, T1562.006, T1562.007, T1562.008. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1562/012/

## T1564.001 - Hide Artifacts: Hidden Files and Directories
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1564.003, T1564.008. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1564/001/

## T1564.003 - Hide Artifacts: Hidden Window
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Nhóm này xoay quanh việc làm thứ độc trông giống bình thường hoặc làm cảm biến mù đi. Có thể là đổi tên và đuôi file, dùng Unicode lừa người nhìn, cất payload ngoài đĩa, né Mark-of-the-Web hoặc Gatekeeper, chặn telemetry, giấu cửa sổ, xoá log và làm mờ command history. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1564.001, T1564.008. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1564/003/

## T1564.008 - Hide Artifacts: Email Hiding Rules
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor thay luật hộp thư để tự động chuyển tiếp, ẩn, đánh dấu đã đọc hoặc redirect thư nhạy cảm. Đây là kiểu persistence rất khó chịu trong Exchange/M365 vì nó sống trong mailbox thay vì trên endpoint.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor thay luật hộp thư để tự động chuyển tiếp, ẩn, đánh dấu đã đọc hoặc redirect thư nhạy cảm. Đây là kiểu persistence rất khó chịu trong Exchange/M365 vì nó sống trong mailbox thay vì trên endpoint. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold hoặc trước hành động ồn -> giảm khả năng nhìn thấy của defender -> thực hiện collection/lateral movement/exfiltration -> tiếp tục che giấu sau đó.
- **Dấu vết/hunting ưu tiên:** Tập trung vào đổi tên file hoặc đuôi lạ, Unicode RTLO, cửa sổ ẩn, thư mục ẩn, log bị rỗng bất thường, sensor bị stop, cloud audit bị tắt, và chuỗi command khó đọc hoặc được mã hoá, nén, nhúng vào config.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1564.001, T1564.003. Hay đi kèm payload execution, collection hoặc lateral movement để làm khó phân tích.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1564/008/

## T1565.001 - Data Manipulation: Stored Data Manipulation
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1565/001/

## T1567 - Exfiltration Over Web Service
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: dữ liệu đã được gom -> nén hoặc mã hoá hoặc chia lô -> gửi ra ngoài qua C2/web/cloud/alternative protocol -> xoá dấu vết hoặc đổi kênh nếu bị chặn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1567.002. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1567/

## T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Dữ liệu bị gom, nén, chia nhỏ, mã hoá hoặc đẩy ra ngoài qua kênh có vẻ bình thường như HTTPS, web service, C2, FTP, giao thức khác hoặc tài khoản cloud do actor kiểm soát. Việc giới hạn kích thước gói hoặc phiên thường nhằm né DLP và ngưỡng cảnh báo. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: dữ liệu đã được gom -> nén hoặc mã hoá hoặc chia lô -> gửi ra ngoài qua C2/web/cloud/alternative protocol -> xoá dấu vết hoặc đổi kênh nếu bị chặn.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Cùng họ kỹ thuật trong tập mã này: T1567. Thường đứng giữa Discovery -> Collection -> Archive/Staging -> Exfiltration.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1567/002/

## T1569 - System Services
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường.
- **Điều kiện/tiền đề thường thấy:** Cần quyền ghi vào vị trí cấu hình hoặc đăng ký cơ chế thực thi, hoặc khả năng gọi API/hệ thống quản trị tạo job/service.
- **Biểu hiện và hành vi chi tiết:** Kẻ tấn công cột payload vào cơ chế được hệ điều hành gọi hộ: trigger sự kiện, scheduler, service, login items hoặc hook, daemon hay tiến trình hệ thống. Điểm ăn tiền là payload được khởi chạy lặp lại, đôi khi bằng ngữ cảnh quyền cao hơn người dùng thường. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: có quyền cục bộ -> ghi cấu hình trigger/job/service -> hệ thống tự chạy payload ở lần boot/logon/sự kiện kế tiếp -> duy trì chỗ đứng dài hạn.
- **Dấu vết/hunting ưu tiên:** Tập trung vào tạo hoặc sửa job, plist, unit, service, cron, systemd timer hoặc CronJob. Cần nối chúng với process con mới sinh, binary ở thư mục user-writable, command line lạ và kết nối mạng theo sau.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1569/

## T1574.014 - Hijack Execution Flow: AppDomainManager
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật lạm dụng thành phần hoặc khả năng hợp pháp của nền tảng để thực thi, nạp mã hoặc truyền lệnh dưới vỏ bọc process quen thuộc. Nó giảm độ nổi bật so với chạy payload thẳng bằng file độc riêng. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1574/014/

## T1578.005 - Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần token, access key, session cookie, service principal, tài khoản tenant, hoặc ít nhất là quyền đọc một phần môi trường cloud/SaaS.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1578/005/

## T1580 - Cloud Infrastructure Discovery
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1580/

## T1584 - Compromise Infrastructure
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1584/

## T1585 - Establish Accounts
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1585/

## T1586.003 - Compromise Accounts: Cloud Accounts
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật xoay quanh API cloud hoặc SaaS: enumerate tenant, mailbox, storage, role, VM, security group, policy, workspace và nội dung lưu trữ. Hành vi thường đi qua CLI, SDK, Graph, REST API hoặc portal automation. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Ưu tiên audit API bất thường: enumerate/list/get dồn dập, đổi role, thêm secret, tắt log, đổi firewall, tạo app/device registration. So khớp hoạt động portal/CLI/SDK với lịch quản trị thật và chú ý đăng nhập từ ASN, IP, quốc gia lạ.
- **Liên hệ/biến thể cần xem cùng:** Nhóm này thường nối với Valid Accounts, Account Manipulation, vé Kerberos giả, mailbox rule hoặc các cơ chế persistence dựa trên identity.
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1586/003/

## T1587.003 - Develop Capabilities: Digital Certificates
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1587/003/

## T1589.002 - Gather Victim Identity Information: Email Addresses
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1589/002/

## T1590.005 - Gather Victim Network Information: IP Addresses
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển.
- **Điều kiện/tiền đề thường thấy:** Không cần foothold trong hệ thống nạn nhân; actor chủ yếu cần dữ liệu công khai, hạ tầng riêng, khả năng đăng ký hoặc mua dịch vụ hoặc quyền truy cập nguồn OSINT.
- **Biểu hiện và hành vi chi tiết:** Đây là nhóm chuẩn bị trước chiến dịch. Actor thu thập danh tính mục tiêu, IP public, dựng hạ tầng, tạo hoặc mua account, chiếm account hoặc phát triển chứng thư số để phục vụ phishing, C2, typosquatting hay hạ tầng điều khiển. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: chuẩn bị hạ tầng hoặc thông tin mục tiêu -> tạo điều kiện phishing/lure/C2 -> initial access hoặc staging cho chiến dịch sau.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1590/005/

## T1601.001 - Modify System Image: Patch System Image
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật sửa thành phần phần mềm hoặc image gốc để mã độc được phân phối cùng sản phẩm hoặc hệ thống hợp pháp. Đây là hướng supply-chain rất sâu vì payload xuất hiện từ giai đoạn build, install, update hoặc boot image.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật sửa thành phần phần mềm hoặc image gốc để mã độc được phân phối cùng sản phẩm hoặc hệ thống hợp pháp. Đây là hướng supply-chain rất sâu vì payload xuất hiện từ giai đoạn build, install, update hoặc boot image. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1601/001/

## T1611 - Escape to Host
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Payload bẻ gãy ranh giới container hoặc namespace để chạm vào host thật, thường thông qua quyền quá rộng, mount socket, cgroup, kernel bug hoặc runtime misconfiguration.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Payload bẻ gãy ranh giới container hoặc namespace để chạm vào host thật, thường thông qua quyền quá rộng, mount socket, cgroup, kernel bug hoặc runtime misconfiguration. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1611/

## T1621 - Multi-Factor Authentication Request Generation
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1621/

## T1647 - Plist File Modification
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Kỹ thuật này thường được dùng như một mô-đun trong chuỗi lớn hơn: nó hiếm khi đứng một mình mà thường nối với xác thực, discovery, collection, exfiltration hoặc impact tuỳ mục tiêu chiến dịch. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: kỹ thuật này đóng vai trò hỗ trợ, đứng giữa foothold ban đầu và mục tiêu cuối như persistence, credential access, collection hoặc impact.
- **Dấu vết/hunting ưu tiên:** Cần so sánh với baseline quản trị bình thường, ưu tiên chuỗi sự kiện thay vì một IOC đơn lẻ, và liên kết process, file, network, identity cùng cloud audit để nhìn ra toàn bộ luồng.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1647/

## T1654 - Log Enumeration
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Actor đọc log hệ điều hành, ứng dụng, bảo mật hay cloud audit để hiểu hệ thống đang ghi gì, có bị phát hiện chưa, tài khoản nào hoạt động, dịch vụ nào lỗi và tuyến nào đáng khai thác tiếp.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Actor đọc log hệ điều hành, ứng dụng, bảo mật hay cloud audit để hiểu hệ thống đang ghi gì, có bị phát hiện chưa, tài khoản nào hoạt động, dịch vụ nào lỗi và tuyến nào đáng khai thác tiếp. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Tìm chuỗi lệnh liệt kê file, account, port, dịch vụ, VM, registry hoặc cloud asset trong thời gian ngắn. Process hệ thống hoặc ứng dụng văn phòng mà bỗng làm discovery hàng loạt thường rất đáng ngờ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1654/

## T1673 - Virtual Machine Discovery
- **Trạng thái ATT&CK:** current
- **Bản chất kỹ thuật:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu.
- **Điều kiện/tiền đề thường thấy:** Thường cần ít nhất một foothold hợp lệ trên endpoint, máy chủ, tenant hoặc hạ tầng có liên quan.
- **Biểu hiện và hành vi chi tiết:** Đây là hành vi trinh sát sau xâm nhập. Actor liệt kê tài nguyên, tài khoản, VM, share, port, dịch vụ và cấu trúc file để vẽ bản đồ mục tiêu trước khi nâng quyền, lan ngang hay thu thập dữ liệu. Về mặt thực thi, actor thường kết hợp kỹ thuật này với công cụ hệ thống, API hợp pháp hoặc quyền đã chiếm được để giảm tiếng ồn, né kiểm soát và làm luồng tấn công trông giống hoạt động bình thường.
- **Luồng tấn công tương ứng:** Chuỗi điển hình: foothold -> trinh sát môi trường -> chọn đích leo quyền, lan ngang hoặc collection -> thực hiện hành động chính xác hơn và ít ồn hơn.
- **Dấu vết/hunting ưu tiên:** Tìm chuỗi lệnh liệt kê file, account, port, dịch vụ, VM, registry hoặc cloud asset trong thời gian ngắn. Process hệ thống hoặc ứng dụng văn phòng mà bỗng làm discovery hàng loạt thường rất đáng ngờ.
- **Liên hệ/biến thể cần xem cùng:** 
- **ATT&CK URL:** https://attack.mitre.org/techniques/T1673/

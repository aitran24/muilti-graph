1. Đọc toàn bộ codebase bao gồm tất cả các app, code file 

2. Dựng một pipepline hoàn chỉnh, triển khai các thuật toán khớp đồ thị

3. Log thu từ sysmon, tham khảo stream pipeline, cấu trúc cây dùng để khớp là cấu trúc trả về từ stream pipeline (ứng với cây ở raw mode, không phải log thuần chưa xử lí), cấu trúc cây tấn công làm mẫu nằm trong thư mục clean_attack_tree 

4. Log thu từ sysmon, là dạng stream poll theo giây, không phải cố định, tức là cấu trúc cần merge có mở rộng 

5. Triển khai một range các thuật toán khớp đồ thị, để so sánh, kết quả khớp cần view được lên UI của streamline (sửa streamline UI để thêm tính năng)


6. Tạm thời chưa dùng tới stream log, điều chỉnh pipeline để nó có thể chạy một mode dùng để trực quan kết quả khớp đồ thị và so sánh kết quả các thuật toán dùng log của các kĩ thuật có sẵn 

7. Danh sách các thuật toán:

1	Baseline — exact, đo recall tối đa	Shamir & Tsur (1999) / Subtree Isomorphism (Chung 1987) → Xác định các pattern exact có xuất hiện trong log sạch. Đo recall tuyệt đối.
2	Core — approximate, chịu nhiễu	TED (Zhang–Shasha / APTED) + Approx Subtree Match (θ, k) + MCS. Chính sách: match khi partial TED ≤ ngưỡng hoặc node bị thiếu ≤ k%.
3	Scale — multi‑pattern cùng lúc	Tree Automata (compile pattern → automaton offline) hoặc Aho–Corasick mở rộng lên tree → duyệt G một lần, kích hoạt mọi pattern đồng thời.
4	Tối ưu theo cấu trúc G	Nếu G là DAG thưa → Treewidth Decomposition + FPT matching. Nếu G dày → Spanning Tree Extract (TreeSpan paradigm). 


Thuật toán triển khai cần linh hoạt, đại khái là mỗi node là một entity có các trường khác nhau, linh hoạt thêm điều kiện trong thuật toán để kết quả chính xác hơn. Bạn có thể tự đề xuất một thuật toán khác mà tối ưu cho dữ liệu hiện tại, hoặc tùy ý tinh chỉnh thuật toán bất kì, có thể dùng thêm malcious pattern của các kĩ thuật để bổ sung ngữ cảnh. 

So sánh cần so sánh về độ chính xác, độ khớp, thời gian xử lí để tôi chọn thuật toán tối ưu hoặc triển khai tất cả cùng một lúc để làm kết quả so sánh 

Kết quả khớp (nếu có khớp kĩ thuật tấn công) được trực quan linh hoạt trên UI, có một panel để hiển thị danh sách các kĩ thuật đã khớp, chọn kĩ thuật nào thì hightlight mạnh (có thể prune toàn bộ các node không liên quan) cây tấn công đã khớp (một phần) lên. Giao diện này có quyền tách biệt và không liên quan tới giao diện streamline, miễn nó có chức năng tương đồng là được

Mỗi thuật toán triển khai cần nằm trong code file khác nhau, viết code clean, modular, oop càng tốt, viết clean hết sức có thể, cái nào xài lại được từ trong code base thì xài, không thì viết thêm. Sẽ có một file .md dùng để giải thích chi tiết cách từng  thuật toán mà bạn sử dụng
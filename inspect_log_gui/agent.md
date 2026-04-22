# Agent Task: Build Inspect Log GUI (Client‑Side Filtering)

## Mục tiêu tổng quát

Tạo một web app trong thư mục `inspect_log_gui/` (không ảnh hưởng gì ra ngoài thư mục này).  
App cho phép:

- Duyệt tuần tự các kỹ thuật (technique) từ các file log có sẵn.
- Với mỗi kỹ thuật, gọi pipeline hiện tại (parse entity, merge entity, tạo triplet) **nhưng không lưu vào Neo4j**.
- Render đồ thị (node + quan hệ) lên giao diện web, có zoom/pan, click node để xem thuộc tính.
- Có một panel để người dùng nhập tay các pattern nghi ngờ là malicious (ví dụ: `-enc`, `p`+`o`+`w`, `Invoke-`…).
- **Sau mỗi lần thêm pattern, giao diện tự động dò tìm và loại bỏ khỏi đồ thị** tất cả các node (và toàn bộ nhánh con bên dưới node `techniques`) có chứa pattern đó. Việc lọc này thực hiện hoàn toàn ở phía trình duyệt (client‑side), không gọi backend.
- Khi người dùng ấn nút **Complete** (hoặc OK), danh sách pattern hiện tại được gửi lên backend để lưu vào file `<tên_kỹ_thuật>_malcious_config.json`.
- Cho phép chuyển qua lại giữa các kỹ thuật, mỗi lần chuyển thì parse lại (hoặc dùng cache) và áp dụng các pattern đã lưu để lọc ngay.

## Các công việc cụ thể

### 1. Đọc hiểu logic codebase hiện tại

Phân tích code có sẵn để nắm được:

- Hàm parse log → entity (cấu trúc entity, các trường).
- Hàm merge entity (tiêu chí merge, output).
- Hàm tạo triplet (subject, predicate, object).
- Cách lưu vào Neo4j (chỉ tham khảo, không cần lưu thật).

Mục đích: tái sử dụng chính xác các hàm đó trong pipeline của GUI, chỉ bỏ qua bước ghi DB.

### 2. Xây dựng backend (Flask/FastAPI) trong `inspect_log_gui/backend/`

Backend có nhiệm vụ tối thiểu:

- Cung cấp API `GET /api/techniques` → trả về danh sách tên kỹ thuật (lấy từ tên file trong thư mục `logs/`).
- Cung cấp API `GET /api/graph?technique=<name>` → gọi pipeline xử lý (parse, merge, triplet) cho kỹ thuật đó, trả về JSON chứa `nodes` và `edges` (giống cấu trúc sẽ lưu vào Neo4j). **Không lưu gì vào DB.**
- Cung cấp API `GET /api/patterns?technique=<name>` → đọc file `<technique>_malcious_config.json` trong thư mục `data/` (nếu có) và trả về danh sách pattern.
- Cung cấp API `POST /api/patterns` → nhận `{technique, patterns}` và ghi đè file JSON tương ứng.
- Cung cấp API `POST /api/patterns/append` → nhận `{technique, new_pattern}`, thêm pattern vào danh sách hiện tại, ghi lại file, trả về danh sách mới.

**Lưu ý quan trọng:** Backend **không thực hiện lọc đồ thị**. Việc lọc theo pattern sẽ do frontend tự xử lý (xem mục 3).

### 3. Xây dựng frontend trong `inspect_log_gui/frontend/`

Giao diện web tĩnh (HTML/CSS/JS) sử dụng thư viện graph như vis-network hoặc Cytoscape.js.

#### 3.1 Các thành phần giao diện

- Dropdown / nút Previous / Next để chọn kỹ thuật.
- Vùng hiển thị graph (có zoom/pan bằng chuột).
- Panel nhập pattern: ô input, nút **Add Pattern**, danh sách các pattern hiện tại (có thể xoá từng cái).
- Nút **Complete** (hoặc OK) để lưu pattern vào file (gọi API).
- Panel inspect: hiển thị thuộc tính của node khi click vào node trên graph.

#### 3.2 Luồng xử lý

1. Khi chọn một kỹ thuật (hoặc bấm Load):
   - Gọi `GET /api/graph` để lấy `fullGraph` (đồ thị gốc chưa lọc).
   - Gọi `GET /api/patterns` để lấy danh sách pattern đã lưu của kỹ thuật đó.
   - Dùng chính frontend để lọc `fullGraph` theo danh sách pattern (xem 3.3) → được `filteredGraph`.
   - Render `filteredGraph` lên canvas.

2. Khi người dùng nhập pattern mới và bấm **Add Pattern**:
   - Gọi `POST /api/patterns/append` để backend lưu pattern vào file.
   - Cập nhật danh sách pattern ở frontend.
   - **Tự động lọc lại `fullGraph` với danh sách pattern mới** (chạy hàm lọc phía client) → cập nhật lại graph đã render.
   - Không gọi backend để lọc.

3. Khi người dùng bấm **Complete**:
   - Gọi `POST /api/patterns` với danh sách pattern hiện tại (hoặc chỉ cần xác nhận vì đã được lưu sau mỗi lần add). Có thể hiển thị thông báo thành công.
   - Cho phép chuyển sang kỹ thuật khác.

4. Khi chuyển kỹ thuật (bấm Next/Prev hoặc chọn từ dropdown):
   - Lặp lại bước 1 cho kỹ thuật mới.

#### 3.3 Hàm lọc đồ thị phía client (JavaScript)

Yêu cầu: loại bỏ tất cả node và toàn bộ nhánh con bên dưới node `techniques` nếu node đó (hoặc bất kỳ node con nào) chứa pattern.

Cách thực hiện:

- Xác định các node gốc là những node có `type === "technique"` (hoặc theo quy ước của pipeline).
- Duyệt BFS/DFS từ các node gốc.
- Với mỗi node, kiểm tra tất cả thuộc tính của nó (tên, command, path, …) có chứa bất kỳ pattern nào không (so khớp chuỗi con, không phân biệt hoa thường).
- Nếu node khớp pattern → đánh dấu node đó và toàn bộ các node con (subtree) của nó để xoá.
- Kết quả trả về là đồ thị mới chỉ gồm các node không bị xoá và các edge nối giữa chúng.

Hàm này chạy hoàn toàn trên trình duyệt, không gửi dữ liệu lên server.

#### 3.4 Node inspection

- Gắn sự kiện click vào từng node.
- Khi click, lấy đối tượng node từ `filteredGraph` và hiển thị tất cả các trường (properties) trong một panel bên cạnh (dạng bảng hoặc JSON).

### 4. Yêu cầu về thư mục và file

- Toàn bộ code mới viết phải nằm gọn trong `inspect_log_gui/`.
- Có thể copy các file log mẫu vào `inspect_log_gui/logs/` (đặt tên file theo tên kỹ thuật, ví dụ `technique1.log`, `technique2.log`).
- Backend tự động tạo thư mục `data/` nếu chưa có, và lưu các file `<technique>_malcious_config.json` vào đó.
- Không được sửa bất kỳ file nào ngoài `inspect_log_gui/`.
- Viết `README.md` hướng dẫn cài đặt (pip install flask, flask-cors) và chạy (python backend/app.py), sau đó mở browser.

### 5. Lưu ý về pipeline hiện tại

- **Có thể viết lại code (sao y bản gốc) nếu cần thêm hàm gì đó, nhưng tất cả đều phải được viết bên trong thư mục đã chỉ định**. Reuse được thì reuse
- Nếu pipeline gốc có kết nối Neo4j hoặc hàm lưu DB, hãy bỏ qua hoặc mock chúng (không gọi thực tế).
- Đảm bảo output của `process_technique` (trong backend) là đồ thị hoàn chỉnh giống hệt như khi lưu vào Neo4j.

### 6. Kiểm tra chức năng

Sau khi hoàn thành, người dùng có thể:

- Chọn technique → thấy graph.
- Click node → thấy properties.
- Nhập pattern `-enc` → bấm Add → graph tự động loại bỏ các node có chứa `-enc` và toàn bộ nhánh con của chúng.
- Nhập pattern `pow` → Add → loại bỏ thêm.
- Bấm Complete → file `<mã_technique>_malcious_config.json` cho từng kĩ thuật được tạo trong `data/`.
- Chuyển sang technique khác → graph mới được load và tự động lọc theo pattern đã lưu của technique đó (nếu có).


# Bắt đầu

Từ cài đặt đến ứng viên lỗ hổng đầu tiên trong 15 phút. Hoạt động với bất kỳ tệp nhị phân ELF stripped nào.

---

## Cài đặt

**Yêu cầu:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Với tính năng LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Từ nguồn:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Xác minh cài đặt:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Bước 1: Tải tệp nhị phân

`BinaryContext` là điểm vào cho tất cả các phân tích. Truyền bất kỳ tệp nhị phân ELF stripped nào:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Lần đầu chạy:** 0,5 đến 5 giây tùy thuộc vào kích thước tệp nhị phân. Ablation xây dựng và lưu cache vào `~/.ablation/cache/<sha256>_<name>.json`.

**Các lần chạy tiếp theo:** 110 ms. Cache được đánh khóa theo SHA256 — một bản dựng khác có cùng tên tệp nhị phân sẽ tự động xây dựng lại.

Ví dụ đầu ra:

```
BinaryContext: libservice.so
  sha256     : fdfaceccdc740d82...
  base_va    : 0x0
  func_starts: 19024
  exports    : 14
  plt entries: 187
  strings    : 44821
  call_edges : 58903
  str_xrefs  : 218440 pairs indexed
  named funcs: 0 (overlay)
```

---

## Bước 2: Chạy quét ngữ nghĩa

Quét là quy trình làm việc cốt lõi. Mã hóa tất cả các hàm dưới dạng dấu vân tay hành vi BERT và truy vấn bằng mô tả lỗ hổng bằng tiếng Anh đơn giản. Sử dụng `sweeps/base_sweep.py` làm mẫu hoặc tự xây dựng:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Xây dựng corpus mô tả hành vi vào func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Xây dựng embedding BERT (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Truy vấn bằng mô tả lỗ hổng
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Thời gian chạy dự kiến:** 35 đến 60 giây cho 19.000 hàm trên CPU. Các truy vấn tiếp theo đối với cùng corpus chạy trong vòng dưới một giây — các embedding được lưu cache.

---

## Bước 3: Phân loại ứng viên

Đối với mỗi ứng viên có điểm cao, lấy ngữ cảnh của nó:

```python
va = 0x1000  # VA ứng viên từ kết quả quét

# Hàm này gọi gì?
print("callees:", ctx.callees_of(va))

# Nó tham chiếu đến chuỗi nào?
print("strings:", ctx.strings_in_func(va))

# Cái gì gọi nó?
print("callers:", ctx.callers_of(va))
```

Hầu hết các ứng viên được phân loại trong hai đến ba phút theo cách này. Nếu danh sách callee chứa các hàm bộ nhớ (`memcpy`, `malloc`, `free`) và chuỗi caller đến điểm vào mạng, hãy tiến hành theo dõi thủ công.

---

## Bước 4: Đặt tên các hàm đã xác nhận

Khi bạn xác định mục đích của hàm, hãy đăng ký tên của nó. Tên tồn tại giữa các phiên và xuất hiện trong tất cả đầu ra phân tích tiếp theo:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Tên xuất hiện ở mọi nơi:
print(ctx.callees_of(0x1000))   # nhãn thay vì địa chỉ hex
print(ctx.names_table())           # tất cả các hàm đã đặt tên trong tệp nhị phân này
```

Tên được lưu trữ trong `~/.ablation/function_names.json`, được đánh khóa theo SHA256 nhị phân. Tồn tại qua các lần khởi động lại phiên, di chuyển tệp nhị phân và khởi động lại hệ thống.

---

## Bước 5: Đăng ký các mẫu đã xác nhận

Khi bạn xác nhận lỗ hổng thực sự, hãy đăng ký truy vấn đã tìm thấy nó. Nó sẽ tự động phát lại trên các tệp nhị phân trong tương lai:

```python
from ablation.analyzers.pattern_library import PatternLibrary

pl = PatternLibrary()
pl.record_hit(
    query="TLV pointer advance loop with no minimum length check",
    binary_sha="fdfaceccdc740d82",
    va=0x1000,
    confirmed=True,
    vuln_class="infinite_loop",
    cvss=7.5,
)
```

Trên bất kỳ lần quét nào trong tương lai — phiên bản firmware khác, nhà cung cấp khác — `pl.sweep(searcher)` tự động chạy tất cả các mẫu đã xác nhận.

---

## Tiếp tục phiên

Ablation được thiết kế cho nghiên cứu đa phiên. Khi bắt đầu bất kỳ phiên nào:

```python
# Tải ngữ cảnh (110ms -- sử dụng cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Hiển thị tất cả các hàm đã đặt tên trước đó
print(ctx.names_table())

# Xem lại các phát hiện đã xác nhận
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Các bước tiếp theo

- [Quy trình làm việc săn lỗ hổng](../../workflows/vuln-hunting.md) -- vòng lặp đầy đủ từ quét đến phát hiện sẵn sàng công khai
- [Tham chiếu mô-đun](../../module-reference/) -- hơn 50 bộ phân tích với tham số và ví dụ
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- cách thêm mẫu, quét và mô-đun bộ phân tích

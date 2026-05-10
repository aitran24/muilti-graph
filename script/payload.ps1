Add-Type -AssemblyName PresentationFramework

[System.Windows.MessageBox]::Show(
"Máy của bạn đã bị lây nhiễm. Sau này không nên mở các file không rõ nguồn gốc nhé",
"Cảnh báo bảo mật",
"OK",
"Warning"
)